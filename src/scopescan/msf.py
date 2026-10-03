"""Verificacion de explotabilidad con Metasploit sobre un escaneo ya guardado.

Encaja donde nvd/msrc: toma un scan_id, cruza sus puertos abiertos y CVE con el
catalogo de modulos (msf_modules) y lanza msfconsole para *comprobar*
(auxiliary/scanner + `check`), nunca para explotar. El resultado se guarda en la
tabla msf_results y aparece junto al resto de evidencia del escaneo.

Guard de alcance: igual que nmap avisa de objetivos publicos, aqui se bloquea
lanzar Metasploit contra objetivos fuera de rango privado salvo que se pase
allow_public=True (que exige, ademas, que conste quien autoriza). Metasploit es
mas ruidoso e intrusivo que un escaneo de puertos: el listo por defecto es no
tocar nada que no sea claramente propio.
"""

from __future__ import annotations

import threading
from collections import defaultdict

from . import db, msf_modules, msf_runner
from .config import MsfConsoleNotFound, msf_lhost, msf_lport, raw_dir
from .msf_modules import MsfModule
from .targets import InvalidTarget, parse_target, parse_targets

ENRICH_KIND = "metasploit"


class MsfScopeError(RuntimeError):
    """Se intento verificar un objetivo fuera de alcance autorizado."""


class MsfError(RuntimeError):
    """La verificacion con Metasploit no se pudo completar."""


def _cve_map(scan_id: int) -> dict[tuple[str, int], set[str]]:
    """CVE asociados a cada (host, puerto) por el escaneo (NSE) y por NVD."""
    out: dict[tuple[str, int], set[str]] = defaultdict(set)
    for row in db.get_findings(scan_id):
        if row["port"]:
            out[(row["host"], int(row["port"]))].update(db.row_list(row["cves"]))
    for row in db.get_cve_candidates(scan_id):
        out[(row["host"], int(row["port"]))].add(row["cve_id"])
    return out


def plan_scan(scan_id: int) -> list[tuple[str, int, str, MsfModule]]:
    """Lista de (host, puerto, servicio, modulo) que se verificaria, sin lanzar nada.

    Permite que la CLI/panel enseñen el plan antes de confirmar.
    """
    hosts = {h["id"]: h for h in db.get_hosts(scan_id) if h["state"] == "up"}
    ports_by_host = db.get_ports(scan_id, only_open=True)
    cves = _cve_map(scan_id)

    plan: list[tuple[str, int, str, MsfModule]] = []
    for host_id, host in hosts.items():
        address = host["address"]
        for port in ports_by_host.get(host_id, []):
            portid = int(port["portid"])
            service = port["service_name"] or ""
            modules = msf_modules.candidates_for(
                service_name=service,
                product=port["product"] or "",
                cve_ids=sorted(cves.get((address, portid), set())),
            )
            for mod in modules:
                plan.append((address, portid, service, mod))
    return plan


def verify_scan(
    scan_id: int,
    *,
    allow_public: bool = False,
    authorized_by: str = "",
    cancel: threading.Event | None = None,
    progress: msf_runner.ProgressCallback | None = None,
) -> int:
    """Lanza la verificacion Metasploit del escaneo. Devuelve nº de veredictos.

    Lanza MsfScopeError si hay objetivos publicos y no se autoriza explicitamente,
    y MsfConsoleNotFound si msfconsole no esta instalado.
    """
    row = db.get_scan(scan_id)
    if row is None:
        raise ValueError(f"No existe el escaneo {scan_id}")

    # --- Guard de alcance --------------------------------------------------
    try:
        target_set = parse_targets(row["targets"], force=True)
    except InvalidTarget as exc:  # pragma: no cover - ya se valido al escanear
        raise MsfError(f"Objetivos del escaneo no validos: {exc}") from exc

    if not target_set.all_private:
        if not allow_public:
            raise MsfScopeError(
                "El escaneo incluye objetivos fuera de rango privado. Lanzar Metasploit "
                "contra ellos exige allow_public=True y autorizacion por escrito."
            )
        if not authorized_by.strip():
            raise MsfScopeError(
                "Para verificar objetivos publicos debe constar quien autoriza "
                "(authorized_by)."
            )

    plan = plan_scan(scan_id)
    if not plan:
        db.set_enrichment_status(scan_id, ENRICH_KIND, "done")
        return 0

    # --- Agrupar por (modulo, puerto): un msfconsole por grupo -------------
    groups: dict[tuple[str, int], list[str]] = defaultdict(list)
    meta: dict[tuple[str, int], tuple[str, MsfModule]] = {}
    for address, portid, service, mod in plan:
        key = (mod.path, portid)
        if address not in groups[key]:
            groups[key].append(address)
        meta[key] = (service, mod)

    db.set_enrichment_status(scan_id, ENRICH_KIND, "running")
    results: list[dict[str, object]] = []
    raw = raw_dir()

    try:
        for (module_path, portid), hosts in groups.items():
            if cancel is not None and cancel.is_set():
                break
            _service, mod = meta[(module_path, portid)]
            slug = module_path.replace("/", "_")
            rc_path = raw / f"msf-{scan_id:05d}-{slug}-{portid}.rc"
            log_path = raw / f"msf-{scan_id:05d}-{slug}-{portid}.log"
            rc_path.write_text(
                msf_modules.build_resource_script(mod, hosts, rport=portid),
                encoding="utf-8",
            )

            if progress is not None:
                progress(f"[*] {mod.action} {module_path} -> {len(hosts)} host(s) :{portid}")

            argv = msf_runner.build_argv(rc_path, log_path=log_path)
            execution = msf_runner.run(argv, cancel=cancel, progress=progress)
            results.extend(
                _rows_from(scan_id, mod, portid, hosts, execution)
            )
    except MsfConsoleNotFound:
        db.set_enrichment_status(scan_id, ENRICH_KIND, "failed", "msfconsole no encontrado")
        raise
    except OSError as exc:
        db.set_enrichment_status(scan_id, ENRICH_KIND, "failed", str(exc))
        raise MsfError(f"No se pudo lanzar msfconsole: {exc}") from exc

    saved = db.save_msf_results(scan_id, results)  # type: ignore[arg-type]
    status = "cancelled" if (cancel is not None and cancel.is_set()) else "done"
    db.set_enrichment_status(scan_id, ENRICH_KIND, status)
    return saved


def exploitable_results(scan_id: int) -> list[dict[str, object]]:
    """Resultados de verificacion que admiten boton 'Explotar'.

    Un resultado es explotable desde el panel si: el modulo es exploit y tiene
    payload, el host salio vulnerable/likely en la verificacion, y aun no se ha
    explotado con exito. Devuelve dicts listos para la plantilla.
    """
    exploited = {
        (row["host"], row["port"], row["module"])
        for row in db.get_exploit_runs(scan_id)
        if row["result"] == msf_modules.EXPLOITED
    }
    out: list[dict[str, object]] = []
    for row in db.get_msf_results(scan_id):
        mod = msf_modules.module_by_path(row["module"])
        if mod is None or not mod.exploitable:
            continue
        if (row["host"], row["port"], row["module"]) in exploited:
            continue
        if row["result"] in (msf_modules.VULNERABLE, msf_modules.LIKELY):
            out.append(
                {
                    "host": row["host"],
                    "port": row["port"],
                    "module": row["module"],
                    "label": mod.label,
                    "result": row["result"],
                }
            )
    return out


def _validated_exploit_context(
    scan_id: int,
    *,
    host: str,
    port: int | None,
    module_path: str,
    allow_public: bool = False,
) -> tuple[object, MsfModule]:
    """Valida que un host/modulo puede entrar en la fase de explotacion.

    Triple-gate antes de disparar nada:
      1. El modulo debe existir en el catalogo y ser explotable (payload definido).
      2. Debe haber un veredicto previo vulnerable/likely para ese host+modulo:
         no se explota lo que no se ha verificado.
      3. El host debe ser privado, salvo allow_public=True (con autorizacion en
         el escaneo). Ademas debe pertenecer al escaneo.
    """
    row = db.get_scan(scan_id)
    if row is None:
        raise ValueError(f"No existe el escaneo {scan_id}")

    mod = msf_modules.module_by_path(module_path)
    if mod is None or not mod.exploitable:
        raise MsfError(f"Modulo no explotable o desconocido: {module_path}")

    if host not in {h["address"] for h in db.get_hosts(scan_id)}:
        raise MsfScopeError("El host no pertenece a este escaneo.")

    verified = any(
        r["module"] == module_path
        and r["host"] == host
        and r["result"] in (msf_modules.VULNERABLE, msf_modules.LIKELY)
        for r in db.get_msf_results(scan_id)
    )
    if not verified:
        raise MsfScopeError(
            "No hay verificacion previa vulnerable para ese host/modulo. "
            "Ejecuta primero la verificacion Metasploit."
        )

    try:
        target = parse_target(host)
    except InvalidTarget as exc:  # pragma: no cover - host ya validado al escanear
        raise MsfError(str(exc)) from exc
    if not target.private and not allow_public:
        raise MsfScopeError(
            f"{host} esta fuera de rango privado. Explotar un objetivo publico exige "
            "allow_public=True y autorizacion por escrito."
        )
    if not target.private and allow_public and not (row["authorized_by"] or "").strip():
        raise MsfScopeError("Para explotar un objetivo publico debe constar quien autoriza.")

    return row, mod


def prepare_exploit_resource(
    scan_id: int,
    *,
    host: str,
    port: int | None,
    module_path: str,
    allow_public: bool = False,
) -> tuple[str, str]:
    """Genera un resource script de Metasploit y lo registra sin ejecutarlo.

    Devuelve ``(rc_path, rc_text)``. Este flujo sirve para handoff: scopescan deja
    el artefacto listo y auditable, y el operador lo lanza manualmente en su
    msfconsole cuando proceda.
    """
    row, mod = _validated_exploit_context(
        scan_id,
        host=host,
        port=port,
        module_path=module_path,
        allow_public=allow_public,
    )

    lhost = msf_lhost()
    lport = msf_lport()
    slug = module_path.replace("/", "_")
    raw = raw_dir()
    rc_path = raw / f"msf-exploit-{scan_id:05d}-{slug}-{host}-manual.rc"
    log_path = raw / f"msf-exploit-{scan_id:05d}-{slug}-{host}.log"
    rc_text = msf_modules.build_exploit_script(
        mod, host, rport=port, lhost=lhost, lport=lport
    )
    rc_path.write_text(rc_text, encoding="utf-8")

    run_id = db.create_exploit_run(
        scan_id,
        host=host,
        port=port,
        protocol="tcp",
        engine="metasploit",
        module=module_path,
        action="prepare_rc",
        rc_path=str(rc_path),
        log_path=str(log_path),
        authorized_by=row["authorized_by"] or "",
    )
    db.finish_exploit_run(
        run_id,
        status="prepared",
        result=msf_modules.PREPARED,
        detail="Resource script generado para ejecucion manual por el operador.",
    )
    return str(rc_path), rc_text


def exploit_target(
    scan_id: int,
    *,
    host: str,
    port: int | None,
    module_path: str,
    allow_public: bool = False,
    cancel: threading.Event | None = None,
    progress: msf_runner.ProgressCallback | None = None,
) -> str:
    """Lanza un exploit concreto contra un host. Devuelve el resultado (EXPLOITED/FAILED)."""
    row, mod = _validated_exploit_context(
        scan_id,
        host=host,
        port=port,
        module_path=module_path,
        allow_public=allow_public,
    )

    lhost = msf_lhost()
    lport = msf_lport()
    slug = module_path.replace("/", "_")
    raw = raw_dir()
    rc_path = raw / f"msf-exploit-{scan_id:05d}-{slug}-{host}.rc"
    log_path = raw / f"msf-exploit-{scan_id:05d}-{slug}-{host}.log"
    rc_path.write_text(
        msf_modules.build_exploit_script(
            mod, host, rport=port, lhost=lhost, lport=lport
        ),
        encoding="utf-8",
    )

    run_id = db.create_exploit_run(
        scan_id,
        host=host,
        port=port,
        protocol="tcp",
        engine="metasploit",
        module=module_path,
        action="exploit",
        rc_path=str(rc_path),
        log_path=str(log_path),
        authorized_by=row["authorized_by"] or "",
    )

    try:
        argv = msf_runner.build_argv(rc_path, log_path=log_path)
        execution = msf_runner.run(argv, cancel=cancel, progress=progress)
    except Exception as exc:
        db.finish_exploit_run(run_id, status="failed", result=msf_modules.ERROR, detail=str(exc))
        raise

    if not execution.ok and not execution.output.strip():
        result, evidence = msf_modules.ERROR, msf_runner.explain_failure(execution)
    else:
        result, evidence = msf_modules.parse_exploit_output(execution.output)

    status = "cancelled" if execution.cancelled else "done"
    db.finish_exploit_run(run_id, status=status, result=result, detail=evidence[:500])
    return result


def _rows_from(
    scan_id: int,
    module: MsfModule,
    portid: int,
    hosts: list[str],
    execution: msf_runner.MsfExecution,
) -> list[dict[str, object]]:
    """Convierte la salida de un modulo en filas para msf_results."""
    if not execution.ok and not execution.output.strip():
        return [
            {
                "host": host, "port": portid, "protocol": "tcp",
                "module": module.path, "module_kind": module.kind, "action": module.action,
                "result": msf_modules.ERROR,
                "detail": msf_runner.explain_failure(execution)[:500],
            }
            for host in hosts
        ]

    verdicts = msf_modules.parse_output(execution.output, default_hosts=hosts)
    rows: list[dict[str, object]] = []
    for host in hosts:
        v = verdicts.get(host)
        rows.append(
            {
                "host": host, "port": portid, "protocol": "tcp",
                "module": module.path, "module_kind": module.kind, "action": module.action,
                "result": v.result if v else msf_modules.UNKNOWN,
                "detail": (v.detail if v else "")[:500],
            }
        )
    return rows
