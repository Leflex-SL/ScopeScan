"""Orquestacion de un escaneo completo: validar, lanzar, parsear, analizar, guardar."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import analysis, db, nmap_parser, nmap_runner
from .config import MAX_HOSTS_DEFAULT, NmapNotFound, is_privileged, raw_dir, scan_timeout
from .models import Finding, NmapRun
from .profiles import DEFAULT_PROFILE, get_profile
from .scopes import pin_targets
from .targets import InvalidTarget, TargetSet, parse_targets


@dataclass
class ScanRequest:
    targets: str
    profile: str = DEFAULT_PROFILE
    name: str = ""
    authorized_by: str = ""
    notes: str = ""
    force: bool = False
    max_hosts: int = MAX_HOSTS_DEFAULT
    exclusions: str = ""
    scope_id: int | None = None


@dataclass
class PreparedScan:
    request: ScanRequest
    target_set: TargetSet
    argv_preview: list[str]
    warnings: list[str]
    privileged: bool = False


def prepare(request: ScanRequest) -> PreparedScan:
    """Valida el encargo y calcula que se va a ejecutar, sin lanzarlo todavia.

    Separar esto de la ejecucion permite que el panel enseñe el comando exacto y
    los avisos antes de que el usuario confirme.
    """
    target_set = pin_targets(request.targets, request.exclusions,
                             max_hosts=request.max_hosts, force=request.force).target_set
    if request.scope_id is not None:
        from .scopes import get_scope
        scope = get_scope(request.scope_id)
        if (set(target_set.argv) != set(scope["pinned_targets"])
                or request.profile != scope["profile"]
                or request.authorized_by != scope["authorized_by"]):
            raise InvalidTarget("El encargo no coincide con el alcance guardado; usa queue_scope")
    profile = get_profile(request.profile)
    privileged = is_privileged()

    warnings = list(target_set.warnings) + profile.warnings(privileged=privileged)

    try:
        argv = nmap_runner.build_argv(
            targets=target_set.argv,
            profile_args=profile.nmap_args(privileged=privileged),
            xml_path=Path("<salida>.xml"),
        )
    except NmapNotFound as exc:
        warnings.append(str(exc))
        argv = []

    return PreparedScan(
        request=request, target_set=target_set, argv_preview=argv, warnings=warnings,
        privileged=privileged,
    )


def queue_scan(request: ScanRequest, *, prepared: PreparedScan | None = None) -> int:
    """Crea la fila del escaneo en estado 'queued' y devuelve su id."""
    prepared = prepared or prepare(request)
    if prepared.request != request:
        raise InvalidTarget("El preview no corresponde a este encargo")
    name = request.name.strip() or f"{prepared.target_set.raw} ({request.profile})"
    scope_snapshot = None
    if request.scope_id is not None:
        saved = db.get_scope(request.scope_id)
        if saved is None:
            raise InvalidTarget("El alcance guardado ya no existe")
        scope_snapshot = {key:saved[key] for key in (
            "profile","authorized_by","pinned_targets","resolutions","exclusions","max_hosts")}
    scan_id = db.create_scan(
        name=name,
        targets=prepared.target_set.raw,
        profile=request.profile,
        target_private=prepared.target_set.all_private,
        authorized_by=request.authorized_by,
        notes=request.notes,
        scope_id=request.scope_id,
        reserve_job=True,
        execution_context={"pinned_targets": prepared.target_set.argv,
                           "privileged":prepared.privileged,"profile":request.profile,
                           "exclusions":request.exclusions,"scope_snapshot":scope_snapshot},
    )
    return scan_id


def execute(scan_id: int, *, cancel: threading.Event | None = None) -> None:
    """Ejecuta un escaneo ya encolado. Pensado para correr en un hilo aparte.

    No propaga excepciones: cualquier fallo se registra en la fila del escaneo,
    porque el unico sitio donde el usuario lo va a ver es el panel.
    """
    row = db.get_scan(scan_id)
    if row is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    if cancel is not None and cancel.is_set():
        db.set_status(scan_id, "cancelled", error="Cancelado antes de empezar")
        return
    if not db.claim_scan_execution(scan_id):
        return

    try:
        context = json.loads(row["execution_context"] or "{}")
        if context.get("engine_plan"):
            from .engine_service import decode_plan
            from .engine_service import execute as execute_engine

            execute_engine(decode_plan(context["engine_plan"]),scan_id=scan_id,cancel=cancel)
            return
        if context.get("authenticated"):
            from .verification import execute_authenticated
            execute_authenticated(scan_id, context, cancel=cancel)
            return
        if row["scope_id"] is not None:
            saved = db.get_scope(row["scope_id"])
            snapshot = context.get("scope_snapshot")
            if (saved is None or saved["authorized_by"] != row["authorized_by"]
                    or saved["profile"] != row["profile"]
                    or set(saved["pinned_targets"]) != set(context.get("pinned_targets", []))
                    or snapshot and snapshot != {key:saved[key] for key in snapshot}):
                raise InvalidTarget("El alcance, perfil, límites o autorización cambiaron; revisa y vuelve a encolar")
        pinned = context.get("pinned_targets")
        target_set = parse_targets(" ".join(pinned) if pinned else row["targets"], force=True)
        # Historical rows may predate pinned scopes. Resolve them safely once.
        if not pinned:
            target_set = pin_targets(row["targets"], force=True).target_set
        profile = get_profile(row["profile"])
        privileged = context.get("privileged", is_privileged())
        if privileged and not is_privileged():
            raise InvalidTarget("Los privilegios cambiaron desde el preview; vuelve a encolar")
    except (InvalidTarget, KeyError, ValueError, TypeError, OSError, RuntimeError) as exc:
        db.set_status(scan_id, "failed", error=str(exc))
        return

    # Hora local: el nombre del XML se lee a ojo al buscarlo en disco.
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")  # noqa: DTZ005
    xml_path = raw_dir() / f"scan-{scan_id:05d}-{stamp}.xml"

    try:
        argv = nmap_runner.build_argv(
            targets=target_set.argv,
            profile_args=_execution_args(profile.key, context, privileged=privileged),
            xml_path=xml_path,
        )
    except NmapNotFound as exc:
        db.set_status(scan_id, "failed", error=str(exc))
        return

    db.set_nmap_args(scan_id, " ".join(argv), str(xml_path))
    db.set_status(scan_id, "running")
    db.set_progress(scan_id, 0, "Iniciando nmap")

    def on_progress(percent: float, task: str) -> None:
        # -1 significa "sin porcentaje todavia": se conserva el ultimo conocido.
        if percent < 0:
            current = db.get_scan(scan_id)
            percent = float(current["progress"]) if current else 0.0
        db.set_progress(scan_id, percent, task)

    try:
        execution = nmap_runner.run(argv, progress=on_progress, cancel=cancel,
                                    timeout=scan_timeout())
    except OSError as exc:
        db.set_status(scan_id, "failed", error=f"No se pudo lanzar nmap: {exc}")
        return

    _store(scan_id, execution, target_private=bool(row["target_private"]))


def _store(scan_id: int, execution: nmap_runner.NmapExecution, *, target_private: bool) -> None:
    """Parsea el XML, analiza y guarda. El XML parcial de un escaneo cancelado
    tambien se aprovecha: lo escaneado hasta ese momento es informacion valida."""
    run: NmapRun | None = None
    parse_error = ""
    if execution.xml_path.exists():
        try:
            run = nmap_parser.parse_file(execution.xml_path)
        except nmap_parser.NmapParseError as exc:
            parse_error = str(exc)

    if run is not None:
        row = db.get_scan(scan_id)
        context = json.loads(row["execution_context"] or "{}") if row else {}
        from .verification import enrich_coverage
        enrich_coverage(run)
        if not execution.ok:
            run.coverage["status"] = "partial"
        context["coverage"] = run.coverage
        context["observed_at"] = run.start or db.now()
        context["provenance"] = {"engine": "nmap", "imported": False,
                                 "raw_path": str(execution.xml_path)}
        db.set_scan_context(scan_id, scope_id=row["scope_id"] if row else None,
                            execution_context=context)
        findings: list[Finding] = analysis.analyze(run, target_is_private=target_private)
        db.save_results(scan_id, run, findings, analysis.risk_score(findings))

    if execution.cancelled:
        db.set_status(scan_id, "cancelled", error="Cancelado por el usuario")
        return

    if not execution.ok:
        db.set_status(scan_id, "failed", error=nmap_runner.explain_failure(execution))
        return

    if run is None:
        db.set_status(
            scan_id,
            "failed",
            error=parse_error or "nmap termino sin generar el XML de resultados",
        )
        return

    db.set_progress(scan_id, 100, "Completado")
    db.set_status(scan_id, "done")


def rerun(scan_id: int) -> int:
    """Encola de nuevo un escaneo con los mismos parametros. Devuelve el nuevo id."""
    row = db.get_scan(scan_id)
    if row is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    if row["profile"] == "imported":
        raise ValueError("Un resultado importado no es una orden ejecutable; crea un alcance")
    context = json.loads(row["execution_context"] or "{}")
    if context.get("engine_plan"):
        raise ValueError("Para repetir un motor, revisa su alcance vigente en /engines antes de ejecutar")
    if context.get("provenance", {}).get("imported"):
        raise ValueError("Un resultado importado no es una orden ejecutable; crea un alcance")
    if any(key in context for key in ("verification", "authenticated", "verification_of")):
        from .verification import rerun_verification
        return rerun_verification(row)
    if row["profile"] == "authenticated":
        raise ValueError("La verificacion autenticada no conserva un plan valido; "
                         "selecciona el hallazgo vigente y usa Verificar")
    request = ScanRequest(name=row["name"], targets=row["targets"], profile=row["profile"],
                          authorized_by=row["authorized_by"], notes=row["notes"], force=True,
                          scope_id=row["scope_id"])
    new_id = queue_scan(request)
    namespace = context.get("namespace") or (
        f"scope:{row['scope_id']}" if row["scope_id"] is not None else f"scan:{scan_id}")
    db.set_scan_context(new_id, scope_id=row["scope_id"], execution_context={"namespace": namespace})
    return new_id


def _execution_args(profile: str, context: dict, *, privileged: bool) -> list[str]:
    verification = context.get("verification")
    if verification:
        from .verification import nmap_args_for_verification
        return nmap_args_for_verification(verification, privileged=privileged)
    return get_profile(profile).nmap_args(privileged=privileged)
