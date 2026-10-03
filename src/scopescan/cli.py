"""Interfaz de linea de comandos.

El panel web es la cara del producto, pero la CLI es lo que se usa en un
pipeline o por SSH: mismo motor, misma base de datos, misma numeracion de
escaneos.
"""

from __future__ import annotations

import argparse
import compileall
import ipaddress
import re
import sys
import tempfile
from pathlib import Path

from . import (
    db,
    exploitdb,
    export,
    linux_inventory,
    msf,
    msf_modules,
    msrc,
    nvd,
    report,
    service,
    windows_inventory,
)
from .config import (
    MAX_HOSTS_DEFAULT,
    MsfConsoleNotFound,
    SearchSploitNotFound,
    msf_available,
    msf_exploit_enabled,
    probe_environment,
)
from .models import Assessment, Severity
from .profiles import DEFAULT_PROFILE, PROFILES
from .service import ScanRequest
from .targets import InvalidTarget

SEV_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}
RESET = "\033[0m"


def _color(text: str, slug: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{SEV_COLORS.get(slug, '')}{text}{RESET}"


def cmd_doctor(_args: argparse.Namespace) -> int:
    env = probe_environment()
    print("Entorno de ScopeScan")
    print(f"  nmap:        {env.nmap_path or 'NO ENCONTRADO'}")
    if env.nmap_version:
        print(f"  version:     {env.nmap_version}")
    print(f"  privilegios: {'si (SYN scan y -O disponibles)' if env.privileged else 'no (solo -sT)'}")
    print(f"  metasploit:  {env.msf_path or 'no instalado (verificacion MSF deshabilitada)'}")
    print(
        "  explotacion: "
        f"{'habilitada' if msf_exploit_enabled() else 'deshabilitada (SCOPESCAN_ENABLE_EXPLOIT=1)'}"
    )
    print(f"  exploit-db:  {env.searchsploit_path or 'no instalado (correlacion Exploit-DB deshabilitada)'}")
    print(f"  datos:       {env.data_dir}")
    if not env.ready:
        print()
        print("Instala nmap con:  winget install -e --id Insecure.Nmap")
        return 1
    if env.nmap_version:
        match = re.search(r"Nmap version\s+(\d+)\.(\d+)", env.nmap_version)
        if match and tuple(map(int, match.groups())) < (7, 94):
            print()
            print("Aviso: esta version de nmap es antigua; actualiza nmap y su biblioteca NSE.")
    if not env.privileged:
        print()
        print("Sugerencia: abre la consola como administrador para el escaneo completo.")
    return 0


def cmd_self_test(_args: argparse.Namespace) -> int:
    """Chequeo local rapido: no lanza nmap ni toca la red."""
    checks: list[tuple[str, bool, str]] = []
    package_dir = Path(__file__).resolve().parent

    checks.append(("codigo", compileall.compile_dir(package_dir, quiet=1), "compileall src/scopescan"))
    checks.append(("plantillas", (package_dir / "web" / "templates").is_dir(), "web/templates existe"))
    checks.append(("estaticos", (package_dir / "web" / "static").is_dir(), "web/static existe"))
    try:
        with tempfile.TemporaryDirectory(prefix="scopescan-selftest-") as tmp:
            test_db = Path(tmp) / "selftest.sqlite3"
            db.init_db(test_db)
            checks.append(("sqlite", test_db.exists(), "schema inicializable"))
    except Exception as exc:  # noqa: BLE001 - self-test debe explicar cualquier fallo local
        checks.append(("sqlite", False, str(exc)))

    checks.append(("cli", "export" in build_parser().format_help(), "parser principal"))
    env = probe_environment()
    checks.append(("entorno", True, f"nmap={'ok' if env.ready else 'no instalado'}; datos={env.data_dir}"))

    failed = False
    print("Self-test de ScopeScan")
    for name, ok, detail in checks:
        failed = failed or not ok
        print(f"  {'OK ' if ok else 'ERR'} {name}: {detail}")
    if failed:
        return 1
    print("Self-test completado. No se ha lanzado nmap ni se ha tocado la red.")
    return 0


def cmd_profiles(_args: argparse.Namespace) -> int:
    for key, profile in PROFILES.items():
        marca = " (por defecto)" if key == DEFAULT_PROFILE else ""
        print(f"{key}{marca}")
        print(f"  {profile.label}")
        print(f"  {profile.description}")
        print()
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    db.init_db()
    request = ScanRequest(
        targets=" ".join(args.targets),
        profile=args.profile,
        name=args.name or "",
        authorized_by=args.authorized_by or "",
        notes=args.notes or "",
        force=args.force,
        max_hosts=args.max_hosts,
    )

    try:
        prepared = service.prepare(request)
    except (InvalidTarget, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(f"Objetivo:  {prepared.target_set.raw} ({prepared.target_set.hosts} host/s)")
    print(f"Comando:   {' '.join(prepared.argv_preview)}")
    for warning in prepared.warnings:
        print(f"Aviso:     {warning}")

    if not args.yes:
        respuesta = input("\nEscanea solo sistemas propios o autorizados. Continuar? [s/N] ")
        if respuesta.strip().lower() not in ("s", "si", "y", "yes"):
            print("Cancelado.")
            return 1

    scan_id = service.queue_scan(request)
    print(f"\nEscaneo #{scan_id} lanzado. Esto puede tardar.\n")
    service.execute(scan_id)

    row = db.get_scan(scan_id)
    if row is None:
        return 1
    if row["status"] != "done":
        print(f"Escaneo #{scan_id}: {row['status']}. {row['error'] or ''}", file=sys.stderr)
        _print_summary(scan_id)
        return 1

    _print_summary(scan_id)

    if args.report:
        destino = report.write_report(scan_id, Path(args.report))
        print(f"\nInforme escrito en {destino}")
    return 0


def _print_summary(scan_id: int) -> None:
    row = db.get_scan(scan_id)
    if row is None:
        return
    counts = db.severity_counts(scan_id)
    print(f"Escaneo #{scan_id} - {row['hosts_up']} host/s vivo/s, "
          f"{row['elapsed']:.0f}s, riesgo {row['risk_score']}/100")
    resumen = "  ".join(
        _color(f"{Severity(int(sev)).label}: {counts[Severity(int(sev)).slug]}",
               Severity(int(sev)).slug)
        for sev in sorted(Severity, reverse=True)
    )
    print(f"  {resumen}\n")

    for host, ports in db.hosts_with_ports(scan_id):
        if host["state"] != "up":
            continue
        print(f"{host['address']}  ({len(ports)} puertos abiertos)")
        for port in ports:
            version = f"{port['product']} {port['version']}".strip()
            print(f"    {port['portid']:>6}/{port['protocol']:<4} "
                  f"{(port['service_name'] or '?'):<16} {version}")
        print()

    findings = db.get_findings(scan_id, min_severity=int(Severity.LOW))
    if findings:
        print("Hallazgos:")
        for finding in findings:
            slug = Severity(int(finding["severity"])).slug
            etiqueta = Severity(int(finding["severity"])).label.upper()
            ubicacion = finding["host"]
            if finding["port"]:
                ubicacion += f":{finding['port']}"
            assessment = Assessment(finding["assessment"]).label
            print(f"  {_color(f'[{etiqueta:>12}]', slug)} {ubicacion:<22} "
                  f"{finding['title']} — {assessment}")
    candidates = db.get_cve_candidates(scan_id)
    if candidates:
        print(f"\nCVE candidatas por CPE: {len(candidates)} (sin confirmar)")


def cmd_list(args: argparse.Namespace) -> int:
    db.init_db()
    rows = db.list_scans(limit=args.limit)
    if not rows:
        print("No hay escaneos registrados.")
        return 0
    print(f"{'ID':>4}  {'ESTADO':<10} {'RIESGO':>6}  {'OBJETIVO':<28} {'PERFIL':<26} FECHA")
    for row in rows:
        print(f"{row['id']:>4}  {row['status']:<10} {row['risk_score']:>6}  "
              f"{row['targets'][:27]:<28} {row['profile'][:25]:<26} "
              f"{row['created_at'][:16].replace('T', ' ')}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    db.init_db()
    if db.get_scan(args.scan_id) is None:
        print(f"No existe el escaneo {args.scan_id}", file=sys.stderr)
        return 2
    _print_summary(args.scan_id)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    db.init_db()
    if db.get_scan(args.scan_id) is None:
        print(f"No existe el escaneo {args.scan_id}", file=sys.stderr)
        return 2
    destino = Path(args.output or f"informe-escaneo-{args.scan_id}.html")
    report.write_report(args.scan_id, destino)
    print(f"Informe escrito en {destino.resolve()}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    if args.format == "bundle" and not args.output:
        print("El formato bundle exige -o/--output para escribir un ZIP.", file=sys.stderr)
        return 2
    db.init_db()
    try:
        if args.format == "bundle":
            destino = Path(args.output)
            export.write_bundle(args.scan_id, destino)
            print(f"Exportacion escrita en {destino.resolve()}")
            return 0
        if args.format == "json":
            content: str | bytes = export.render_json(args.scan_id)
            binary = False
        elif args.format == "csv":
            content = export.render_findings_csv(args.scan_id)
            binary = False
        else:
            content = export.render_bundle(args.scan_id)
            binary = True
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.output:
        destino = Path(args.output)
        destino.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            destino.write_bytes(content if isinstance(content, bytes) else content.encode())
        else:
            destino.write_text(str(content), encoding="utf-8", newline="")
        print(f"Exportacion escrita en {destino.resolve()}")
    elif binary:
        print("El formato bundle exige -o/--output para escribir un ZIP.", file=sys.stderr)
        return 2
    else:
        print(content, end="")
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    db.init_db()
    try:
        count = nvd.enrich_scan(args.scan_id, include_firmware=args.include_firmware)
    except (ValueError, nvd.NvdError) as exc:
        print(f"Error NVD: {exc}", file=sys.stderr)
        return 1
    print(f"{count} coincidencias candidatas de NVD en el escaneo #{args.scan_id}.")
    print("Una coincidencia CPE no confirma vulnerabilidad ni parche pendiente.")
    return 0


def cmd_exploitdb(args: argparse.Namespace) -> int:
    db.init_db()
    try:
        count = exploitdb.enrich_scan(args.scan_id)
    except SearchSploitNotFound as exc:
        print(f"Error Exploit-DB: {exc}", file=sys.stderr)
        return 1
    except (ValueError, exploitdb.ExploitDbError) as exc:
        print(f"Error Exploit-DB: {exc}", file=sys.stderr)
        return 1
    print(f"{count} referencia(s) Exploit-DB guardadas para el escaneo #{args.scan_id}.")
    print("Son PoC publicas por CVE; scopescan no las descarga ni ejecuta.")
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    db.init_db()
    try:
        count = windows_inventory.inventory_scan(
            args.scan_id, host=args.host, local=args.local
        )
    except (ValueError, windows_inventory.InventoryError) as exc:
        print(f"Error de inventario: {exc}", file=sys.stderr)
        return 1
    print(f"Inventario autenticado guardado para {count} host(s) del escaneo #{args.scan_id}.")
    print("Incluye versiones y KB observadas; la aplicabilidad de cada CVE requiere verificar el aviso del fabricante.")
    return 0


def cmd_inventory_linux(args: argparse.Namespace) -> int:
    db.init_db()
    try:
        count = linux_inventory.inventory_scan(
            args.scan_id, host=args.host, user=args.user, port=args.port, local=args.local
        )
    except (ValueError, linux_inventory.InventoryError) as exc:
        print(f"Error de inventario Linux: {exc}", file=sys.stderr)
        return 1
    print(f"Inventario Linux autenticado guardado para {count} host(s) del escaneo #{args.scan_id}.")
    print("Se usaron claves o agente OpenSSH en modo no interactivo; no se guardaron credenciales.")
    return 0


def cmd_patches(args: argparse.Namespace) -> int:
    db.init_db()
    try:
        count = msrc.assess_scan(args.scan_id, release_id=args.release)
    except (ValueError, msrc.MsrcError) as exc:
        print(f"Error MSRC: {exc}", file=sys.stderr)
        return 1
    print(f"Evaluacion MSRC guardada: {count} CVE pendientes en el escaneo #{args.scan_id}.")
    print("La comparacion usa producto exacto y build acumulativo observado.")
    return 0


_MSF_RESULT_STYLE = {
    msf_modules.VULNERABLE: ("critical", "VULNERABLE"),
    msf_modules.LIKELY: ("high", "PROBABLE"),
    msf_modules.UNKNOWN: ("info", "SIN DATOS"),
    msf_modules.SAFE: ("low", "NO VULN."),
    msf_modules.ERROR: ("medium", "ERROR"),
}


def cmd_msf(args: argparse.Namespace) -> int:
    db.init_db()
    if db.get_scan(args.scan_id) is None:
        print(f"No existe el escaneo {args.scan_id}", file=sys.stderr)
        return 2

    plan = msf.plan_scan(args.scan_id)
    if not plan:
        print("Ningun puerto/servicio del escaneo tiene modulo de verificacion asociado.")
        print("Metasploit solo se lanza cuando hay un servicio o CVE reconocido.")
        return 0

    print(f"Plan de verificacion Metasploit para el escaneo #{args.scan_id}:")
    for address, portid, service_name, mod in plan:
        print(f"  {address}:{portid:<6} {mod.action:<6} {mod.path}  ({service_name or '?'})")
    print(
        f"\n{len(plan)} comprobacion(es). Solo scanner/`check`: scopescan NO lanza exploits "
        "ni payloads."
    )

    if args.dry_run:
        return 0

    if not msf_available():
        print(file=sys.stderr)
        print(MsfConsoleNotFound().args[0], file=sys.stderr)
        return 1

    if not args.yes:
        respuesta = input(
            "\nVerifica solo sistemas propios o autorizados. Lanzar Metasploit? [s/N] "
        )
        if respuesta.strip().lower() not in ("s", "si", "y", "yes"):
            print("Cancelado.")
            return 1

    def on_progress(line: str) -> None:
        if sys.stdout.isatty():
            print(f"  {line}")

    try:
        saved = msf.verify_scan(
            args.scan_id,
            allow_public=args.allow_public,
            authorized_by=args.authorized_by or "",
            progress=on_progress,
        )
    except msf.MsfScopeError as exc:
        print(f"\nAlcance: {exc}", file=sys.stderr)
        return 2
    except (MsfConsoleNotFound, msf.MsfError) as exc:
        print(f"\nError Metasploit: {exc}", file=sys.stderr)
        return 1

    print(f"\n{saved} veredicto(s) guardados en el escaneo #{args.scan_id}.\n")
    _print_msf_results(args.scan_id)
    return 0


def cmd_msf_catalog(_args: argparse.Namespace) -> int:
    """Lista el catalogo allowlistado de Metasploit sin tocar objetivos."""
    print("Catalogo Metasploit allowlistado")
    print("  scanner/check: se usan para verificacion")
    print("  exploit: solo se prepara .rc o se ejecuta si SCOPESCAN_ENABLE_EXPLOIT=1")
    for mod in msf_modules.catalog():
        cves = ", ".join(mod.cves) if mod.cves else "-"
        exploitable = "si" if mod.exploitable else "no"
        print()
        print(f"{mod.path}")
        print(f"  tipo: {mod.kind}; explotable: {exploitable}; payload: {mod.payload or '-'}")
        print(f"  CVE: {cves}")
        if mod.prerequisites:
            print(f"  prerequisitos: {mod.prerequisites}")
        if mod.safety_note:
            print(f"  guarda: {mod.safety_note}")
    return 0


def cmd_msf_rc(args: argparse.Namespace) -> int:
    db.init_db()
    if db.get_scan(args.scan_id) is None:
        print(f"No existe el escaneo {args.scan_id}", file=sys.stderr)
        return 2
    try:
        rc_path, _rc_text = msf.prepare_exploit_resource(
            args.scan_id,
            host=args.host,
            port=args.port,
            module_path=args.module,
            allow_public=args.allow_public,
        )
    except msf.MsfScopeError as exc:
        print(f"Alcance: {exc}", file=sys.stderr)
        return 2
    except (ValueError, msf.MsfError) as exc:
        print(f"Error Metasploit: {exc}", file=sys.stderr)
        return 1

    print(f"Resource script preparado: {rc_path}")
    print("Ejecucion manual sugerida: msfconsole -q -r <ruta-del-rc>")
    return 0


def _print_msf_results(scan_id: int) -> None:
    rows = db.get_msf_results(scan_id)
    if not rows:
        return
    for row in rows:
        slug, etiqueta = _MSF_RESULT_STYLE.get(row["result"], ("info", row["result"].upper()))
        ubicacion = f"{row['host']}:{row['port']}" if row["port"] else row["host"]
        linea = f"  {_color(f'[{etiqueta:>10}]', slug)} {ubicacion:<22} {row['module']}"
        if row["detail"]:
            linea += f"\n{' ' * 37}{row['detail']}"
        print(linea)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    try:
        local = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        local = False
    if not local:
        print("El panel sin login solo puede escucharse en 127.0.0.1 o ::1.", file=sys.stderr)
        return 2

    db.init_db()
    env = probe_environment()
    if not env.ready:
        print("Aviso: nmap no esta instalado; el panel arranca pero no podra escanear.\n")
    print(f"Panel en http://{args.host}:{args.port}")
    uvicorn.run(
        "scopescan.web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
        proxy_headers=False,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopescan",
        description="Escaner de puertos y vulnerabilidades sobre nmap, con panel web.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Escanear uno o varios objetivos")
    p_scan.add_argument("targets", nargs="+", help="IP, CIDR, rango o nombre de host")
    p_scan.add_argument("-p", "--profile", default=DEFAULT_PROFILE, choices=list(PROFILES),
                        help=f"Perfil de escaneo (por defecto: {DEFAULT_PROFILE})")
    p_scan.add_argument("-n", "--name", help="Nombre del escaneo")
    p_scan.add_argument("--authorized-by", help="Quien autoriza el escaneo (consta en el informe)")
    p_scan.add_argument("--notes", help="Notas para el informe")
    p_scan.add_argument("-r", "--report", help="Ruta del informe HTML a generar al terminar")
    p_scan.add_argument("-y", "--yes", action="store_true", help="No pedir confirmacion")
    p_scan.add_argument("--force", action="store_true",
                        help="Permitir objetivos por encima del limite de hosts")
    p_scan.add_argument("--max-hosts", type=int, default=MAX_HOSTS_DEFAULT,
                        help=f"Limite de hosts por escaneo (por defecto: {MAX_HOSTS_DEFAULT})")
    p_scan.set_defaults(func=cmd_scan)

    p_serve = sub.add_parser("serve", help="Arrancar el panel web")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true", help="Recarga automatica (desarrollo)")
    p_serve.set_defaults(func=cmd_serve)

    p_list = sub.add_parser("list", help="Listar escaneos guardados")
    p_list.add_argument("-l", "--limit", type=int, default=30)
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Mostrar el resultado de un escaneo")
    p_show.add_argument("scan_id", type=int)
    p_show.set_defaults(func=cmd_show)

    p_report = sub.add_parser("report", help="Generar el informe HTML de un escaneo")
    p_report.add_argument("scan_id", type=int)
    p_report.add_argument("-o", "--output", help="Ruta del fichero de salida")
    p_report.set_defaults(func=cmd_report)

    p_export = sub.add_parser("export", help="Exportar un escaneo a JSON, CSV o ZIP")
    p_export.add_argument("scan_id", type=int)
    p_export.add_argument("-f", "--format", choices=("json", "csv", "bundle"), default="json")
    p_export.add_argument("-o", "--output", help="Ruta de salida; si se omite escribe en stdout")
    p_export.set_defaults(func=cmd_export)

    p_enrich = sub.add_parser("enrich", help="Cruzar CPE de un escaneo con NVD (candidatos)")
    p_enrich.add_argument("scan_id", type=int)
    p_enrich.add_argument(
        "--include-firmware", action="store_true",
        help="Enviar tambien a NVD la version Intel ME obtenida por inventario autenticado",
    )
    p_enrich.set_defaults(func=cmd_enrich)

    p_exploitdb = sub.add_parser(
        "exploitdb", help="Cruzar las CVE de un escaneo con Exploit-DB/SearchSploit"
    )
    p_exploitdb.add_argument("scan_id", type=int)
    p_exploitdb.set_defaults(func=cmd_exploitdb)

    p_inventory = sub.add_parser("inventory", help="Inventario autenticado Windows por WinRM")
    p_inventory.add_argument("scan_id", type=int)
    p_inventory.add_argument("--host", help="Un host de este escaneo; por defecto todos los vivos")
    p_inventory.add_argument("--local", action="store_true",
                             help="Recoger datos del equipo local (exige --host si hay varios)")
    p_inventory.set_defaults(func=cmd_inventory)

    p_linux = sub.add_parser("inventory-linux", help="Inventario autenticado Linux por OpenSSH")
    p_linux.add_argument("scan_id", type=int)
    p_linux.add_argument("--host", help="Un host vivo de este escaneo; por defecto todos")
    p_linux.add_argument("--user", help="Usuario SSH; por defecto usa la configuracion OpenSSH")
    p_linux.add_argument("--port", type=int, default=22, help="Puerto SSH (por defecto: 22)")
    p_linux.add_argument("--local", action="store_true",
                         help="Recoger el equipo Linux local; exige un host loopback")
    p_linux.set_defaults(func=cmd_inventory_linux)

    p_patches = sub.add_parser("patches", help="Evaluar el build Windows con Microsoft MSRC")
    p_patches.add_argument("scan_id", type=int)
    p_patches.add_argument("--release", help="Boletin CVRF concreto, por ejemplo 2026-Sep")
    p_patches.set_defaults(func=cmd_patches)

    p_msf = sub.add_parser(
        "msf", help="Verificar explotabilidad con Metasploit (scanner + check, sin exploits)"
    )
    p_msf.add_argument("scan_id", type=int)
    p_msf.add_argument("--dry-run", action="store_true",
                       help="Solo mostrar el plan de modulos, sin lanzar msfconsole")
    p_msf.add_argument("-y", "--yes", action="store_true", help="No pedir confirmacion")
    p_msf.add_argument("--allow-public", action="store_true",
                       help="Permitir verificar objetivos fuera de rango privado (exige autorizacion)")
    p_msf.add_argument("--authorized-by", help="Quien autoriza (obligatorio con --allow-public)")
    p_msf.set_defaults(func=cmd_msf)

    p_msf_catalog = sub.add_parser(
        "msf-catalog", help="Listar el catalogo Metasploit allowlistado"
    )
    p_msf_catalog.set_defaults(func=cmd_msf_catalog)

    p_msf_rc = sub.add_parser(
        "msf-rc", help="Preparar un .rc de explotacion Metasploit para ejecucion manual"
    )
    p_msf_rc.add_argument("scan_id", type=int)
    p_msf_rc.add_argument("--host", required=True, help="Host del escaneo ya verificado")
    p_msf_rc.add_argument("--module", required=True, help="Modulo exploit de Metasploit")
    p_msf_rc.add_argument("--port", type=int, help="Puerto remoto, si aplica")
    p_msf_rc.add_argument("--allow-public", action="store_true",
                          help="Permitir objetivo publico si el escaneo tiene autorizacion")
    p_msf_rc.set_defaults(func=cmd_msf_rc)

    p_doctor = sub.add_parser("doctor", help="Comprobar el entorno (nmap, privilegios, rutas)")
    p_doctor.set_defaults(func=cmd_doctor)

    p_self_test = sub.add_parser("self-test", help="Comprobar instalacion local sin tocar la red")
    p_self_test.set_defaults(func=cmd_self_test)

    p_profiles = sub.add_parser("profiles", help="Listar los perfiles de escaneo")
    p_profiles.set_defaults(func=cmd_profiles)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\nInterrumpido.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
