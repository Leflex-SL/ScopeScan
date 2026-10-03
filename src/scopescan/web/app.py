"""Panel web: lanzar escaneos, seguirlos en vivo y consultar hallazgos."""

from __future__ import annotations

import ipaddress
import json
from base64 import b64decode
from binascii import Error as Base64Error
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import (
    attack_paths,
    db,
    exploitdb,
    export,
    linux_inventory,
    msf,
    msf_modules,
    msrc,
    nvd,
    report,
    windows_inventory,
)
from ..config import (
    msf_available,
    msf_exploit_enabled,
    panel_auth_enabled,
    panel_auth_matches,
    probe_environment,
    searchsploit_available,
)
from ..jobs import QUEUE
from ..models import Assessment, Severity
from ..profiles import DEFAULT_PROFILE, PROFILES
from ..service import ScanRequest, prepare, queue_scan, rerun
from ..targets import InvalidTarget

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    # Un escaneo que quedo 'running' de un arranque anterior ya no tiene hilo
    # detras: se cierra para que el panel no mienta sobre su estado.
    db.reset_stale_scans()
    db.reset_stale_enrichments()
    yield
    QUEUE.shutdown()


app = FastAPI(title="ScopeScan", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def local_access_only(request: Request, call_next):
    """El panel maneja inventarios autenticados; remoto exige Basic Auth opt-in."""
    try:
        local = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        local = False
    if not local and not _basic_auth_ok(request):
        headers = {}
        if panel_auth_enabled():
            headers["WWW-Authenticate"] = 'Basic realm="ScopeScan"'
        return PlainTextResponse(
            "El panel solo acepta conexiones locales o autenticacion configurada",
            status_code=403,
            headers=headers,
        )
    if not _same_origin_write(request):
        return PlainTextResponse("Origen del formulario no permitido", status_code=403)
    return await call_next(request)


def _basic_auth_ok(request: Request) -> bool:
    """Permite clientes no locales solo cuando el operador configuro Basic Auth."""
    if not panel_auth_enabled():
        return False
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "basic" or not token:
        return False
    try:
        raw = b64decode(token, validate=True).decode("utf-8")
    except (Base64Error, UnicodeDecodeError):
        return False
    user, separator, password = raw.partition(":")
    return bool(separator) and panel_auth_matches(user, password)


def _same_origin_write(request: Request) -> bool:
    """Mitiga CSRF del panel local para metodos que cambian estado.

    Los clientes sin cabeceras Origin/Referer siguen funcionando (curl, tests,
    scripts locales). Los navegadores modernos envian Origin en POST; si aparece
    una cabecera de navegador, debe coincidir exactamente con el host del panel.
    """
    if request.method.upper() not in _UNSAFE_METHODS:
        return True
    origin = request.headers.get("origin")
    if origin:
        return _matches_panel_origin(request, origin)
    referer = request.headers.get("referer")
    if referer:
        return _matches_panel_origin(request, referer)
    return True


def _matches_panel_origin(request: Request, value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    expected_host = (request.url.hostname or "").strip("[]").lower()
    actual_host = parsed.hostname.strip("[]").lower()
    if actual_host != expected_host:
        return False
    expected_port = request.url.port or (443 if request.url.scheme == "https" else 80)
    actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme == request.url.scheme and actual_port == expected_port


def _severity_meta() -> list[dict[str, str | int]]:
    return [
        {"slug": sev.slug, "label": sev.label, "value": int(sev)}
        for sev in sorted(Severity, reverse=True)
    ]


templates.env.globals["severity_meta"] = _severity_meta()
templates.env.globals["Severity"] = Severity
templates.env.globals["severity_label"] = lambda value: Severity(int(value)).label
templates.env.globals["severity_slug"] = lambda value: Severity(int(value)).slug
templates.env.globals["assessment_label"] = lambda value: Assessment(value).label
templates.env.globals["nvd_match_note"] = nvd.match_note


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "stats": db.global_stats(),
            "scans": db.list_scans(limit=25),
            "env": probe_environment(),
            "active": QUEUE.active_ids(),
        },
    )


@app.get("/scans/new", response_class=HTMLResponse)
def new_scan_form(request: Request, targets: str = ""):
    return templates.TemplateResponse(
        request,
        "new_scan.html",
        {
            "profiles": PROFILES,
            "default_profile": DEFAULT_PROFILE,
            "env": probe_environment(),
            "targets": targets,
            "error": None,
        },
    )


@app.post("/scans")
def create_scan(
    request: Request,
    targets: str = Form(...),
    profile: str = Form(DEFAULT_PROFILE),
    name: str = Form(""),
    authorized_by: str = Form(""),
    notes: str = Form(""),
    force: str = Form(""),
    authorized: str = Form(""),
):
    # Sin la casilla de autorizacion no se lanza nada. No es un tramite legal,
    # pero obliga a parar un segundo y a dejar por escrito quien lo autoriza.
    if not authorized:
        return _form_error(request, targets, "Confirma que tienes autorizacion sobre el objetivo.")

    scan_request = ScanRequest(
        targets=targets,
        profile=profile,
        name=name,
        authorized_by=authorized_by,
        notes=notes,
        force=bool(force),
    )
    try:
        prepare(scan_request)
    except InvalidTarget as exc:
        return _form_error(request, targets, str(exc))
    except KeyError as exc:
        return _form_error(request, targets, str(exc))

    scan_id = queue_scan(scan_request)
    QUEUE.submit(scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _form_error(request: Request, targets: str, message: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "new_scan.html",
        {
            "profiles": PROFILES,
            "default_profile": DEFAULT_PROFILE,
            "env": probe_environment(),
            "targets": targets,
            "error": message,
        },
        status_code=400,
    )


@app.post("/api/preview")
def preview(targets: str = Form(...), profile: str = Form(DEFAULT_PROFILE)):
    """Vista previa para el formulario: comando, hosts y avisos, sin lanzar nada."""
    try:
        prepared = prepare(ScanRequest(targets=targets, profile=profile, force=True))
    except (InvalidTarget, KeyError) as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=200)
    return {
        "ok": True,
        "hosts": prepared.target_set.hosts,
        "private": prepared.target_set.all_private,
        "command": " ".join(prepared.argv_preview),
        "warnings": prepared.warnings,
    }


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int, min_severity: int = 0):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")

    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {
            "scan": scan,
            "hosts": db.hosts_with_ports(scan_id),
            "findings": db.get_findings(scan_id, min_severity=min_severity),
            "candidates": db.get_cve_candidates(scan_id),
            "exploitdb_results": db.get_exploitdb_results(scan_id),
            "controls": db.get_control_results(scan_id),
            "patch_statuses": db.get_windows_patch_statuses(scan_id),
            "patch_candidates": db.get_windows_patch_candidates(scan_id),
            "inventories": db.get_host_inventories(scan_id),
            "enrichment": db.get_enrichment_statuses(scan_id),
            "counts": db.severity_counts(scan_id),
            "attack_paths": attack_paths.build(scan_id),
            "min_severity": min_severity,
            "active": QUEUE.is_active(scan_id),
            "msf_results": db.get_msf_results(scan_id),
            "exploit_runs": db.get_exploit_runs(scan_id),
            "msf_exploitable": msf.exploitable_results(scan_id),
            "msf_available": msf_available(),
            "msf_exploit_enabled": msf_exploit_enabled(),
            "searchsploit_available": searchsploit_available(),
            "msf_result_slug": _msf_result_slug,
            "json": json,
        },
    )


# Severidad visual de cada veredicto MSF, para reutilizar los colores del panel.
_MSF_SLUG = {
    msf_modules.PREPARED: "info",
    msf_modules.EXPLOITED: "critical",
    msf_modules.VULNERABLE: "critical",
    msf_modules.LIKELY: "high",
    msf_modules.FAILED: "medium",
    msf_modules.ERROR: "medium",
    msf_modules.UNKNOWN: "info",
    msf_modules.SAFE: "low",
}


def _msf_result_slug(result: str) -> str:
    return _MSF_SLUG.get(result, "info")


@app.get("/api/scans/{scan_id}/status")
def scan_status(scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return {
        "id": scan_id,
        "status": scan["status"],
        "progress": scan["progress"],
        "task": scan["progress_task"],
        "error": scan["error"],
        "counts": db.severity_counts(scan_id),
        "risk": scan["risk_score"],
        "enrichment": {
            kind: job["status"] for kind, job in db.get_enrichment_statuses(scan_id).items()
        },
    }


@app.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int):
    QUEUE.cancel(scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@app.post("/scans/{scan_id}/rerun")
def rerun_scan(scan_id: int):
    new_id = rerun(scan_id)
    QUEUE.submit(new_id)
    return RedirectResponse(f"/scans/{new_id}", status_code=303)


@app.post("/scans/{scan_id}/delete")
def delete_scan(scan_id: int):
    QUEUE.cancel(scan_id)
    db.delete_scan(scan_id)
    return RedirectResponse("/", status_code=303)


@app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
def scan_report(scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return HTMLResponse(report.render_report(scan_id))


@app.get("/scans/{scan_id}/export.json")
def scan_export_json(scan_id: int):
    if db.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return Response(
        export.render_json(scan_id),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="scopescan-{scan_id:05d}.json"'
        },
    )


@app.get("/scans/{scan_id}/findings.csv")
def scan_findings_csv(scan_id: int):
    if db.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return Response(
        export.render_findings_csv(scan_id),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="scopescan-{scan_id:05d}-findings.csv"'
            )
        },
    )


@app.get("/scans/{scan_id}/bundle.zip")
def scan_bundle_zip(scan_id: int):
    if db.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return Response(
        export.render_bundle(scan_id),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="scopescan-{scan_id:05d}.zip"'
        },
    )


def _run_nvd(scan_id: int, include_firmware: bool) -> None:
    try:
        nvd.enrich_scan(scan_id, include_firmware=include_firmware)
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, "nvd", "failed", str(exc))
    else:
        db.set_enrichment_status(scan_id, "nvd", "done")


@app.post("/scans/{scan_id}/enrich/nvd")
def enrich_nvd(
    scan_id: int, background_tasks: BackgroundTasks, include_firmware: str = Form("")
):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan["status"] != "done":
        raise HTTPException(status_code=409, detail="El escaneo debe terminar primero")
    status = db.get_enrichment_statuses(scan_id).get("nvd")
    if not status or status["status"] != "running":
        db.set_enrichment_status(scan_id, "nvd", "running")
        background_tasks.add_task(_run_nvd, scan_id, bool(include_firmware))
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _run_windows_inventory(scan_id: int, host: str, local: bool) -> None:
    try:
        windows_inventory.inventory_scan(scan_id, host=host, local=local)
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, "windows", "failed", str(exc))
    else:
        db.set_enrichment_status(scan_id, "windows", "done")


@app.post("/scans/{scan_id}/inventory/windows")
def windows_inventory_route(
    scan_id: int, background_tasks: BackgroundTasks,
    host: str = Form(...), local: str = Form(""),
):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan["status"] != "done":
        raise HTTPException(status_code=409, detail="El escaneo debe terminar primero")
    if host not in {row["address"] for row in db.get_hosts(scan_id)}:
        raise HTTPException(status_code=400, detail="Host fuera del escaneo")
    status = db.get_enrichment_statuses(scan_id).get("windows")
    if not status or status["status"] != "running":
        db.set_enrichment_status(scan_id, "windows", "running")
        background_tasks.add_task(_run_windows_inventory, scan_id, host, bool(local))
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _run_linux_inventory(scan_id: int, host: str, user: str, port: int, local: bool) -> None:
    try:
        linux_inventory.inventory_scan(
            scan_id, host=host, user=user or None, port=port, local=local
        )
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, "linux", "failed", str(exc))
    else:
        db.set_enrichment_status(scan_id, "linux", "done")


@app.post("/scans/{scan_id}/inventory/linux")
def linux_inventory_route(
    scan_id: int, background_tasks: BackgroundTasks,
    host: str = Form(...), user: str = Form(""), port: int = Form(22),
    local: str = Form(""),
):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan["status"] != "done":
        raise HTTPException(status_code=409, detail="El escaneo debe terminar primero")
    if host not in {row["address"] for row in db.get_hosts(scan_id)}:
        raise HTTPException(status_code=400, detail="Host fuera del escaneo")
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=400, detail="Puerto SSH invalido")
    if user and not linux_inventory.SSH_USER.fullmatch(user):
        raise HTTPException(status_code=400, detail="Usuario SSH invalido")
    status = db.get_enrichment_statuses(scan_id).get("linux")
    if not status or status["status"] != "running":
        db.set_enrichment_status(scan_id, "linux", "running")
        background_tasks.add_task(
            _run_linux_inventory, scan_id, host, user, port, bool(local)
        )
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _run_msrc(scan_id: int) -> None:
    try:
        msrc.assess_scan(scan_id)
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, "msrc", "failed", str(exc))


@app.post("/scans/{scan_id}/enrich/msrc")
def enrich_msrc(scan_id: int, background_tasks: BackgroundTasks):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan["status"] != "done":
        raise HTTPException(status_code=409, detail="El escaneo debe terminar primero")
    if not any(data.get("platform", "windows") == "windows"
               for data in db.get_host_inventories(scan_id).values()):
        raise HTTPException(status_code=409, detail="Primero ejecuta el inventario Windows")
    status = db.get_enrichment_statuses(scan_id).get("msrc")
    if not status or status["status"] != "running":
        db.set_enrichment_status(scan_id, "msrc", "running")
        background_tasks.add_task(_run_msrc, scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _run_exploitdb(scan_id: int) -> None:
    try:
        exploitdb.enrich_scan(scan_id)
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, exploitdb.ENRICH_KIND, "failed", str(exc))


@app.post("/scans/{scan_id}/enrich/exploitdb")
def enrich_exploitdb(scan_id: int, background_tasks: BackgroundTasks):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan["status"] != "done":
        raise HTTPException(status_code=409, detail="El escaneo debe terminar primero")
    if not searchsploit_available():
        raise HTTPException(status_code=409, detail="searchsploit no esta instalado")
    status = db.get_enrichment_statuses(scan_id).get(exploitdb.ENRICH_KIND)
    if not status or status["status"] != "running":
        db.set_enrichment_status(scan_id, exploitdb.ENRICH_KIND, "running")
        background_tasks.add_task(_run_exploitdb, scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _run_msf_verify(scan_id: int) -> None:
    try:
        msf.verify_scan(scan_id)
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, msf.ENRICH_KIND, "failed", str(exc))


@app.post("/scans/{scan_id}/enrich/msf")
def enrich_msf(scan_id: int, background_tasks: BackgroundTasks):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan["status"] != "done":
        raise HTTPException(status_code=409, detail="El escaneo debe terminar primero")
    if not msf_available():
        raise HTTPException(status_code=409, detail="msfconsole no esta instalado")
    status = db.get_enrichment_statuses(scan_id).get(msf.ENRICH_KIND)
    if not status or status["status"] != "running":
        db.set_enrichment_status(scan_id, msf.ENRICH_KIND, "running")
        background_tasks.add_task(_run_msf_verify, scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@app.post("/scans/{scan_id}/msf/exploit-rc")
def msf_exploit_rc(
    scan_id: int,
    host: str = Form(...),
    module: str = Form(...),
    port: str = Form(""),
    authorized: str = Form(""),
):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if not authorized:
        raise HTTPException(status_code=400, detail="Debes confirmar la autorizacion")

    portid = int(port) if port.isdigit() else None
    try:
        rc_path, rc_text = msf.prepare_exploit_resource(
            scan_id, host=host, port=portid, module_path=module
        )
    except msf.MsfScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (ValueError, msf.MsfError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    filename = Path(rc_path).name
    return PlainTextResponse(
        rc_text,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _run_msf_exploit(scan_id: int, host: str, port: int | None, module_path: str) -> None:
    try:
        msf.exploit_target(scan_id, host=host, port=port, module_path=module_path)
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, "metasploit-exploit", "failed", str(exc))
    else:
        db.set_enrichment_status(scan_id, "metasploit-exploit", "done")


@app.post("/scans/{scan_id}/msf/exploit")
def msf_exploit(
    scan_id: int,
    background_tasks: BackgroundTasks,
    host: str = Form(...),
    module: str = Form(...),
    port: str = Form(""),
    authorized: str = Form(""),
):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if not msf_available():
        raise HTTPException(status_code=409, detail="msfconsole no esta instalado")
    if not msf_exploit_enabled():
        raise HTTPException(
            status_code=409,
            detail=(
                "La explotacion directa esta deshabilitada. Usa Preparar .rc "
                "o define SCOPESCAN_ENABLE_EXPLOIT=1."
            ),
        )
    # Casilla de autorizacion obligatoria: explotar es una accion deliberada.
    if not authorized:
        raise HTTPException(status_code=400, detail="Debes confirmar la autorizacion para explotar")

    portid = int(port) if port.isdigit() else None
    # Validacion barata aqui (host del escaneo, modulo del catalogo). El scope real
    # (privado/autorizado + verificacion previa) lo revalida exploit_target antes
    # de disparar, ya en segundo plano.
    if host not in {h["address"] for h in db.get_hosts(scan_id)}:
        raise HTTPException(status_code=403, detail="El host no pertenece a este escaneo")
    mod = msf_modules.module_by_path(module)
    if mod is None or not mod.exploitable:
        raise HTTPException(status_code=400, detail="Modulo no explotable o desconocido")

    status = db.get_enrichment_statuses(scan_id).get("metasploit-exploit")
    if not status or status["status"] != "running":
        db.set_enrichment_status(scan_id, "metasploit-exploit", "running")
        background_tasks.add_task(_run_msf_exploit, scan_id, host, portid, module)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@app.get("/findings", response_class=HTMLResponse)
def findings_view(request: Request, min_severity: int = int(Severity.LOW)):
    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "findings": db.recent_findings(limit=300, min_severity=min_severity),
            "min_severity": min_severity,
        },
    )
