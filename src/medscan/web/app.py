"""Panel web: lanzar escaneos, seguirlos en vivo y consultar hallazgos."""

from __future__ import annotations

import ipaddress
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import db, linux_inventory, msrc, nvd, report, windows_inventory
from ..config import probe_environment
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


app = FastAPI(title="Medscan", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.middleware("http")
async def local_access_only(request: Request, call_next):
    """El panel maneja inventarios autenticados y no tiene login propio."""
    try:
        local = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        local = False
    if not local:
        return PlainTextResponse("El panel solo acepta conexiones locales", status_code=403)
    return await call_next(request)


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
            "controls": db.get_control_results(scan_id),
            "patch_statuses": db.get_windows_patch_statuses(scan_id),
            "patch_candidates": db.get_windows_patch_candidates(scan_id),
            "inventories": db.get_host_inventories(scan_id),
            "enrichment": db.get_enrichment_statuses(scan_id),
            "counts": db.severity_counts(scan_id),
            "min_severity": min_severity,
            "active": QUEUE.is_active(scan_id),
            "json": json,
        },
    )


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
