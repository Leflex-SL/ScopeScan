"""Panel web: lanzar escaneos, seguirlos en vivo y consultar hallazgos."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
from base64 import b64decode
from binascii import Error as Base64Error
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask

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
    yield
    QUEUE.shutdown()


app = FastAPI(title="ScopeScan", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

from .continuity import preview_evidence
from .continuity import router as continuity_router

app.include_router(continuity_router)
from .engines import router as engines_router

app.include_router(engines_router)
from .jobs import router as jobs_router

app.include_router(jobs_router)
for route_module in ("software", "integrations"):
    import importlib
    try:
        optional_routes = importlib.import_module(f"scopescan.web.{route_module}")
    except ModuleNotFoundError as exc:
        if exc.name != f"scopescan.web.{route_module}":
            raise
    else:
        app.include_router(optional_routes.router)
templates.env.globals["preview_evidence"] = preview_evidence


_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


_CSRF_SECRET = secrets.token_bytes(32)
_CSRF_COOKIE = "scopescan_csrf"


def _canonical_origin(value: str, *, referer: bool = False) -> tuple[str, str, int] | None:
    try:
        if any(ord(char) < 32 or char.isspace() for char in value):
            return None
        parsed = urlparse(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or (not referer and (parsed.path not in {"", "/"}
                                                        or parsed.query))):
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            return None
        return parsed.scheme, parsed.hostname.lower(), port
    except ValueError:
        return None


def _allowed_hosts() -> set[str]:
    return {"localhost", "127.0.0.1", "::1"} | {
        host.strip().lower().strip("[]")
        for host in os.getenv("SCOPESCAN_PANEL_HOSTS", "").split(",") if host.strip()
    }


def _host_allowed(request: Request) -> bool:
    host = request.headers.get("host", "")
    origin = _canonical_origin("http://" + host)
    return origin is not None and origin[1] in _allowed_hosts()


def _allowed_origins() -> set[tuple[str, str, int]]:
    configured = os.getenv("SCOPESCAN_PANEL_ORIGINS")
    values = configured.split(",") if configured is not None else [
        f"{scheme}://{host}{port}" for host in ("localhost", "127.0.0.1", "[::1]")
        for scheme, port in (("http", ""), ("http", ":8000"), ("https", ""))
    ]
    return {origin for value in values if (origin := _canonical_origin(value.strip()))}


def _csrf_token() -> str:
    nonce = secrets.token_hex(24)
    return nonce + "." + hmac.new(_CSRF_SECRET, nonce.encode(), hashlib.sha256).hexdigest()


def _valid_csrf(token: str) -> bool:
    if len(token) != 113 or re.fullmatch(r"[0-9a-f]{48}\.[0-9a-f]{64}", token) is None:
        return False
    nonce, sep, signature = token.partition(".")
    return bool(sep) and hmac.compare_digest(
        signature, hmac.new(_CSRF_SECRET, nonce.encode(), hashlib.sha256).hexdigest()
    )


@app.middleware("http")
async def local_access_only(request: Request, call_next):
    """Host trust is explicit; forwarded headers never grant local access."""
    if not _host_allowed(request):
        return PlainTextResponse("Host del panel no permitido", status_code=403)
    try:
        local = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        local = False
    if (panel_auth_enabled() or not local) and not _basic_auth_ok(request):
        headers = {"WWW-Authenticate": 'Basic realm="ScopeScan"'} if panel_auth_enabled() else {}
        return PlainTextResponse("Autenticacion configurada requerida o acceso solo local",
                                 status_code=401 if panel_auth_enabled() else 403, headers=headers)
    if not _same_origin_write(request):
        return PlainTextResponse("Origen del formulario no permitido", status_code=403)
    cookie = request.cookies.get(_CSRF_COOKIE, "")
    token = cookie if _valid_csrf(cookie) else _csrf_token()
    request.state.csrf_token = token
    browser = bool(cookie or request.headers.get("origin") or request.headers.get("referer")
                   or any(key.startswith("sec-fetch-") for key in request.headers)
                   or "mozilla/" in request.headers.get("user-agent", "").lower())
    if request.method.upper() in _UNSAFE_METHODS and browser:
        supplied = request.headers.get("x-csrf-token", "")
        if not supplied and request.headers.get("content-type", "").startswith(
                "application/x-www-form-urlencoded"):
            body = await request.body()
            supplied = parse_qs(body.decode("utf-8", errors="replace")).get("csrf_token", [""])[0]
        if (not cookie or not _valid_csrf(cookie) or not _valid_csrf(supplied)
                or not hmac.compare_digest(cookie.encode("utf-8"), supplied.encode("utf-8"))):
            return PlainTextResponse("Token CSRF requerido", status_code=403)
    response = await call_next(request)
    # Only issue a session token to HTML pages. Headerless API clients stay stateless.
    if "text/html" in response.headers.get("content-type", ""):
        response.set_cookie(_CSRF_COOKIE, token, httponly=True, samesite="strict",
                            secure=request.url.scheme == "https" or
                            os.getenv("SCOPESCAN_PANEL_COOKIE_SECURE", "").lower() in {"1", "true", "yes"})
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _basic_auth_ok(request: Request) -> bool:
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
    if request.method.upper() not in _UNSAFE_METHODS:
        return True
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    if origin:
        return _matches_panel_origin(request, origin)
    if referer:
        return _canonical_origin(referer, referer=True) in _allowed_origins()
    return request.headers.get("sec-fetch-site", "") != "cross-site"


def _matches_panel_origin(request: Request, value: str) -> bool:
    return _host_allowed(request) and _canonical_origin(value) in _allowed_origins()


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
def dashboard(request: Request, page: int = 1, q: str = ""):
    page = max(1, page)
    scans = db.list_scans(limit=26, offset=(page - 1) * 25, search=q)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "stats": db.global_stats(),
            "scans": scans[:25],
            "page": page, "has_next": len(scans) > 25, "q": q,
            "page_query": urlencode({"q": q}),
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
            "observation": json.loads(scan["execution_context"] or "{}"),
            "hosts": db.hosts_with_ports(scan_id),
            "findings": db.get_findings(scan_id, min_severity=min_severity),
            "candidates": db.get_cve_candidates(scan_id),
            "exploitdb_results": db.get_exploitdb_results(scan_id),
            "controls": db.get_control_results(scan_id),
            "patch_statuses": db.get_windows_patch_statuses(scan_id),
            "patch_candidates": db.get_windows_patch_candidates(scan_id),
            "inventories": db.get_host_inventory_summaries(scan_id),
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
    try:
        new_id = rerun(scan_id)
    except (ValueError, InvalidTarget, KeyError) as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    QUEUE.submit(new_id)
    return RedirectResponse(f"/scans/{new_id}", status_code=303)


@app.post("/scans/{scan_id}/delete")
def delete_scan(scan_id: int):
    if any(job["status"] == "running" for job in db.get_enrichment_statuses(scan_id).values()):
        raise HTTPException(status_code=409, detail="Espera a que termine el enriquecimiento")
    try:
        QUEUE.request_delete(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
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
    path = export.spool_bundle(scan_id)
    return FileResponse(path, media_type="application/zip",
                        filename=f"scopescan-{scan_id:05d}.zip",
                        background=BackgroundTask(path.unlink, missing_ok=True))


@app.post("/api/environment/refresh")
def refresh_environment():
    probe_environment(refresh=True)
    return RedirectResponse("/", status_code=303)


@app.get("/scans/{scan_id}/inventory/{host}/{collection}", response_class=HTMLResponse)
def inventory_collection(request: Request, scan_id: int, host: str, collection: str,
                         page: int = 1, q: str = ""):
    if collection not in {"packages", "software", "updates"}:
        raise HTTPException(status_code=404, detail="Coleccion no encontrada")
    if not db.inventory_exists(scan_id, host):
        raise HTTPException(status_code=404, detail="Inventario no encontrado")
    page = max(1, page)
    items, total = db.inventory_page(scan_id, host, collection, offset=(page - 1) * 100,
                                    limit=100, search=q)
    return templates.TemplateResponse(request, "inventory.html", {
        "scan_id": scan_id, "host": host, "collection": collection, "items": items,
        "total": total, "page": page, "q": q, "has_next": page * 100 < total,
        "page_query": urlencode({"q": q}),
        "inv": db.get_host_inventory_summaries(scan_id).get(host, {}),
    })


def _submit_enrichment(scan_id: int, kind: str, func, *args) -> None:
    if db.get_scan(scan_id) is None:
        return
    from ..jobs import DurableQueue
    if isinstance(QUEUE, DurableQueue):
        try:
            QUEUE.submit_enrichment(scan_id, kind, func, *args)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return
    if not db.enrichment_claim_active(scan_id, kind):
        return
    try:
        submitted = QUEUE.submit_enrichment(scan_id, kind, func, *args)
    except (RuntimeError, ValueError) as exc:
        db.set_enrichment_status(scan_id, kind, "failed", str(exc))
        return
    if not submitted:
        db.set_enrichment_status(scan_id, kind, "failed", "Cola no disponible")


def _claim_enrichment(scan_id: int, kind: str) -> bool:
    from ..jobs import DurableQueue
    if isinstance(QUEUE, DurableQueue):
        # DurableQueue performs the claim and serialization in one transaction.
        existing = db.get_enrichment_statuses(scan_id).get(kind)
        return existing is None or existing["status"] not in {"running", "queued"}
    try:
        return db.claim_enrichment_job(scan_id, kind)
    except db.ScanUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _run_nvd(scan_id: int, include_firmware: bool) -> None:
    try:
        nvd.enrich_scan(scan_id, include_firmware=include_firmware)
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, "nvd", "failed", str(exc))
    else:
        statuses = db.get_enrichment_statuses(scan_id)
        if statuses.get("nvd") is None or statuses["nvd"]["status"] not in {"partial", "failed", "cancelled"}:
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
    if _claim_enrichment(scan_id, "nvd"):
        _submit_enrichment( scan_id, "nvd", _run_nvd, scan_id, bool(include_firmware))
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
    if _claim_enrichment(scan_id, "windows"):
        _submit_enrichment( scan_id, "windows", _run_windows_inventory, scan_id, host, bool(local))
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
    if _claim_enrichment(scan_id, "linux"):
        _submit_enrichment( scan_id, "linux", _run_linux_inventory, scan_id, host, user, port, bool(local)
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
    if _claim_enrichment(scan_id, "msrc"):
        _submit_enrichment( scan_id, "msrc", _run_msrc, scan_id)
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
    if _claim_enrichment(scan_id, exploitdb.ENRICH_KIND):
        _submit_enrichment( scan_id, exploitdb.ENRICH_KIND, _run_exploitdb, scan_id)
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
    if _claim_enrichment(scan_id, msf.ENRICH_KIND):
        _submit_enrichment( scan_id, msf.ENRICH_KIND, _run_msf_verify, scan_id)
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
        result = msf.exploit_target(scan_id, host=host, port=port, module_path=module_path)
    except Exception as exc:  # noqa: BLE001 - el error debe quedar visible tras responder
        db.set_enrichment_status(scan_id, "metasploit-exploit", "failed", str(exc))
    else:
        if result == msf_modules.ERROR:
            runs = db.get_exploit_runs(scan_id)
            run = runs[0] if runs else None
            status = "cancelled" if run is not None and run["status"] == "cancelled" else "failed"
            error = run["detail"] if run is not None else "Ejecucion incompleta; ver detalle MSF"
            db.set_enrichment_status(scan_id, "metasploit-exploit", status, error)
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

    if _claim_enrichment(scan_id, "metasploit-exploit"):
        _submit_enrichment( scan_id, "metasploit-exploit", _run_msf_exploit, scan_id, host, portid, module)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@app.get("/findings", response_class=HTMLResponse)
def findings_view(request: Request, min_severity: int = int(Severity.LOW),
                  page: int = 1, q: str = ""):
    page = max(1, page)
    findings = db.recent_findings(limit=101, min_severity=min_severity,
                                  offset=(page - 1) * 100, search=q)
    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "findings": findings[:100],
            "page": page, "has_next": len(findings) > 100, "q": q,
            "page_query": urlencode({"q": q, "min_severity": min_severity}),
            "min_severity": min_severity,
        },
    )


from .body_limit import BodyLimitMiddleware

app.add_middleware(BodyLimitMiddleware)
