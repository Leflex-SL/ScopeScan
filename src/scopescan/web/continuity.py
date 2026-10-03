"""Continuous assessment routes; all mutations use the panel security middleware."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import db
from ..config import MAX_HOSTS_DEFAULT
from ..profiles import DEFAULT_PROFILE, PROFILES

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["max_hosts_default"] = MAX_HOSTS_DEFAULT
MAX_IMPORT_BYTES = 8_000_000


def preview_evidence(value, depth: int = 0):
    """Bound embedded evidence; full observation JSON is fetched on demand."""
    if depth >= 8:
        return "[Vista previa: profundidad limitada]"
    if isinstance(value, dict):
        result = {key: preview_evidence(item, depth + 1)
                  for key, item in list(value.items())[:30]}
        if len(value) > 30:
            result["vista_previa"] = f"{len(value) - 30} campos adicionales"
        return result
    if isinstance(value, (list, tuple)):
        items = [preview_evidence(item, depth + 1) for item in value[:20]]
        if len(value) > 20:
            items.append(f"[Vista previa: {len(value) - 20} elementos adicionales]")
        return items
    if isinstance(value, str) and len(value) > 4000:
        return value[:4000] + f" [Vista previa: {len(value) - 4000} caracteres adicionales]"
    return value


templates.env.globals["preview_evidence"] = preview_evidence


def page(request: Request, view: str, *, error: str = "", code: int = 200, **data):
    return templates.TemplateResponse(request, "continuous.html",
                                      {"view": view, "error": error, **data}, status_code=code)


def _error(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _optional_scope(value: str | None) -> int | None:
    try:
        return int(value) if value else None
    except ValueError as exc:
        raise HTTPException(400, "ID de alcance debe ser numerico") from exc


def _scope_signature(scope: dict, stamp: str) -> str:
    from .app import _CSRF_SECRET
    payload = json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(_CSRF_SECRET, stamp.encode() + b":" + payload, hashlib.sha256).hexdigest()


def _scope_preview_token(scope: dict) -> str:
    stamp = str(int(time.time()))
    return stamp + "." + _scope_signature(scope, stamp)


@router.get("/assets", response_class=HTMLResponse)
def assets(request: Request, q: str = "", scope_id: str | None = None, page_number: int = 1):
    scope_id = _optional_scope(scope_id)
    page_number = max(1, page_number)
    items, total = db.list_assets(search=q, scope_id=scope_id, limit=50,
                                 offset=(page_number - 1) * 50)
    return page(request, "assets", items=items, total=total, q=q, scope_id=scope_id,
                page_number=page_number, query=urlencode({"q": q, **(
                    {"scope_id": scope_id} if scope_id is not None else {})}),
                summary=db.current_summary())


@router.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_detail(request: Request, asset_id: str, history_page: int = 1):
    item = db.get_asset(asset_id)
    if item is None:
        raise HTTPException(404, "Activo inexistente")
    findings, total = db.list_current_findings(asset_id=asset_id, limit=100)
    history_page = max(1, history_page)
    observations, observation_total = db.list_asset_observations(
        asset_id, limit=25, offset=(history_page - 1) * 25, summaries=True)
    return page(request, "asset", item=item, findings=findings, total=total,
                observations=observations, observation_total=observation_total,
                history_page=history_page)


@router.post("/assets/{asset_id}/metadata")
def asset_metadata(request: Request, asset_id: str, criticality: int = Form(...),
                   alias: str = Form(""), actor: str = Form("web")):
    if db.get_asset(asset_id) is None:
        raise HTTPException(404, "Activo inexistente")
    try:
        db.update_asset_metadata(asset_id, criticality=criticality, alias=alias.strip(), actor=actor)
    except (ValueError, KeyError) as exc:
        item = db.get_asset(asset_id)
        findings, total = db.list_current_findings(asset_id=asset_id, limit=100)
        observations, observation_total = db.list_asset_observations(asset_id, limit=25, summaries=True)
        return page(request, "asset", item=item, findings=findings, total=total,
                    observations=observations,
                    observation_total=observation_total, history_page=1,
                    error=str(exc), code=400)
    return RedirectResponse(f"/assets/{asset_id}", status_code=303)


@router.get("/current-findings", response_class=HTMLResponse)
def current_findings(request: Request, q: str = "", status: str | None = None,
                     scope_id: str | None = None, asset_id: str | None = None,
                     page_number: int = 1, min_severity: int = 0,
                     assessment: str = "", lifecycle: str = ""):
    scope_id = _optional_scope(scope_id)
    page_number = max(1, page_number)
    items, total = db.list_current_findings(search=q, status=status or None, scope_id=scope_id,
                                          asset_id=asset_id, limit=50,
                                          min_severity=min_severity, assessment=assessment or None,
                                          lifecycle=lifecycle or None,
                                          offset=(page_number - 1) * 50)
    filters = {key: value for key, value in {"q": q, "status": status,
               "scope_id": scope_id, "asset_id": asset_id, "min_severity": min_severity,
               "assessment": assessment, "lifecycle": lifecycle}.items() if value is not None}
    return page(request, "findings", items=items, total=total, q=q, status=status,
                scope_id=scope_id, asset_id=asset_id, page_number=page_number,
                min_severity=min_severity, assessment=assessment, lifecycle=lifecycle,
                query=urlencode(filters))


@router.get("/remediation/{finding_id}", response_class=HTMLResponse)
def remediation(request: Request, finding_id: str):
    item = db.get_current_finding(finding_id)
    if item is None:
        raise HTTPException(404, "Hallazgo inexistente")
    return page(request, "remediation", item=item, history=db.remediation_history(finding_id))


@router.post("/remediation/{finding_id}")
def remediation_update(request: Request, finding_id: str, actor: str = Form("web"),
                       owner: str = Form(""), status: str = Form("open"),
                       due_at: str = Form(""), exception_until: str = Form(""),
                       evidence: str = Form(""), verification_scan_id: str = Form("")):
    if db.get_current_finding(finding_id) is None:
        raise HTTPException(404, "Hallazgo inexistente")
    try:
        db.update_remediation(finding_id, actor=actor, owner=owner, status=status,
                              due_at=due_at, exception_until=exception_until,
                              evidence=evidence or None,
                              verification_scan_id=(int(verification_scan_id)
                                                    if verification_scan_id else None))
    except (ValueError, KeyError) as exc:
        return page(request, "remediation", item=db.get_current_finding(finding_id),
                    history=db.remediation_history(finding_id), error=str(exc), code=400)
    return RedirectResponse(f"/remediation/{finding_id}", status_code=303)


@router.get("/scans/{scan_id}/delta", response_class=HTMLResponse)
def delta(request: Request, scan_id: int):
    if db.get_scan(scan_id) is None:
        raise HTTPException(404, "Escaneo inexistente")
    return page(request, "delta", scan_id=scan_id, delta=db.scan_delta(scan_id))


@router.get("/scopes", response_class=HTMLResponse)
def scopes_view(request: Request, q: str = "", page_number: int = 1):
    from .. import scopes
    page_number = max(1, page_number)
    items, total = scopes.list_scopes(search=q, limit=50, offset=(page_number - 1) * 50)
    return page(request, "scopes", items=items, total=total, profiles=PROFILES,
                default_profile=DEFAULT_PROFILE, item=None, q=q,
                page_number=page_number, query=urlencode({"q": q}))


@router.get("/scopes/{scope_id}", response_class=HTMLResponse)
def scope_detail(request: Request, scope_id: int):
    from .. import scopes
    try:
        item = scopes.get_scope(scope_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return page(request, "scope", item=item, profiles=PROFILES, default_profile=DEFAULT_PROFILE)


@router.post("/scopes")
def scope_save(request: Request, name: str = Form(...), targets: str = Form(...),
               exclusions: str = Form(""), profile: str = Form(DEFAULT_PROFILE),
               authorized_by: str = Form(...), notes: str = Form(""),
               scope_id: str = Form(""), max_hosts: int = Form(MAX_HOSTS_DEFAULT)):
    from .. import scopes
    values = {"name": name, "targets": targets, "exclusions": exclusions, "profile": profile,
              "authorized_by": authorized_by, "notes": notes, "max_hosts": max_hosts}
    try:
        if scope_id:
            result = int(scope_id)
            scopes.update_scope(result, **values)
        else:
            result = scopes.create_scope(**values)
    except (ValueError, KeyError) as exc:
        return page(request, "scope", item={**values, "id": scope_id}, profiles=PROFILES,
                    default_profile=DEFAULT_PROFILE, error=str(exc), code=400)
    return RedirectResponse(f"/scopes/{result}", status_code=303)


@router.post("/scopes/{scope_id}/preview", response_class=HTMLResponse)
def scope_preview(request: Request, scope_id: int):
    from .. import scopes
    try:
        item = scopes.get_scope(scope_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    try:
        prepared = scopes.preview_scope(scope_id)
        if item != scopes.get_scope(scope_id):
            raise ValueError("El alcance cambio durante el preview; vuelve a previsualizar")
    except (ValueError, KeyError, RuntimeError) as exc:
        return page(request, "scope", item=item, profiles=PROFILES,
                    default_profile=DEFAULT_PROFILE, error=str(exc), code=400)
    return page(request, "scope", item=item, profiles=PROFILES,
                default_profile=DEFAULT_PROFILE, prepared=prepared,
                preview_token=_scope_preview_token(item))


@router.post("/scopes/{scope_id}/queue")
def scope_queue(scope_id: int, preview_token: str = Form("")):
    from .. import scopes
    from .app import QUEUE
    try:
        item = scopes.get_scope(scope_id)
        if len(preview_token) != 75 or re.fullmatch(r"[0-9]{10}\.[0-9a-f]{64}", preview_token) is None:
            raise ValueError("Token de preview invalido; previsualiza de nuevo")
        stamp, _, signature = preview_token.partition(".")
        if (not 0 <= time.time() - int(stamp) <= 900
                or not hmac.compare_digest(signature, _scope_signature(item, stamp))):
            raise ValueError("Previsualiza de nuevo: el alcance cambio o el preview caduco")
        prepared = scopes.preview_scope(scope_id)
        if item != scopes.get_scope(scope_id):
            raise ValueError("El alcance cambio durante la confirmacion; revisa el preview")
        scan_id = scopes.queue_scope(scope_id, prepared=prepared)
        try:
            QUEUE.submit(scan_id)
        except RuntimeError as exc:
            db.set_status(scan_id, "failed", error=f"No se pudo encolar: {exc}")
            raise ValueError(f"Escaneo #{scan_id} no encolado; revisa su error y vuelve a intentar") from exc
    except (ValueError, KeyError, RuntimeError) as exc:
        raise _error(exc) from exc
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@router.get("/verification", response_class=HTMLResponse)
def verification_form(request: Request, finding_id: str = ""):
    return page(request, "verification", finding_ids=finding_id)


@router.post("/verification", response_class=HTMLResponse)
def verification_action(request: Request, finding_ids: str = Form(...),
                        authorized_by: str = Form(...), action: str = Form("preview")):
    from .. import verification
    from .app import QUEUE
    try:
        plan = verification.plan_verification(finding_ids.split(), authorized_by=authorized_by,
                                              defer_identity=True)
        scan_ids = []
        failures = []
        if action == "queue":
            scan_ids = verification.queue_verification(plan)
            for scan_id in scan_ids:
                try:
                    QUEUE.submit(scan_id)
                except RuntimeError as exc:
                    db.set_status(scan_id, "failed", error=f"No se pudo encolar: {exc}")
                    failures.append(f"Escaneo #{scan_id} no encolado: {exc}")
        return page(request, "verification", finding_ids=finding_ids, plan=plan,
                    scan_ids=scan_ids, authorized_by=authorized_by,
                    error="; ".join(failures), code=400 if failures else 200)
    except (ValueError, KeyError, RuntimeError) as exc:
        return page(request, "verification", finding_ids=finding_ids,
                    authorized_by=authorized_by, error=str(exc), code=400)


@router.get("/imports", response_class=HTMLResponse)
def imports_form(request: Request):
    return page(request, "imports", max_bytes=MAX_IMPORT_BYTES)


@router.post("/api/imports/{kind}")
async def import_upload(request: Request, kind: str, name: str = "", namespace: str = "",
                        authorized_by: str = ""):
    from .. import importers
    if kind not in {"nmap", "external"}:
        raise HTTPException(400, "Formato permitido: nmap o external")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_IMPORT_BYTES:
            raise HTTPException(413, f"El fichero supera {MAX_IMPORT_BYTES} bytes")
    if not body:
        raise HTTPException(400, "Selecciona un fichero con resultados")
    try:
        with tempfile.TemporaryDirectory(prefix="scopescan-import-") as directory:
            path = Path(directory) / ("input.xml" if kind == "nmap" else "input.json")
            path.write_bytes(body)
            importer = importers.import_nmap if kind == "nmap" else importers.import_external_json
            scan_id = importer(path, name=name, namespace=namespace, authorized_by=authorized_by)
    except (ValueError, KeyError, OSError) as exc:
        raise _error(exc) from exc
    return {"scan_id": scan_id, "url": f"/scans/{scan_id}", "status": "imported"}


@router.get("/api/assets")
def assets_api(q: str = "", scope_id: int | None = None, limit: int = 50, offset: int = 0):
    items, total = db.list_assets(search=q, scope_id=scope_id, limit=min(max(1, limit), 100),
                                 offset=max(0, offset))
    return {"items": items, "total": total}


@router.get("/api/assets/{asset_id}/observations")
def observation_api(asset_id: str, offset: int = 0):
    if db.get_asset(asset_id) is None:
        raise HTTPException(404, "Activo inexistente")
    items, total = db.list_asset_observations(asset_id, limit=1, offset=max(0, offset))
    return {"items": items, "total": total, "offset": max(0, offset)}


@router.get("/api/assets/{asset_id}")
def asset_api(asset_id: str):
    item = db.get_asset(asset_id)
    if item is None:
        raise HTTPException(404, "Activo inexistente")
    return item


@router.get("/api/assets/{asset_id}/risk-factors")
def risk_factors_api(asset_id: str, limit: int = 100, offset: int = 0):
    items, total = db.list_asset_risk_factors(asset_id, limit=limit, offset=offset)
    return {"items": items, "total": total, "offset": max(0, offset)}


@router.get("/api/assets/{asset_id}/ports")
def asset_ports_api(asset_id: str, limit: int = 100, offset: int = 0):
    items, total = db.list_asset_ports(asset_id, limit=limit, offset=offset)
    return {"items": items, "total": total, "offset": max(0, offset)}


@router.get("/api/current-findings")
def findings_api(q: str = "", status: str | None = None, asset_id: str | None = None,
                 scope_id: int | None = None, limit: int = 50, offset: int = 0,
                 min_severity: int = 0, assessment: str = "", lifecycle: str = ""):
    items, total = db.list_current_findings(search=q, status=status, asset_id=asset_id,
                                          scope_id=scope_id, limit=min(max(1, limit), 100),
                                          min_severity=min_severity, assessment=assessment or None,
                                          lifecycle=lifecycle or None,
                                          offset=max(0, offset))
    return {"items": items, "total": total}


@router.get("/api/scans/{scan_id}/delta")
def delta_api(scan_id: int):
    if db.get_scan(scan_id) is None:
        raise HTTPException(404, "Escaneo inexistente")
    return db.scan_delta(scan_id)
