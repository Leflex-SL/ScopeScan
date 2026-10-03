"""Connector UI/API under the shared authorization and CSRF middleware."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .. import defectdojo, integrations_service, integrations_store

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/integrations")
def index(request: Request, page_number: int = 1):
    offset = max(0, page_number - 1) * 50
    destinations, destination_total = integrations_store.page("integration_destinations", offset=offset)
    imports, import_total = integrations_store.page("integration_imports", offset=offset)
    deliveries, delivery_total = integrations_store.page("integration_deliveries", offset=offset)
    return templates.TemplateResponse(request, "integrations.html", {"destinations": destinations, "destination_total": destination_total, "imports": imports,
        "import_total": import_total, "deliveries": deliveries, "delivery_total": delivery_total, "page_number": page_number})


@router.post("/integrations/destinations")
def add(name: str = Form(...), kind: str = Form(...), url: str = Form(...), options: str = Form(...)):
    try:
        settings = json.loads(options)
    except (ValueError, RecursionError) as exc:
        raise HTTPException(400, "Options must be JSON with environment references") from exc
    _call(integrations_store.create_destination, name, kind, url, settings)
    return RedirectResponse("/integrations", 303)


@router.post("/integrations/deliver")
def deliver(destination_id: int = Form(...), scan_id: int = Form(...), engagement_id: str = Form(""), test_id: str = Form("")):
    try:
        engagement, test = int(engagement_id) if engagement_id else None, int(test_id) if test_id else None
    except ValueError as exc:
        raise HTTPException(400, "Engagement/test IDs must be integers") from exc
    value = _call(integrations_service.enqueue_delivery, destination_id, scan_id, engagement_id=engagement, test_id=test)
    return RedirectResponse(f"/jobs/{value['job_id']}", 303)


@router.post("/integrations/pull")
def pull(destination_id: int = Form(...), scope_id: int = Form(...), report_id: str = Form("")):
    value = _call(integrations_service.enqueue_pull, destination_id, scope_id, report_id=report_id)
    return RedirectResponse(f"/jobs/{value['job_id']}", 303)


@router.post("/integrations/poll")
def poll(delivery_id: int = Form(...), remote_test_id: str = Form("")):
    try:
        remote = int(remote_test_id) if remote_test_id else None
    except ValueError as exc:
        raise HTTPException(400, "Remote test ID must be an integer") from exc
    value = _call(integrations_service.enqueue_poll, delivery_id, remote_test_id=remote)
    return RedirectResponse(f"/jobs/{value['job_id']}", 303)


@router.post("/integrations/import")
async def import_form(file: UploadFile, kind: str = Form(...), scope_id: int = Form(...)):
    payload = await file.read(8_000_001)
    if len(payload) > 8_000_000:
        raise HTTPException(413, "Evidence exceeds 8 MB")
    value = _call(integrations_service.import_evidence, kind, payload, scope_id=scope_id)
    return RedirectResponse(f"/integrations/imports/{value['import_id']}", 303)


@router.post("/api/integrations/import/{kind}")
async def import_api(request: Request, kind: str, scope_id: int):
    payload = bytearray()
    async for chunk in request.stream():
        payload.extend(chunk)
        if len(payload) > 8_000_000:
            raise HTTPException(413, "Evidence exceeds 8 MB")
    return _call(integrations_service.import_evidence, kind, bytes(payload), scope_id=scope_id)


@router.get("/integrations/imports/{import_id}")
def import_detail(request: Request, import_id: int):
    value = _call(integrations_store.get_import, import_id)
    return templates.TemplateResponse(request, "integrations.html", {"result": value})


@router.get("/api/integrations/{collection}")
def listing(collection: str, limit: int = 50, offset: int = 0):
    if collection not in {"destinations", "imports", "deliveries"}:
        raise HTTPException(404, "Unknown integration collection")
    items, total = _call(integrations_store.page, "integration_" + collection, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/api/integrations/imports/{import_id}")
def import_result(import_id: int):
    return _call(integrations_store.get_import, import_id)


@router.get("/api/integrations/imports/{import_id}/raw")
def import_raw(import_id: int):
    return _call(integrations_store.get_import, import_id, include_raw=True)


@router.get("/api/integrations/deliveries/{delivery_id}")
def delivery_result(delivery_id: int):
    return _call(integrations_store.get_delivery, delivery_id)


@router.get("/integrations/deliveries/{delivery_id}")
def delivery_detail(request: Request, delivery_id: int, page_number: int = 1):
    value = _call(integrations_store.get_delivery, delivery_id)
    history, total = _call(integrations_store.delivery_history, delivery_id, offset=max(0, page_number - 1) * 50)
    return templates.TemplateResponse(request, "integrations.html", {"delivery": value, "history": history, "history_total": total, "page_number": page_number})


@router.get("/api/integrations/deliveries/{delivery_id}/history")
def delivery_events(delivery_id: int, limit: int = 50, offset: int = 0):
    items, total = _call(integrations_store.delivery_history, delivery_id, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/api/integrations/deliveries/{delivery_id}/raw")
def delivery_raw(delivery_id: int):
    value = _call(integrations_store.get_delivery, delivery_id, include_payload=True)
    return Response(value["payload"], media_type="application/json", headers={"Content-Disposition": f'attachment; filename="scopescan-delivery-{delivery_id}.json"'})


@router.get("/integrations/export/defectdojo/{scan_id}")
def export_report(scan_id: int):
    return Response(_call(defectdojo.generic_findings, scan_id), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="scopescan-{scan_id}-defectdojo.json"'})
