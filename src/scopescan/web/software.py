"""Software/SCAP upload, immutable evidence pagination and durable operation UI."""
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .. import software_service, software_store
from ..sbom import MAX_BYTES

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/software")
def index(request: Request, search: str = "", page: int = 1, resource_id: str | None = None):
    try:
        items, total = software_store.page("documents", search=search, resource_id=resource_id, offset=max(0, page - 1) * 50)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return templates.TemplateResponse(request, "software.html", {"items": items, "total": total, "page": page, "search": search, "resource_id": resource_id})


@router.get("/software/{document_id}")
def detail(request: Request, document_id: int, page: int = 1):
    value = software_store.get(document_id)
    if value is None:
        raise HTTPException(404, "Evidence not found")
    components, count = software_store.page("components", document_id=document_id, offset=max(0, page - 1) * 50)
    observations, observation_count = software_store.page("observations", document_id=document_id, offset=max(0, page - 1) * 50)
    return templates.TemplateResponse(request, "software.html", {"document": value, "components": components, "observations": observations, "count": count, "observation_count": observation_count, "page": page})


@router.post("/api/software/import/{kind}")
async def import_document(request: Request, kind: str, namespace: str, resource: str, resource_kind: str = "software"):
    payload = bytearray()
    async for chunk in request.stream():
        payload.extend(chunk)
        if len(payload) > MAX_BYTES:
            raise HTTPException(413, "Evidence exceeds 8 MB")
    try:
        document_id = software_service.import_evidence(kind, bytes(payload), namespace=namespace, resource_kind=resource_kind, resource_name=resource)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"document_id": document_id}


@router.get("/api/software/documents")
def documents(search: str = "", resource_id: str | None = None, limit: int = 50, offset: int = 0):
    try:
        items, total = software_store.page("documents", resource_id=resource_id, search=search, limit=limit, offset=offset)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"items": items, "total": total}


@router.get("/api/software/{document_id}")
def document(document_id: int):
    value = software_store.get(document_id)
    if value is None:
        raise HTTPException(404, "Evidence not found")
    return value


@router.get("/api/software/{document_id}/raw")
def raw(document_id: int):
    value = software_store.get(document_id, raw=True)
    if value is None:
        raise HTTPException(404, "Evidence not found")
    return Response(value["raw"], media_type="application/xml" if value["kind"] == "scap" else "application/json", headers={"Content-Disposition": f'attachment; filename="software-{document_id}.evidence"'})


@router.get("/api/software/{document_id}/export/{kind}")
def export(document_id: int, kind: str):
    try:
        return Response(software_service.export_document(document_id, kind), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="software-{document_id}-{kind}.json"'})
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/api/software/{document_id}/{collection}")
def collection(document_id: int, collection: str, limit: int = 50, offset: int = 0, search: str = ""):
    if collection not in {"components", "observations"}:
        raise HTTPException(404, "Collection not found")
    try:
        items, total = software_store.page(collection, document_id=document_id, limit=limit, offset=offset, search=search)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"items": items, "total": total}


@router.post("/software/queue")
def queue(engine: str = Form(...), namespace: str = Form(...), resource: str = Form(...), resource_kind: str = Form("software"),
          authorized_by: str = Form(...), source: str = Form(""), document_id: int | None = Form(None),
          allow_registry: bool = Form(False), timeout: float = Form(120), reviewed: bool = Form(False)):
    if not reviewed:
        raise HTTPException(400, "Review the explicit source and authorization before queueing")
    try:
        job_id = software_service.enqueue("software." + engine, {"namespace": namespace, "resource_name": resource,
                                             "resource_kind": resource_kind, "source": source, "document_id": document_id,
                                             "allow_registry": allow_registry, "timeout": timeout}, authorized_by=authorized_by)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(f"/jobs/{job_id}", 303)
