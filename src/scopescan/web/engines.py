"""Optional engines panel and API, protected by shared auth/CSRF middleware."""
import secrets
import threading
import time
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import db, engine_service, engine_store
from ..engine_cli import parse_ports
from .continuity import preview_evidence

router=APIRouter()
templates=Jinja2Templates(directory=str(Path(__file__).parent/'templates'))
templates.env.globals['preview_evidence']=preview_evidence
_plans={}
_lock=threading.Lock()


def page(request, **data):
    return templates.TemplateResponse(request,'engines.html',data)


def save_preview(plan):
    with _lock:
        expired=[key for key,(deadline,_) in _plans.items() if deadline<time.monotonic()]
        for key in expired:
            del _plans[key]
        if len(_plans)>=128:
            raise ValueError('Too many pending engine previews; wait or reuse an existing preview')
        token=secrets.token_urlsafe(32)
        _plans[token]=(time.monotonic()+900,plan)
    return token


def take_preview(token):
    with _lock:
        value=_plans.pop(token,None)
    if value is None or value[0]<time.monotonic():
        raise ValueError('Preview expired or already used; preview the scope again')
    plan=value[1]
    if plan.scope.scope_id is not None:
        row=db.get_scope(plan.scope.scope_id)
        if row is None or row['authorized_by']!=plan.scope.authorized_by or any(e.host not in row['pinned_targets'] for e in plan.endpoints):
            raise ValueError('Saved scope authorization changed; preview again')
        bindings=dict(plan.scope.resolutions)
        if any(e.hostname and e.host not in row['resolutions'].get(e.hostname,[]) for e in plan.endpoints):
            raise ValueError('Operator hostname binding changed; preview again')
        if bindings!={name:tuple(addresses) for name,addresses in row['resolutions'].items() if not name.startswith('exclude:')}:
            raise ValueError('Scope resolution changed; preview again')
    return plan


@router.get('/engines')
def index(request:Request,page_number:int=1):
    offset=max(0,page_number-1)*50
    items,total=engine_store.list_results(limit=50,offset=offset)
    executions,execution_total=engine_service.executions(limit=50,offset=offset)
    scopes,_=db.list_scopes(limit=100)
    return page(request,catalog=engine_service.catalog(),items=items,total=total,executions=executions,execution_total=execution_total,scopes=scopes,page_number=page_number)


@router.post('/engines/preview')
def preview(request:Request,engine:str=Form(...),scope_id:int=Form(...),ports:str=Form(''),timeout:float=Form(120),service:str=Form('')):
    try:
        plan=engine_service.preview(engine,scope_id,ports=parse_ports(ports),timeout=timeout,service=service)
        return page(request,plan=asdict(plan),plan_token=save_preview(plan),fingerprint=plan.fingerprint)
    except (ValueError,OSError) as exc:
        raise HTTPException(400,str(exc)) from exc


@router.post('/engines/run')
def run(preview_token:str=Form(...)):
    try:
        plan=take_preview(preview_token)
        available,message=engine_service.adapter(plan.engine).available()
        if not available:
            raise ValueError(message)
        scan_id=engine_service.create_execution(plan)
        from ..jobs import QUEUE

        QUEUE.submit(scan_id)
        return RedirectResponse(f'/scans/{scan_id}',303)
    except (ValueError,OSError) as exc:
        raise HTTPException(400,str(exc)) from exc


@router.get('/engines/results/{result_id}')
def detail(request:Request,result_id:int):
    try:
        result=engine_store.get_result(result_id)
    except ValueError as exc:
        raise HTTPException(404,str(exc)) from exc
    return page(request,result=result)


@router.get('/api/engines')
def catalog_api():
    return engine_service.catalog()


@router.get('/api/engines/results')
def results_api(scan_id:int|None=None,limit:int=50,offset:int=0):
    items,total=engine_store.list_results(scan_id=scan_id,limit=limit,offset=offset)
    return {'items':items,'total':total}


@router.get('/api/engines/results/{result_id}')
def result_api(result_id:int):
    try:
        return engine_store.get_result(result_id)
    except ValueError as exc:
        raise HTTPException(404,str(exc)) from exc


@router.get('/api/engines/results/{result_id}/raw')
def raw_api(result_id:int):
    try:
        return engine_store.get_result(result_id,include_raw=True)
    except ValueError as exc:
        raise HTTPException(404,str(exc)) from exc


@router.post('/engines/import/{kind}')
async def import_upload(request:Request,kind:str,scope_id:int,host:str,inventory_scan_id:int|None=None):
    payload=bytearray()
    async for chunk in request.stream():
        payload.extend(chunk)
        if len(payload)>8_000_000:
            raise HTTPException(413,'Import exceeds 8 MB')
    try:
        scan_id=engine_service.import_evidence(kind,bytes(payload),scope_id=scope_id,host=host,inventory_scan_id=inventory_scan_id)
    except (ValueError,OSError) as exc:
        raise HTTPException(400,str(exc)) from exc
    return {'scan_id':scan_id}
