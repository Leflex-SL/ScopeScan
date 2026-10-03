"""Queue and schedule UI. HTTP handlers never run operation workers."""
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import durable_jobs, scheduler

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/jobs")
def jobs_page(request: Request, limit: int = 100, offset: int = 0):
    try:
        rows = durable_jobs.list_jobs(limit=limit, offset=offset)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return templates.TemplateResponse(request=request, name="jobs.html", context={"jobs": rows, "schedules": scheduler.list_schedules(), "events":scheduler.events(), "offset": offset, "limit": limit})


@router.get("/api/jobs")
def jobs_api(limit: int = 100, offset: int = 0):
    try:
        return {"jobs": durable_jobs.list_jobs(limit=limit, offset=offset)}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/jobs/{job_id}")
def job_detail(request: Request, job_id: int):
    row = durable_jobs.get(job_id)
    if row is None:
        raise HTTPException(404, "Job not found")
    row.pop("owner", None)
    return templates.TemplateResponse(request=request, name="job_detail.html", context={"job":row})


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int):
    durable_jobs.cancel(job_id)
    return RedirectResponse("/jobs", 303)


@router.post("/jobs/{job_id}/retry")
def retry_job(job_id: int, acknowledge_uncertain: str = Form("")):
    try:
        durable_jobs.retry(job_id, acknowledge_uncertain=bool(acknowledge_uncertain))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return RedirectResponse("/jobs", 303)


@router.post("/schedules")
def create_schedule(scope_id: int = Form(...), name: str = Form("Scheduled assessment"),
                    starts_at: str = Form(...), interval: int = Form(86400),
                    ends_at: str = Form(""), window_start: str = Form("00:00"),
                    window_end: str = Form("00:00"), max_running: int = Form(1)):
    try:
        scheduler.create(name=name, scope_id=scope_id, starts_at=starts_at, ends_at=ends_at or None,
                         interval_seconds=interval, window_start=window_start, window_end=window_end,
                         max_running=max_running)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse("/jobs", 303)


@router.post("/schedules/{schedule_id}/{action}")
def toggle_schedule(schedule_id: int, action: str):
    if action not in {"enable", "disable"}:
        raise HTTPException(400, "Use enable or disable")
    try:
        scheduler.set_enabled(schedule_id, action == "enable")
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return RedirectResponse("/jobs", 303)
