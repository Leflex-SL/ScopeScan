"""Separate worker process; the web process only persists operation requests."""
from __future__ import annotations

import importlib
import json
import threading
import time

from . import db, durable_jobs

HANDLERS = {}


def register_handler(kind, handler):
    HANDLERS[kind] = handler


class PersistentCancel:
    def __init__(self, job_id, owner):
        self.job_id, self.owner = job_id, owner
        self.local = threading.Event()

    def is_set(self):
        if self.local.is_set():
            return True
        token = durable_jobs.ownership.set(None)
        try:
            return bool(durable_jobs.cancelled(self.job_id, self.owner))
        finally:
            durable_jobs.ownership.reset(token)

    def set(self):
        self.local.set()

    def wait(self, timeout=None):
        end = time.monotonic() + timeout if timeout is not None else None
        while not self.is_set():
            if end is not None and time.monotonic() >= end:
                return False
            self.local.wait(min(.1, max(0, end - time.monotonic())) if end else .1)
        return True


class JobContext:
    def __init__(self, row):
        self.job_id, self.owner = row["id"], row["owner"]
        self.cancel = PersistentCancel(self.job_id, self.owner)

    def check_cancelled(self):
        if self.cancel.is_set():
            raise durable_jobs.JobLost("Job cancellation or lease loss")


def _scan(payload, context):
    from . import service
    context.check_cancelled()
    if payload.get("schedule_id"):
        from .scheduler import validate_schedule
        validate_schedule(payload["schedule_id"])
    service.execute(payload["scan_id"], cancel=context.cancel)
    row = db.get_scan(payload["scan_id"])
    status = row["status"] if row else "cancelled"
    if row and json.loads(row["execution_context"] or "{}").get("engine_plan"):
        with db.connect() as conn:
            evidence = conn.execute("SELECT status FROM engine_results WHERE scan_id=? ORDER BY id DESC LIMIT 1", (payload["scan_id"],)).fetchone()
        if evidence and evidence[0] == "partial" and status != "cancelled":
            status = "partial"
    return {"status": status, "scan_id": payload["scan_id"], "error": row["error"] if row else "Deleted"}


def _enrich(payload, context):
    from . import exploitdb, linux_inventory, msf, msrc, nvd, windows_inventory
    scan_id, kind = payload["scan_id"], payload["kind"]
    options = payload.get("options", {})
    context.check_cancelled()
    from .operation_grants import validate
    def revalidate():
        context.check_cancelled()
        validate(scan_id,kind,options,payload.get("grant"))
    revalidate()
    db.set_enrichment_status(scan_id, kind, "running")
    if kind == "nvd":
        count = nvd.enrich_scan(scan_id, client=nvd.NvdClient(cancel=context.cancel), **options)
    elif kind == "linux":
        count = linux_inventory.inventory_scan(scan_id, cancel=context.cancel, before_target=revalidate, **options)
    elif kind == "windows":
        count = windows_inventory.inventory_scan(scan_id, cancel=context.cancel, before_target=revalidate, **options)
    elif kind == "msrc":
        count = msrc.assess_scan(scan_id, cancel=context.cancel, **options)
    elif kind == exploitdb.ENRICH_KIND:
        count = exploitdb.enrich_scan(scan_id, cancel=context.cancel)
    elif kind == msf.ENRICH_KIND:
        count = msf.verify_scan(scan_id, cancel=context.cancel, before_target=revalidate, **options)
    elif kind == "metasploit-exploit":
        count = msf.exploit_target(scan_id, cancel=context.cancel, before_target=revalidate, **options)
        from . import msf_modules
        if count == msf_modules.ERROR:
            runs = db.get_exploit_runs(scan_id)
            latest = runs[0] if runs else None
            return {"status": "cancelled" if latest and latest["status"] == "cancelled" else "failed",
                    "error": latest["detail"] if latest else "Metasploit execution incomplete"}
    else:
        raise ValueError("Unsupported enrichment operation")
    context.check_cancelled()
    existing = db.get_enrichment_statuses(scan_id).get(kind)
    status = existing["status"] if existing and existing["status"] in {"partial", "failed", "cancelled"} else "done"
    db.set_enrichment_status(scan_id, kind, status)
    return {"status": status, "count": count}


def register_builtin_handlers():
    register_handler("scan", _scan)
    register_handler("enrichment", _enrich)
    for name in ("software_service", "integrations_service"):
        try:
            module = importlib.import_module(f"scopescan.{name}")
        except ModuleNotFoundError as exc:
            if exc.name != f"scopescan.{name}":
                raise
        else:
            module.register_jobs()


def run_once(*, job_id=None, lease_seconds=30):
    register_builtin_handlers()
    row = durable_jobs.claim(job_id=job_id, lease_seconds=lease_seconds)
    if row is None:
        return None
    context, stop = JobContext(row), threading.Event()
    def renew():
        while not stop.wait(lease_seconds / 3):
            try:
                if not durable_jobs.heartbeat(row["id"], row["owner"], lease_seconds=lease_seconds):
                    context.cancel.set()
                    return
            except Exception:  # noqa: BLE001 - a heartbeat failure must stop the operation
                context.cancel.set()
                return
    thread = threading.Thread(target=renew, daemon=True)
    thread.start()
    token = durable_jobs.ownership.set((row["id"], row["owner"]))
    status, result, error = "done", {}, ""
    try:
        handler = HANDLERS.get(row["kind"])
        if handler is None:
            raise ValueError(f"No handler registered for {row['kind']}")
        result = handler(json.loads(row["payload"]), context) or {}
        context.check_cancelled()
        status = result.get("status", "done") if isinstance(result, dict) else "done"
        if status not in durable_jobs.TERMINAL:
            status = "partial"
        if isinstance(result, dict):
            error = str(result.get("error", ""))
    except durable_jobs.JobLost as exc:
        status, error = "cancelled", str(exc)
    except Exception as exc:  # noqa: BLE001 - persisted jobs must record handler failures
        status, error = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        durable_jobs.ownership.reset(token)
        stop.set()
        thread.join(timeout=2)
    durable_jobs.finish(row["id"], row["owner"], status, result=result if isinstance(result, dict) else {}, error=error)
    return durable_jobs.get(row["id"])


def run_forever(*, stop=None, poll_seconds=1):
    from .scheduler import tick
    stop = stop or threading.Event()
    while not stop.is_set():
        tick()
        if run_once() is None:
            stop.wait(poll_seconds)


def execute_now(job_id):
    row = run_once(job_id=job_id)
    if row is None:
        row = durable_jobs.get(job_id)
    if row is None or row["status"] not in {"done", "partial"}:
        message = (row["error"] or f"Job #{job_id} is {row['status']}; start scopescan worker or wait for worker capacity") if row else f"Job #{job_id} is unavailable"
        raise ValueError(message)
    return json.loads(row["result"])
