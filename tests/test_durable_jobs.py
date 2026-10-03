"""Cross-process queue contracts and real process cancellation, no target traffic."""
import json
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from scopescan import db, jobs, scheduler, worker
from scopescan import durable_jobs as queue


def scan():
    return db.create_scan(name="fixture", targets="127.0.0.1", profile="rapido", authorized_by="test")


def expire(job_id):
    with db.connect() as conn:
        conn.execute("UPDATE durable_jobs SET lease_until=? WHERE id=?", (time.time() - 1, job_id))


def test_cross_process_workers_only_one_claim(tmp_path):
    job_id = queue.enqueue("test.fixture", {})
    code = "from scopescan.durable_jobs import claim; import json; r=claim(); print(json.dumps(r['id'] if r else None))"
    first = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    second = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    answers = [json.loads(proc.communicate(timeout=30)[0]) for proc in (first, second)]
    assert answers.count(job_id) == 1 and answers.count(None) == 1


def test_restart_preserves_pending_operation():
    job_id = queue.enqueue("test.fixture", {"value": 4})
    db.init_db()
    assert queue.get(job_id)["status"] == "queued"
    worker.register_handler("test.fixture", lambda payload, context: {"value": payload["value"]})
    assert worker.run_once(job_id=job_id)["status"] == "done"
    assert json.loads(queue.get(job_id)["result"]) == {"value": 4}


def test_stale_owner_cannot_write_after_recovery():
    scan_id = scan()
    job_id = queue.enqueue("test.fixture", {}, scan_id=scan_id)
    old = queue.claim(job_id=job_id)
    expire(job_id)
    new = queue.claim(job_id=job_id)
    assert new["owner"] != old["owner"]
    token = queue.ownership.set((job_id, old["owner"]))
    try:
        with pytest.raises(queue.JobLost):
            db.set_progress(scan_id, 99, "stale")
    finally:
        queue.ownership.reset(token)
    assert not queue.finish(job_id, old["owner"], "done")
    assert db.get_scan(scan_id)["progress"] == 0


def test_heartbeat_requires_current_unexpired_owner():
    job_id = queue.enqueue("test.fixture", {})
    row = queue.claim(job_id=job_id)
    assert not queue.heartbeat(job_id, "wrong")
    assert queue.heartbeat(job_id, row["owner"])
    expire(job_id)
    assert not queue.heartbeat(job_id, row["owner"])


def test_unsafe_expired_external_write_requires_review():
    job_id = queue.enqueue("test.write", {}, retry_safe=False)
    queue.claim(job_id=job_id)
    expire(job_id)
    assert queue.claim(job_id=job_id) is None
    assert queue.get(job_id)["status"] == "failed"
    with pytest.raises(ValueError, match="reconciliation"):
        queue.retry(job_id)
    queue.retry(job_id, acknowledge_uncertain=True)
    assert queue.get(job_id)["status"] == "queued"


def test_retry_budget_and_idempotency():
    job_id = queue.enqueue("test.fixture", {}, idempotency_key="operation", max_attempts=1)
    assert queue.enqueue("test.fixture", {}, idempotency_key="operation", max_attempts=1) == job_id
    with pytest.raises(ValueError, match="another operation"):
        queue.enqueue("test.other", {}, idempotency_key="operation")
    row = queue.claim(job_id=job_id)
    queue.finish(job_id, row["owner"], "failed")
    with pytest.raises(ValueError, match="limit"):
        queue.retry(job_id)


@pytest.mark.parametrize("payload", [{"password": "x"}, {"nested": {"api_key": "secret"}}, {"url": "https://user:pass@example.org"}])
def test_payload_refuses_credentials(payload):
    with pytest.raises(ValueError):
        queue.enqueue("test.fixture", payload)
    assert queue.list_jobs() == []


def test_worker_terminal_errors_redact_configured_secrets(monkeypatch):
    monkeypatch.setenv("SCOPESCAN_REMOTE_TOKEN", "bearer-secret")
    def fail(payload, context):
        raise RuntimeError("provider bearer-secret https://user:pwd@example.org token=visible")
    worker.register_handler("test.fixture", fail)
    row = worker.run_once(job_id=queue.enqueue("test.fixture", {}))
    assert row["status"] == "failed"
    assert "bearer-secret" not in row["error"] and "pwd" not in row["error"] and "visible" not in row["error"]


def test_persistent_cancel_kills_silent_process(tmp_path):
    from scopescan.process_runner import run_process
    started = threading.Event()
    def handler(payload, context):
        started.set()
        result = run_process([sys.executable, "-c", "import time;time.sleep(60)"], cancel=context.cancel, timeout=20)
        assert result.cancelled
    worker.register_handler("test.silent", handler)
    job_id = queue.enqueue("test.silent", {})
    thread = threading.Thread(target=lambda: worker.run_once(job_id=job_id))
    thread.start()
    assert started.wait(5)
    queue.cancel(job_id)
    thread.join(12)
    assert not thread.is_alive() and queue.get(job_id)["status"] == "cancelled"


def test_delete_running_scan_fences_final_write():
    scan_id = scan()
    job_id = jobs.QUEUE.submit(scan_id)
    row = queue.claim(job_id=job_id)
    assert jobs.QUEUE.request_delete(scan_id)
    token = queue.ownership.set((job_id, row["owner"]))
    try:
        with pytest.raises(queue.JobLost):
            db.set_status(scan_id, "done")
    finally:
        queue.ownership.reset(token)
    assert queue.finish(job_id, row["owner"], "cancelled")
    assert db.get_scan(scan_id) is None and queue.get(job_id) is None


def test_cancel_queued_scan_visible_without_worker():
    scan_id = scan()
    job_id = jobs.QUEUE.submit(scan_id)
    assert queue.cancel(job_id)
    assert db.get_scan(scan_id)["status"] == "cancelled"
    assert queue.claim(job_id=job_id) is None


def test_completed_scan_not_replayed_after_worker_dies():
    scan_id = scan()
    job_id = jobs.QUEUE.submit(scan_id)
    queue.claim(job_id=job_id)
    db.set_status(scan_id, "done")
    expire(job_id)
    assert queue.claim(job_id=job_id) is None
    assert queue.get(job_id)["status"] == "done"


def make_schedule(stamp=None, **options):
    from scopescan.scopes import create_scope
    scope_id = create_scope(name="loopback", targets="127.0.0.1", profile="rapido", authorized_by="test")
    stamp = time.time() - 1 if stamp is None else stamp
    schedule_id = scheduler.create(name="fixture", scope_id=scope_id, starts_at=datetime.fromtimestamp(stamp, UTC).isoformat(), interval_seconds=60, **options)
    return scope_id, schedule_id, stamp


def test_scheduler_atomic_slots_duplicate_and_concurrency():
    _, schedule_id, stamp = make_schedule()
    first = scheduler.tick(stamp=stamp + 1)
    assert len(first) == 1 and scheduler.tick(stamp=stamp + 1) == []
    assert scheduler.tick(stamp=stamp + 61) == []  # queued job consumes schedule limit
    queue.cancel(first[0])
    assert len(scheduler.tick(stamp=stamp + 61)) == 1
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM schedule_runs WHERE schedule_id=?", (schedule_id,)).fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM scans").fetchone()[0] == 2


def test_schedule_changed_authorization_disables_once():
    from scopescan.scopes import update_scope
    scope_id, schedule_id, stamp = make_schedule()
    update_scope(scope_id, name="loopback", targets="127.0.0.1", profile="rapido", authorized_by="another")
    assert scheduler.tick(stamp=stamp + 1) == []
    assert scheduler.tick(stamp=stamp + 61) == []
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM schedule_events WHERE schedule_id=?", (schedule_id,)).fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM scans").fetchone()[0] == 0


def test_schedule_transaction_failure_no_orphan_scan(monkeypatch):
    _, _, stamp = make_schedule()
    def fail(*args, **kwargs):
        raise ValueError("enqueue failure")
    monkeypatch.setattr(queue, "enqueue", fail)
    with pytest.raises(ValueError):
        scheduler.tick(stamp=stamp + 1)
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM scans").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM schedule_runs").fetchone()[0] == 0


def test_utc_window_and_worker_revalidates_scope():
    _, schedule_id, stamp = make_schedule(window_start="03:00", window_end="04:00")
    day = datetime.fromtimestamp(stamp, UTC).replace(hour=5, minute=0, second=0).timestamp()
    assert scheduler.tick(stamp=max(day, stamp + 1)) == []
    scheduler.set_enabled(schedule_id, False)
    with pytest.raises(ValueError, match="disabled"):
        scheduler.validate_schedule(schedule_id)
    with pytest.raises(ValueError, match="UTC"):
        scheduler.utc_timestamp("2026-10-03T00:00:00")


def test_web_startup_preserves_live_worker_and_queue_only(monkeypatch):
    from scopescan.web import app as web
    scan_id = scan()
    job_id = jobs.QUEUE.submit(scan_id)
    row = queue.claim(job_id=job_id)
    db.set_status(scan_id, "running")
    monkeypatch.setattr(worker, "run_once", lambda **kw: pytest.fail("Web cannot execute jobs"))
    with TestClient(web.app, base_url="http://localhost", client=("127.0.0.1", 50000)) as client:
        assert client.get("/jobs").status_code == 200
        assert client.get("/api/jobs").json()["jobs"][0]["status"] == "running"
        assert db.get_scan(scan_id)["status"] == "running"
    assert queue.get(job_id)["owner"] == row["owner"]


def test_global_worker_concurrency_across_claims(monkeypatch):
    from scopescan import config
    monkeypatch.setattr(config, "MAX_CONCURRENT_SCANS", 1)
    first, second = queue.enqueue("test.fixture", {}), queue.enqueue("test.fixture", {})
    claimed = queue.claim(job_id=first)
    assert queue.claim(job_id=second) is None
    queue.finish(first, claimed["owner"], "done")
    assert queue.claim(job_id=second) is not None


def test_scan_reservation_cannot_execute_before_final_plan_submission():
    from scopescan.service import ScanRequest, queue_scan
    scan_id = queue_scan(ScanRequest(targets="127.0.0.1", profile="rapido", authorized_by="test"))
    row = queue.list_jobs()[0]
    assert row["scan_id"] == scan_id and "finalized" in row["error"]
    assert queue.claim(job_id=row["id"]) is None
    db.set_scan_context(scan_id, execution_context={"verification": {"protocol":"tcp","ports":[443],"scripts":[],"rules":[]}})
    assert jobs.QUEUE.submit(scan_id) == row["id"]
    assert queue.claim(job_id=row["id"]) is not None
    assert json.loads(db.get_scan(scan_id)["execution_context"])["verification"]["ports"] == [443]


def test_imports_do_not_reserve_executable_jobs():
    db.create_scan(name="external", targets="127.0.0.1", profile="imported", execution_context={"pinned_targets":["127.0.0.1"]})
    assert queue.list_jobs() == []


def test_legacy_pending_migration_idempotent_and_unknown_operations_actionable():
    ready = db.create_scan(name="legacy", targets="127.0.0.1", profile="rapido", execution_context={"pinned_targets":["127.0.0.1"]})
    unknown = scan()
    db.set_status(unknown, "running")
    assert db.claim_enrichment_job(ready, "nvd")
    db.init_db()
    db.init_db()
    rows = queue.list_jobs()
    assert len(rows) == 1 and rows[0]["scan_id"] == ready
    assert rows[0]["available_at"] == 0
    assert db.get_scan(unknown)["status"] == "failed"
    assert "review" in db.get_scan(unknown)["error"]
    assert db.get_enrichment_statuses(ready)["nvd"]["status"] == "failed"


def test_two_scheduler_processes_create_one_slot():
    _, _, _ = make_schedule()
    code = "from scopescan.scheduler import tick;import json;print(json.dumps(tick()))"
    processes = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True) for _ in range(2)]
    replies = [json.loads(proc.communicate(timeout=30)[0]) for proc in processes]
    assert sum(map(len, replies)) == 1
    assert len(queue.list_jobs()) == 1


def test_schedule_unchanged_success_emits_no_repeated_event():
    _, schedule_id, stamp = make_schedule()
    first = scheduler.tick(stamp=stamp + 1)[0]
    row = queue.claim(job_id=first)
    db.set_status(row["scan_id"], "done")
    queue.finish(first, row["owner"], "done")
    second = scheduler.tick(stamp=stamp + 61)[0]
    row = queue.claim(job_id=second)
    db.set_status(row["scan_id"], "done")
    queue.finish(second, row["owner"], "done")
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM schedule_events WHERE schedule_id=?", (schedule_id,)).fetchone()[0] == 1


def test_worker_export_snapshot_does_not_drop_fence():
    scan_id = scan()
    job_id = queue.enqueue("test.export", {}, scan_id=scan_id)
    row = queue.claim(job_id=job_id)
    token = queue.ownership.set((job_id, row["owner"]))
    try:
        with db.read_snapshot():
            assert db.get_scan(scan_id)["id"] == scan_id
    finally:
        queue.ownership.reset(token)
    assert queue.heartbeat(job_id, row["owner"])


def test_collector_cancellation_forwards_bounds_and_does_not_store(monkeypatch):
    from scopescan import linux_inventory, process_runner
    cancel = threading.Event()
    cancel.set()
    def run(argv, **options):
        assert options["cancel"] is cancel and options["deadline"] == 123
        assert options["timeout"] == 180 and options["max_output_chars"] == 8_000_000
        assert "SCOPESCAN_PANEL_PASSWORD" not in options["env"]
        return process_runner.ProcessResult(-1, "", "", cancelled=True)
    monkeypatch.setenv("SCOPESCAN_PANEL_PASSWORD", "private")
    monkeypatch.setattr(linux_inventory.shutil, "which", lambda name: "fake-ssh")
    monkeypatch.setattr(process_runner, "run_process", run)
    with pytest.raises(linux_inventory.InventoryError, match="cancelado"):
        linux_inventory.collect("127.0.0.1", cancel=cancel, deadline=123)


def test_finished_status_does_not_repeat_enrichment_observations(monkeypatch):
    from scopescan import continuity
    scan_id = scan()
    calls = []
    monkeypatch.setattr(continuity, "reconcile", lambda conn, scan_id: calls.append(scan_id))
    db.set_status(scan_id, "done")
    first = db.get_scan(scan_id)["finished_at"]
    db.set_status(scan_id, "done")
    assert calls == [scan_id] and db.get_scan(scan_id)["finished_at"] == first


def test_worker_command_reports_queued_capacity_action(monkeypatch):
    job_id = queue.enqueue("test.fixture", {})
    monkeypatch.setattr(worker, "run_once", lambda **options: None)
    with pytest.raises(ValueError, match=f"Job #{job_id} is queued; start scopescan worker"):
        worker.execute_now(job_id)
    assert queue.get(job_id)["status"] == "queued"


@pytest.mark.parametrize("declared", [True, False])
def test_asgi_upload_bound_rejects_before_parser(declared):
    import asyncio

    from scopescan.web.body_limit import BodyLimitMiddleware
    invoked, replies = [], []
    async def app(scope, receive, send):
        invoked.append(True)
    payloads = iter([{"type":"http.request","body":b"a"*4_100_000,"more_body":True},
                     {"type":"http.request","body":b"a"*4_100_000,"more_body":False}])
    async def receive():
        return next(payloads)
    async def send(message):
        replies.append(message)
    scope = {"type":"http","method":"POST","path":"/software/import","headers":[(b"content-length",b"8200000")] if declared else []}
    asyncio.run(BodyLimitMiddleware(app)(scope, receive, send))
    assert invoked == [] and replies[0]["status"] == 413


def test_default_web_enrichment_enqueues_atomically_and_cannot_duplicate(monkeypatch):
    from scopescan.web import app as web
    scan_id = scan()
    db.set_status(scan_id, "done")
    monkeypatch.setattr(web.nvd, "enrich_scan", lambda *args, **options: pytest.fail("Web cannot call provider"))
    with TestClient(web.app, base_url="http://localhost", client=("127.0.0.1",50000)) as client:
        client.get("/")
        headers = {"X-CSRF-Token":client.cookies["scopescan_csrf"]}
        assert client.post(f"/scans/{scan_id}/enrich/nvd", headers=headers, follow_redirects=False).status_code == 303
        assert client.post(f"/scans/{scan_id}/enrich/nvd", headers=headers, follow_redirects=False).status_code == 303
        row = queue.list_jobs()[0]
        assert row["status"] == "queued" and row["kind"] == "enrichment"
        assert len(queue.list_jobs()) == 1
        assert db.get_enrichment_statuses(scan_id)["nvd"]["status"] == "queued"
        assert client.get(f"/jobs/{row['id']}").status_code == 200


def test_worker_revalidates_saved_scope_authorization_before_nmap(monkeypatch):
    from scopescan import nmap_runner, scopes
    scope_id = scopes.create_scope(name="approved",targets="127.0.0.1",profile="rapido",authorized_by="owner")
    scan_id = scopes.queue_scope(scope_id)
    job_id = jobs.QUEUE.submit(scan_id)
    scopes.update_scope(scope_id,name="approved",targets="127.0.0.1",profile="rapido",authorized_by="other")
    monkeypatch.setattr(nmap_runner,"build_argv",lambda **options: pytest.fail("Changed authorization cannot execute"))
    result = worker.run_once(job_id=job_id)
    assert result["status"] == "failed" and "autorización" in result["error"]


def test_lease_expiring_during_transaction_rolls_back_domain_mutation():
    scan_id = scan()
    job_id = queue.enqueue("test.transaction",{},scan_id=scan_id)
    claimed = queue.claim(job_id=job_id)
    token = queue.ownership.set((job_id,claimed["owner"]))
    try:
        with pytest.raises(queue.JobLost), db.connect() as conn:
            conn.execute("UPDATE scans SET progress=90 WHERE id=?",(scan_id,))
            # Deterministic expiry inside the locked transaction models a
            # long bulk write whose heartbeat cannot acquire the writer lock.
            conn.execute("UPDATE durable_jobs SET lease_until=? WHERE id=?",(time.time()-1,job_id))
    finally:
        queue.ownership.reset(token)
    assert db.get_scan(scan_id)["progress"] == 0
    assert queue.get(job_id)["lease_until"] == claimed["lease_until"]
