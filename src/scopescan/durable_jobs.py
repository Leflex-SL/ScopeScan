"""SQLite queue with fenced leases, cancellation and explicit recovery policy."""
from __future__ import annotations

import contextvars
import json
import os
import re
import time
import uuid

from . import db

ownership = contextvars.ContextVar("job_ownership", default=None)
TERMINAL = {"done", "partial", "failed", "cancelled"}


class JobLost(RuntimeError):
    pass


def migrate(conn):
    conn.executescript("""
CREATE TABLE IF NOT EXISTS durable_jobs (
 id INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
 scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
 status TEXT NOT NULL DEFAULT 'queued', owner TEXT, lease_until REAL,
 cancel_requested INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
 max_attempts INTEGER NOT NULL DEFAULT 3, retry_safe INTEGER NOT NULL DEFAULT 1,
 idempotency_key TEXT UNIQUE, created_at REAL NOT NULL, updated_at REAL NOT NULL,
 available_at REAL NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS durable_jobs_pending ON durable_jobs(status, available_at, id);
CREATE TABLE IF NOT EXISTS job_events (
 id INTEGER PRIMARY KEY, job_id INTEGER REFERENCES durable_jobs(id) ON DELETE CASCADE,
 event TEXT NOT NULL, detail TEXT NOT NULL, created_at REAL NOT NULL);
""")


def guard(conn, *, begin=True):
    current = ownership.get()
    if current is None:
        return
    if begin and not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM durable_jobs WHERE id=?", (current[0],)).fetchone()
    if (row is None or row["owner"] != current[1] or row["status"] != "running"
            or row["lease_until"] < time.time() or row["cancel_requested"]):
        raise JobLost("Job cancelled, deleted, or lease ownership lost")
    if row["scan_id"] is not None:
        scan = conn.execute("SELECT deletion_pending FROM scans WHERE id=?", (row["scan_id"],)).fetchone()
        if scan is None or scan[0]:
            raise JobLost("Scan deleted or pending deletion")


def migrate_legacy_pending(conn):
    """Capture only reconstructible queued requests; ambiguous legacy runs need review."""
    for row in conn.execute("SELECT * FROM scans WHERE status IN ('queued','running') AND deletion_pending=0 AND NOT EXISTS (SELECT 1 FROM durable_jobs j WHERE j.scan_id=scans.id AND j.kind='scan')").fetchall():
        context = json.loads(row["execution_context"] or "{}")
        if row["status"] == "queued" and (context.get("pinned_targets") or context.get("engine_plan")) and row["profile"] != "imported":
            enqueue("scan", {"scan_id":row["id"]}, scan_id=row["id"], idempotency_key=f"scan:{row['id']}", conn=conn)
        else:
            conn.execute("UPDATE scans SET status='failed',error=?,finished_at=? WHERE id=?", ("Legacy operation has no durable ownership; review and enqueue again", db.now(), row["id"]))
    conn.execute("""UPDATE enrichment_jobs SET status='failed',error='Legacy operation options are unavailable; review and enqueue again',updated_at=?
        WHERE status IN ('running','queued') AND NOT EXISTS
        (SELECT 1 FROM durable_jobs j WHERE j.scan_id=enrichment_jobs.scan_id AND j.kind='enrichment' AND json_extract(j.payload,'$.kind')=enrichment_jobs.kind AND j.status IN ('queued','running'))""", (db.now(),))


def _validate_payload(payload):
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("Job payload keys must be strings")
                if re.search(r"password|secret|token|credential|api.?key|authorization", key, re.IGNORECASE) and not key.endswith("_env"):
                    raise ValueError("Use environment references for job credentials")
                if key.endswith("_env") and (not isinstance(item, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", item)):
                    raise ValueError("Credential environment reference must be a variable name")
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and re.search(r"[a-z][a-z0-9+.-]*://[^/\s]+@", value, re.IGNORECASE):
            raise ValueError("Credential-bearing URLs are forbidden in jobs")
    if not isinstance(payload, dict):
        raise TypeError("Job payload must be an object")
    walk(payload)
    encoded = json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > 1_000_000:
        raise ValueError("Job payload exceeds 1 MB")
    return encoded


def enqueue(kind, payload, *, scan_id=None, idempotency_key=None, retry_safe=True, max_attempts=3, conn=None):
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", kind) or type(max_attempts) is not int or not 1 <= max_attempts <= 10:
        raise ValueError("Invalid job kind or attempts")
    if idempotency_key is not None and (not isinstance(idempotency_key,str) or not 1 <= len(idempotency_key) <= 200):
        raise ValueError("Invalid idempotency key")
    encoded = _validate_payload(payload)
    def insert(connection):
        if scan_id is not None:
            scan = connection.execute("SELECT deletion_pending FROM scans WHERE id=?", (scan_id,)).fetchone()
            if scan is None or scan[0]:
                raise ValueError("Scan missing or pending deletion")
        stamp = time.time()
        cur = connection.execute("""INSERT INTO durable_jobs
            (kind,payload,scan_id,idempotency_key,retry_safe,max_attempts,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(idempotency_key) DO NOTHING""",
            (kind, encoded, scan_id, idempotency_key, int(retry_safe), max_attempts, stamp, stamp))
        if cur.rowcount:
            return int(cur.lastrowid)
        row = connection.execute("SELECT id,kind,payload,scan_id FROM durable_jobs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
        if row["kind"] != kind or row["payload"] != encoded or row["scan_id"] != scan_id:
            raise ValueError("Idempotency key already belongs to another operation")
        return row["id"]
    if conn is not None:
        return insert(conn)
    with db.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        return insert(connection)


def get(job_id):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM durable_jobs WHERE id=?", (job_id,)).fetchone()
    return dict(row) if row is not None else None


def list_jobs(*, limit=100, offset=0, scan_id=None):
    if not 1 <= limit <= 500 or offset < 0:
        raise ValueError("Invalid pagination")
    with db.connect() as conn:
        where, params = ("WHERE scan_id=?", [scan_id]) if scan_id is not None else ("", [])
        return [dict(row) for row in conn.execute(f"SELECT id,kind,scan_id,status,cancel_requested,attempts,max_attempts,retry_safe,available_at,created_at,updated_at,error FROM durable_jobs {where} ORDER BY id DESC LIMIT ? OFFSET ?", (*params, limit, offset))]


def recover(conn, *, stamp=None):
    stamp = time.time() if stamp is None else stamp
    rows = conn.execute("SELECT * FROM durable_jobs WHERE status='running' AND lease_until<?", (stamp,)).fetchall()
    for row in rows:
        status = ("cancelled" if row["cancel_requested"] else
                  "queued" if row["retry_safe"] and row["attempts"] < row["max_attempts"] else "failed")
        if row["kind"] == "scan" and not row["cancel_requested"]:
            scan = conn.execute("SELECT status FROM scans WHERE id=?", (row["scan_id"],)).fetchone()
            if scan is not None and scan[0] in TERMINAL:
                status = scan[0]
        message = "Worker lease expired; operation needs review" if status == "failed" else "Worker lease expired"
        conn.execute("UPDATE durable_jobs SET status=?,owner=NULL,lease_until=NULL,error=?,updated_at=? WHERE id=?", (status, message, stamp, row["id"]))
        if row["scan_id"] is not None and row["kind"] == "scan":
            conn.execute("UPDATE scans SET status=? WHERE id=? AND deletion_pending=0", (status, row["scan_id"]))
        elif row["scan_id"] is not None and row["kind"] == "enrichment":
            conn.execute("UPDATE enrichment_jobs SET status=?,error=?,updated_at=? WHERE scan_id=? AND kind=?", (status, message, db.now(), row["scan_id"], json.loads(row["payload"])["kind"]))
        conn.execute("INSERT INTO job_events(job_id,event,detail,created_at) VALUES (?,?,?,?)", (row["id"], "recovery", message, stamp))
    # A crashed cancellation must also finish pending deletion without resurrecting rows.
    for row in conn.execute("SELECT id FROM scans WHERE deletion_pending=1").fetchall():
        if not conn.execute("SELECT 1 FROM durable_jobs WHERE scan_id=? AND status='running' AND lease_until>=?", (row[0], stamp)).fetchone():
            db._delete_scan_rows(conn, row[0])


def claim(*, lease_seconds=30, job_id=None):
    if not 2 <= lease_seconds <= 3600:
        raise ValueError("Lease must be 2..3600 seconds")
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        stamp = time.time()
        recover(conn, stamp=stamp)
        from .config import MAX_CONCURRENT_SCANS
        if conn.execute("SELECT count(*) FROM durable_jobs WHERE status='running' AND lease_until>=?", (stamp,)).fetchone()[0] >= MAX_CONCURRENT_SCANS:
            return None
        sql = "SELECT * FROM durable_jobs WHERE status='queued' AND cancel_requested=0 AND available_at<=?"
        params = [stamp]
        if job_id is not None:
            sql += " AND id=?"
            params.append(job_id)
        row = conn.execute(sql + " ORDER BY id LIMIT 1", params).fetchone()
        if row is None:
            return None
        owner = uuid.uuid4().hex
        conn.execute("UPDATE durable_jobs SET status='running',owner=?,lease_until=?,attempts=attempts+1,updated_at=? WHERE id=?", (owner, stamp + lease_seconds, stamp, row["id"]))
        result = dict(row)
        result.update(owner=owner, lease_until=stamp + lease_seconds, attempts=row["attempts"] + 1, status="running")
        return result


def heartbeat(job_id, owner, *, lease_seconds=30):
    with db.connect() as conn:
        stamp = time.time()
        return conn.execute("UPDATE durable_jobs SET lease_until=?,updated_at=? WHERE id=? AND owner=? AND status='running' AND lease_until>=? AND cancel_requested=0", (stamp + lease_seconds, stamp, job_id, owner, stamp)).rowcount == 1


def cancelled(job_id, owner):
    row = get(job_id)
    return row is None or row["owner"] != owner or row["status"] != "running" or row["cancel_requested"] or row["lease_until"] < time.time()


def finish(job_id, owner, status, *, result=None, error=""):
    if status not in TERMINAL:
        raise ValueError("Invalid terminal job status")
    from .engine_store import redact_text, sanitize
    error = redact_text(error)
    for key, value in os.environ.items():
        if value and len(value) >= 3 and re.search(r"password|secret|token|api.?key", key, re.IGNORECASE):
            error = error.replace(value, "[redacted]")
    encoded_result, _ = sanitize(json.dumps(result or {}, allow_nan=False).encode(), "application/json")
    secrets = [value for key,value in os.environ.items() if value and len(value)>=3 and re.search(r"password|secret|token|api.?key",key,re.IGNORECASE)]
    def scrub(value):
        if isinstance(value,str):
            for secret in secrets:
                value = value.replace(secret,"[redacted]")
            return value
        if isinstance(value,dict):
            return {key:scrub(item) for key,item in value.items()}
        if isinstance(value,list):
            return [scrub(item) for item in value]
        return value
    encoded_result = json.dumps(scrub(json.loads(encoded_result)),allow_nan=False).encode()
    if len(encoded_result) > 1_000_000:
        status, error, encoded_result = "failed", "Job result exceeds 1 MB", b"{}"
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM durable_jobs WHERE id=? AND owner=? AND status='running' AND lease_until>=?", (job_id, owner, time.time())).fetchone()
        if row is None:
            return False
        if row["cancel_requested"]:
            status = "cancelled"
        conn.execute("UPDATE durable_jobs SET status=?,result=?,error=?,owner=NULL,lease_until=NULL,updated_at=? WHERE id=?", (status, encoded_result.decode(), error[:2000], time.time(), job_id))
        from .scheduler import record_result
        record_result(conn, row, status, error)
        if status in {"failed", "partial", "cancelled"}:
            conn.execute("INSERT INTO job_events(job_id,event,detail,created_at) VALUES (?,?,?,?)", (job_id, status, error[:2000], time.time()))
        if row["scan_id"] is not None:
            pending = conn.execute("SELECT deletion_pending FROM scans WHERE id=?", (row["scan_id"],)).fetchone()
            if pending and pending[0]:
                db._delete_scan_rows(conn, row["scan_id"])
            elif row["kind"] == "scan" and status in {"failed", "cancelled"}:
                conn.execute("UPDATE scans SET status=?,error=?,finished_at=? WHERE id=?", (status, error[:2000], db.now(), row["scan_id"]))
            elif row["kind"] == "enrichment":
                conn.execute("UPDATE enrichment_jobs SET status=?,error=?,updated_at=? WHERE scan_id=? AND kind=?", (status, error[:2000], db.now(), row["scan_id"], json.loads(row["payload"])["kind"]))
        return True


def cancel(job_id):
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM durable_jobs WHERE id=?", (job_id,)).fetchone()
        changed = conn.execute("UPDATE durable_jobs SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,updated_at=? WHERE id=? AND status IN ('queued','running')", (time.time(), job_id)).rowcount == 1
        if changed and row["status"] == "queued" and row["scan_id"] is not None:
            if row["kind"] == "scan":
                conn.execute("UPDATE scans SET status='cancelled',finished_at=? WHERE id=?", (db.now(), row["scan_id"]))
            elif row["kind"] == "enrichment":
                kind = json.loads(row["payload"])["kind"]
                conn.execute("UPDATE enrichment_jobs SET status='cancelled' WHERE scan_id=? AND kind=?", (row["scan_id"], kind))
        return changed


def retry(job_id, *, acknowledge_uncertain=False):
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM durable_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None or row["status"] not in {"failed", "cancelled", "partial"}:
            raise ValueError("Only failed, partial or cancelled jobs can be retried")
        if not row["retry_safe"] and not acknowledge_uncertain:
            raise ValueError("External writes need explicit reconciliation and acknowledgement")
        if row["attempts"] >= row["max_attempts"]:
            raise ValueError("Retry limit reached")
        conn.execute("UPDATE durable_jobs SET status='queued',cancel_requested=0,owner=NULL,lease_until=NULL,error='',updated_at=? WHERE id=?", (time.time(), job_id))
        if row["kind"] == "scan":
            conn.execute("UPDATE scans SET status='queued' WHERE id=? AND deletion_pending=0", (row["scan_id"],))
        return job_id
