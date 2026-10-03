"""Explicit UTC schedules and atomic slots; no schedule is enabled implicitly."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime

from . import db, durable_jobs


def migrate(conn):
    conn.executescript("""
CREATE TABLE IF NOT EXISTS schedules (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, scope_id INTEGER NOT NULL,
 snapshot TEXT NOT NULL, interval_seconds INTEGER NOT NULL, starts_at REAL NOT NULL,
 ends_at REAL, window_start INTEGER NOT NULL, window_end INTEGER NOT NULL,
 max_running INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1,
 last_fingerprint TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS schedule_runs (
 schedule_id INTEGER REFERENCES schedules(id) ON DELETE CASCADE,
 slot INTEGER NOT NULL, job_id INTEGER REFERENCES durable_jobs(id) ON DELETE SET NULL,
 PRIMARY KEY(schedule_id,slot));
CREATE TABLE IF NOT EXISTS schedule_events (
 id INTEGER PRIMARY KEY, schedule_id INTEGER REFERENCES schedules(id) ON DELETE CASCADE,
 job_id INTEGER, event TEXT NOT NULL, detail TEXT NOT NULL, created_at REAL NOT NULL);
""")


def utc_timestamp(value):
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("Use an ISO timestamp with UTC offset") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("Schedule timestamps must be explicitly UTC")
    return parsed.timestamp()


def _minute(value):
    try:
        hours, minutes = map(int, value.split(":"))
    except (ValueError, AttributeError) as exc:
        raise ValueError("UTC window needs HH:MM") from exc
    if not 0 <= hours <= 23 or not 0 <= minutes <= 59:
        raise ValueError("Invalid UTC window")
    return 60 * hours + minutes


def _snapshot(scope):
    return {key: scope[key] for key in ("pinned_targets", "profile", "authorized_by", "max_hosts", "exclusions", "resolutions")}


def create(*, name, scope_id, interval_seconds=86400, starts_at, ends_at=None,
           window_start="00:00", window_end="00:00", max_running=1):
    from .profiles import get_profile
    from .scopes import get_scope
    scope = get_scope(scope_id)
    get_profile(scope["profile"])
    if not scope["authorized_by"].strip():
        raise ValueError("A schedule requires an authorized saved scope")
    if type(interval_seconds) is not int or not 60 <= interval_seconds <= 31_536_000 or type(max_running) is not int or not 1 <= max_running <= 10:
        raise ValueError("Invalid interval or concurrency limit")
    start, end = utc_timestamp(starts_at), utc_timestamp(ends_at) if ends_at else None
    if end is not None and end <= start:
        raise ValueError("End must follow start")
    first, last = _minute(window_start), _minute(window_end)
    with db.connect() as conn:
        cur = conn.execute("INSERT INTO schedules(name,scope_id,snapshot,interval_seconds,starts_at,ends_at,window_start,window_end,max_running,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", (name[:200], scope_id, json.dumps(_snapshot(scope), sort_keys=True), interval_seconds, start, end, first, last, max_running, time.time()))
        return int(cur.lastrowid)


def list_schedules():
    with db.connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM schedules ORDER BY id DESC")]


def events(*, limit=100):
    if not 1 <= limit <= 500:
        raise ValueError("Invalid event limit")
    with db.connect() as conn:
        rows = [dict(row) for row in conn.execute("SELECT * FROM schedule_events ORDER BY id DESC LIMIT ?", (limit,))]
    for row in rows:
        row["created_at"] = datetime.fromtimestamp(row["created_at"], UTC).isoformat(timespec="seconds")
    return rows


def set_enabled(schedule_id, enabled):
    with db.connect() as conn:
        if not conn.execute("UPDATE schedules SET enabled=? WHERE id=?", (int(enabled), schedule_id)).rowcount:
            raise ValueError("Schedule missing")


def _inside(row, stamp):
    minute = datetime.fromtimestamp(stamp, UTC).hour * 60 + datetime.fromtimestamp(stamp, UTC).minute
    first, last = row["window_start"], row["window_end"]
    return first == last or first <= minute < last if first <= last else minute >= first or minute < last


def validate_schedule(schedule_id):
    from .scopes import get_scope
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
    if row is None or not row["enabled"] or not _inside(row, time.time()):
        raise ValueError("Schedule disabled or outside UTC execution window")
    if json.loads(row["snapshot"]) != _snapshot(get_scope(row["scope_id"])):
        raise ValueError("Scope authorization, profile or pinned targets changed; recreate schedule")
    if row["ends_at"] is not None and time.time() >= row["ends_at"]:
        raise ValueError("Schedule expired")


def tick(*, stamp=None):
    stamp = time.time() if stamp is None else stamp
    created = []
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        for row in conn.execute("SELECT * FROM schedules WHERE enabled=1 AND starts_at<=?", (stamp,)).fetchall():
            if row["ends_at"] is not None and stamp >= row["ends_at"] or not _inside(row, stamp):
                continue
            slot = int((stamp - row["starts_at"]) // row["interval_seconds"])
            if conn.execute("SELECT 1 FROM schedule_runs WHERE schedule_id=? AND slot=?", (row["id"], slot)).fetchone():
                continue
            count = conn.execute("SELECT count(*) FROM schedule_runs r JOIN durable_jobs j ON j.id=r.job_id WHERE r.schedule_id=? AND j.status IN ('queued','running')", (row["id"],)).fetchone()[0]
            if count >= row["max_running"]:
                continue
            try:
                # Read from this transaction: no second connection or mixed scope snapshot.
                scope_row = conn.execute("SELECT * FROM saved_scopes WHERE id=?", (row["scope_id"],)).fetchone()
                if scope_row is None:
                    raise ValueError("Saved scope deleted")
                scope = json.loads(scope_row["specification"])
                if _snapshot(scope) != json.loads(row["snapshot"]):
                    raise ValueError("Saved scope changed; schedule requires review")
            except ValueError as exc:
                conn.execute("UPDATE schedules SET enabled=0 WHERE id=?", (row["id"],))
                conn.execute("INSERT INTO schedule_events(schedule_id,event,detail,created_at) VALUES (?,?,?,?)", (row["id"], "action_required", str(exc), stamp))
                continue
            from .targets import parse_targets
            target_set = parse_targets(" ".join(scope["pinned_targets"]), max_hosts=scope["max_hosts"])
            context = {"namespace": f"scope:{row['scope_id']}", "pinned_targets": scope["pinned_targets"], "profile": scope["profile"], "schedule_id": row["id"], "privileged": False}
            scan = conn.execute("INSERT INTO scans(name,targets,profile,status,created_at,target_private,authorized_by,notes,scope_id,execution_context) VALUES (?,?,?,'queued',?,?,?,?,?,?)", (row["name"], target_set.raw, scope["profile"], db.now(), int(target_set.all_private), scope["authorized_by"], "Scheduled assessment", row["scope_id"], json.dumps(context)))
            scan_id = int(scan.lastrowid)
            job_id = durable_jobs.enqueue("scan", {"scan_id": scan_id, "schedule_id": row["id"]}, scan_id=scan_id, idempotency_key=f"schedule:{row['id']}:{slot}", conn=conn)
            conn.execute("INSERT INTO schedule_runs(schedule_id,slot,job_id) VALUES (?,?,?)", (row["id"], slot, job_id))
            created.append(job_id)
    return created


def record_result(conn, job, status, error):
    run = conn.execute("SELECT schedule_id FROM schedule_runs WHERE job_id=?", (job["id"],)).fetchone()
    if run is None:
        return
    event, detail = status, error
    if status == "done":
        findings = [tuple(r) for r in conn.execute("SELECT host,protocol,port,source,rule_id,component,cves,severity,assessment FROM findings WHERE scan_id=? ORDER BY host,protocol,port,source,rule_id,component,cves,severity,assessment", (job["scan_id"],))]
        endpoints = [tuple(r) for r in conn.execute("SELECT h.address,h.state,p.portid,p.protocol,p.state,p.service_name,p.product,p.version FROM hosts h LEFT JOIN ports p ON p.host_id=h.id WHERE h.scan_id=? ORDER BY h.address,p.protocol,p.portid", (job["scan_id"],))]
        fingerprint = hashlib.sha256(json.dumps([findings, endpoints], sort_keys=True).encode()).hexdigest()
        previous = conn.execute("SELECT last_fingerprint FROM schedules WHERE id=?", (run[0],)).fetchone()
        if previous is None or previous[0] == fingerprint:
            return
        conn.execute("UPDATE schedules SET last_fingerprint=? WHERE id=?", (fingerprint, run[0]))
        event, detail = "change", "Assessment evidence changed" if previous[0] else "Initial assessment recorded"
    conn.execute("INSERT INTO schedule_events(schedule_id,job_id,event,detail,created_at) VALUES (?,?,?,?,?)", (run[0], job["id"], event, detail[:2000], time.time()))
