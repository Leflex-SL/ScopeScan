"""Connector destinations, immutable imports and delivery checkpoints in SQLite."""
from __future__ import annotations

import hashlib
import json

from . import db, destinations
from .engine_store import sanitize

SCHEMA = """
CREATE TABLE IF NOT EXISTS integration_destinations (
 id INTEGER PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,url TEXT NOT NULL,
 settings TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS integration_imports (
 id INTEGER PRIMARY KEY,kind TEXT NOT NULL,scope_id INTEGER,scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
 destination_id INTEGER REFERENCES integration_destinations(id) ON DELETE SET NULL,
 observed_at TEXT NOT NULL,status TEXT NOT NULL,normalized TEXT NOT NULL,raw BLOB NOT NULL,
 received_sha256 TEXT NOT NULL,raw_sha256 TEXT NOT NULL,redactions TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS integration_deliveries (
 id INTEGER PRIMARY KEY,destination_id INTEGER NOT NULL REFERENCES integration_destinations(id),
 destination_hash TEXT NOT NULL,scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
 payload BLOB NOT NULL,payload_hash TEXT NOT NULL,engagement_id INTEGER,test_id INTEGER,
 remote_test_id INTEGER,state TEXT NOT NULL,job_id INTEGER,error TEXT NOT NULL DEFAULT '',
 response TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 UNIQUE(destination_hash,scan_id,payload_hash,engagement_id,test_id));
CREATE INDEX IF NOT EXISTS integration_delivery_state ON integration_deliveries(state,id);
CREATE TABLE IF NOT EXISTS integration_delivery_events (
 id INTEGER PRIMARY KEY,delivery_id INTEGER NOT NULL REFERENCES integration_deliveries(id) ON DELETE CASCADE,
 state TEXT NOT NULL,remote_status TEXT NOT NULL,error TEXT NOT NULL,created_at TEXT NOT NULL);
"""


def migrate(conn):
    conn.executescript(SCHEMA)


def create_destination(name, kind, url, settings):
    if not isinstance(name, str) or not name.strip() or len(name) > 160:
        raise ValueError("Destination name must be 1..160 characters")
    url, settings = destinations.validate(kind, url, settings)
    with db.connect() as conn:
        return conn.execute("INSERT INTO integration_destinations(name,kind,url,settings,created_at) VALUES (?,?,?,?,?)",
            (name.strip(), kind, url, json.dumps(settings, sort_keys=True), db.now())).lastrowid


def get_destination(destination_id):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM integration_destinations WHERE id=?", (destination_id,)).fetchone()
    if row is None:
        raise ValueError("Destination does not exist; configure it first")
    value = dict(row)
    value["settings"] = json.loads(value["settings"])
    destinations.validate(value["kind"], value["url"], value["settings"])
    return value


def page(table, *, limit=50, offset=0):
    if table not in {"integration_destinations", "integration_imports", "integration_deliveries"} or type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
        raise ValueError("Invalid collection or pagination")
    with db.connect() as conn:
        total = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        columns = "*" if table == "integration_destinations" else ("id,kind,scope_id,scan_id,destination_id,observed_at,status,received_sha256,raw_sha256,created_at" if table == "integration_imports" else "id,destination_id,scan_id,payload_hash,engagement_id,test_id,remote_test_id,state,job_id,error,created_at,updated_at")
        rows = [dict(row) for row in conn.execute(f"SELECT {columns} FROM {table} ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))]
    for row in rows:
        if "settings" in row:
            row["settings"] = json.loads(row["settings"])
    return rows, total


def store_import(kind, original, normalized, *, scope_id, scan_id=None, destination_id=None):
    encoded = json.dumps(normalized, ensure_ascii=True, allow_nan=False).encode()
    if len(original) > 8_000_000 or len(encoded) > 8_000_000:
        raise ValueError("Integration evidence exceeds 8 MB")
    raw, redactions = sanitize(encoded, "application/json")
    redactions.append("Original document omitted; only sanitized normalized evidence retained")
    with db.connect() as conn:
        return conn.execute("""INSERT INTO integration_imports(kind,scope_id,scan_id,destination_id,observed_at,status,normalized,raw,received_sha256,raw_sha256,redactions,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (kind, scope_id, scan_id, destination_id, normalized["observed_at"], normalized["status"], raw.decode(), raw,
            hashlib.sha256(original).hexdigest(), hashlib.sha256(raw).hexdigest(), json.dumps(redactions), db.now())).lastrowid


def get_import(import_id, *, include_raw=False):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM integration_imports WHERE id=?", (import_id,)).fetchone()
    if row is None:
        raise ValueError("Import does not exist")
    value = dict(row)
    value["normalized"] = json.loads(value["normalized"])
    value["redactions"] = json.loads(value["redactions"])
    raw = value.pop("raw")
    if include_raw:
        value["raw"] = raw.decode()
    return value


def create_delivery(destination, scan_id, payload, *, engagement_id=None, test_id=None):
    for value in (engagement_id, test_id):
        if value is not None and (type(value) is not int or value <= 0):
            raise ValueError("Remote IDs must be positive integers")
    if (engagement_id is None) == (test_id is None):
        raise ValueError("Specify engagement for import OR existing test for reimport")
    if len(payload) > 8_000_000:
        raise ValueError("Delivery exceeds 8 MB; use smaller snapshots")
    digest = hashlib.sha256(payload).hexdigest()
    config_hash = destinations.fingerprint(destination)
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("""SELECT id FROM integration_deliveries WHERE destination_hash=? AND scan_id=? AND payload_hash=?
            AND engagement_id IS ? AND test_id IS ?""", (config_hash, scan_id, digest, engagement_id, test_id)).fetchone()
        if row:
            return row[0]
        stamp = db.now()
        return conn.execute("""INSERT INTO integration_deliveries(destination_id,destination_hash,scan_id,payload,payload_hash,engagement_id,test_id,state,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,'prepared',?,?)""", (destination["id"], config_hash, scan_id, payload, digest, engagement_id, test_id, stamp, stamp)).lastrowid


def get_delivery(delivery_id, *, include_payload=False):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM integration_deliveries WHERE id=?", (delivery_id,)).fetchone()
    if row is None:
        raise ValueError("Delivery does not exist")
    value = dict(row)
    value["response"] = json.loads(value["response"])
    if not include_payload:
        value.pop("payload")
    return value


def delivery_history(delivery_id, *, limit=50, offset=0):
    if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
        raise ValueError("Invalid history pagination")
    with db.connect() as conn:
        rows = [dict(row) for row in conn.execute("SELECT * FROM integration_delivery_events WHERE delivery_id=? ORDER BY id LIMIT ? OFFSET ?", (delivery_id, limit, offset))]
        total = conn.execute("SELECT count(*) FROM integration_delivery_events WHERE delivery_id=?", (delivery_id,)).fetchone()[0]
    return rows, total


def checkpoint(delivery_id, state, *, remote_test_id=None, response=None, error="", posting=False):
    if state not in {"prepared", "posting", "polling", "done", "failed", "action_required"}:
        raise ValueError("Invalid delivery state")
    if remote_test_id is not None and (type(remote_test_id) is not int or remote_test_id <= 0):
        raise ValueError("Invalid remote test ID")
    safe, _ = sanitize(json.dumps(response or {}, allow_nan=False).encode(), "application/json")
    if len(safe) > 1_000_000:
        raise ValueError("Delivery response metadata exceeds 1 MB")
    with db.connect() as conn:
        old = conn.execute("SELECT state,response FROM integration_deliveries WHERE id=?", (delivery_id,)).fetchone()
        changed = conn.execute("""UPDATE integration_deliveries SET state=?,remote_test_id=coalesce(?,remote_test_id),response=?,error=?,updated_at=?
            WHERE id=?""" + (" AND state='prepared'" if posting else ""), (state, remote_test_id, safe.decode(), error[:2000], db.now(), delivery_id)).rowcount == 1
        remote_status = json.loads(safe).get("status", "")
        if changed and old and (old["state"] != state or json.loads(old["response"]).get("status", "") != remote_status):
            conn.execute("INSERT INTO integration_delivery_events(delivery_id,state,remote_status,error,created_at) VALUES (?,?,?,?,?)", (delivery_id, state, str(remote_status)[:160], error[:2000], db.now()))
        return changed
