"""Immutable software/compliance evidence, separate from network endpoint assets."""
from __future__ import annotations

import hashlib
import json

from . import db
from .engine_store import redact_text
from .sbom import MAX_BYTES, component_identity, text

SCHEMA = """
CREATE TABLE IF NOT EXISTS software_resources (
 id TEXT PRIMARY KEY, namespace TEXT NOT NULL, kind TEXT NOT NULL,
 name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS software_documents (
 id INTEGER PRIMARY KEY,resource_id TEXT NOT NULL REFERENCES software_resources(id),
 kind TEXT NOT NULL,status TEXT NOT NULL,observed_at TEXT,created_at TEXT NOT NULL,
 normalized TEXT NOT NULL,raw BLOB NOT NULL,received_sha256 TEXT NOT NULL,
 raw_sha256 TEXT NOT NULL,provenance TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS software_documents_resource ON software_documents(resource_id,id);
CREATE TABLE IF NOT EXISTS software_components (
 id TEXT NOT NULL,document_id INTEGER NOT NULL REFERENCES software_documents(id) ON DELETE CASCADE,
 ref TEXT NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,purl TEXT NOT NULL,detail TEXT NOT NULL,
 PRIMARY KEY(document_id,ref));
CREATE INDEX IF NOT EXISTS software_components_search ON software_components(document_id,name);
CREATE TABLE IF NOT EXISTS software_observations (
 id TEXT NOT NULL,document_id INTEGER NOT NULL REFERENCES software_documents(id) ON DELETE CASCADE,
 component_ref TEXT NOT NULL,rule_id TEXT NOT NULL,outcome TEXT NOT NULL,severity TEXT NOT NULL,
 detail TEXT NOT NULL,PRIMARY KEY(document_id,id));
"""


def migrate(conn):
    for statement in SCHEMA.split(";"):
        if statement.strip():
            conn.execute(statement)


def identity(namespace: str, kind: str, name: str) -> str:
    for value in (namespace, name):
        text(value, required=True, maximum=2048)
        if redact_text(value) != value or any(ord(char) < 32 for char in value):
            raise ValueError("Resource identity must not contain credentials or control characters")
    if kind not in {"image", "directory", "file", "software", "host-compliance"}:
        raise ValueError("Unsupported software resource kind")
    return hashlib.sha256(json.dumps([namespace, kind, name], separators=(",", ":")).encode()).hexdigest()


def persist(normalized: dict, *, namespace: str, resource_kind: str, resource_name: str,
            kind: str = "sbom", provenance: dict | None = None) -> int:
    resource_id = identity(namespace, resource_kind, resource_name)
    value = dict(normalized)
    raw = value.pop("raw", b"")
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("Invalid bounded evidence")
    received = value["received_sha256"]
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    if len(encoded.encode()) > 24_000_000:
        raise ValueError("Normalized evidence exceeds budget")
    status = value.get("status", "partial" if value.get("errors") else "complete")
    safe_provenance = dict(provenance or {})
    safe_provenance.update(imported=True, confirmed=False, received_sha256=received,
                           coverage=value.get("coverage", "supplied_evidence"))
    from .engine_store import sanitize
    clean_provenance, _ = sanitize(json.dumps(safe_provenance).encode(), "application/json")
    with db.connect() as conn:
        conn.execute("INSERT OR IGNORE INTO software_resources VALUES(?,?,?,?,?)", (resource_id, namespace, resource_kind, resource_name, db.now()))
        row = conn.execute("INSERT INTO software_documents(resource_id,kind,status,observed_at,created_at,normalized,raw,received_sha256,raw_sha256,provenance) VALUES(?,?,?,?,?,?,?,?,?,?)", (resource_id, kind, status, value.get("observed_at"), db.now(), encoded, raw, received, hashlib.sha256(raw).hexdigest(), clean_provenance.decode()))
        document_id = row.lastrowid
        component_ids = {}
        for item in value.get("components", []):
            component_id = component_identity(resource_id, item)
            component_ids[item["ref"]] = component_id
            conn.execute("INSERT INTO software_components VALUES(?,?,?,?,?,?,?)", (component_id, document_id, item["ref"], item["name"], item["version"], item["purl"], json.dumps(item)))
        occurrences = {}
        for item in value.get("observations", []):
            component_key = component_ids.get(item.get("component_ref", ""), item.get("component_ref", ""))
            # Logical component identity intentionally spans versions and paths.
            # A document retains each concrete reported occurrence separately,
            # including repeated identical matches from its producer.
            occurrence = json.dumps([resource_id,component_key,item],sort_keys=True,separators=(",", ":"))
            ordinal = occurrences.get(occurrence,0)
            occurrences[occurrence] = ordinal + 1
            observation_id = hashlib.sha256(json.dumps([occurrence,ordinal]).encode()).hexdigest()
            conn.execute("INSERT INTO software_observations VALUES(?,?,?,?,?,?,?)", (observation_id, document_id, item.get("component_ref", ""), item["rule_id"], item["outcome"], item.get("severity", "unknown"), json.dumps(item)))
    return int(document_id)


def page(collection: str, *, document_id: int | None = None, resource_id: str | None = None,
         search: str = "", limit: int = 50, offset: int = 0):
    if type(limit) is not int or type(offset) is not int or not 1 <= limit <= 200 or offset < 0:
        raise ValueError("Pagination requires limit 1..200 and nonnegative offset")
    text(search, maximum=256)
    if collection == "documents":
        table = "software_documents d JOIN software_resources r ON r.id=d.resource_id"
        fields = "d.id,d.resource_id,d.kind,d.status,d.observed_at,d.created_at,d.received_sha256,d.raw_sha256,d.provenance,r.name,r.namespace,r.kind resource_kind"
        where = "WHERE (? IS NULL OR d.resource_id=?) AND r.name LIKE ? ESCAPE '\\'"
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params = [resource_id, resource_id, "%" + escaped + "%"]
        order = "d.id DESC"
    elif collection in {"components", "observations"}:
        table = "software_" + collection
        fields = "*"
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        search_field = "name" if collection == "components" else "rule_id"
        where = f"WHERE document_id=? AND {search_field} LIKE ? ESCAPE '\\'"
        params = [document_id, "%" + escaped + "%"]
        order = "id"
    else:
        raise ValueError("Unknown software collection")
    with db.connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM {table} {where}", params).fetchone()[0]
        rows = [dict(row) for row in conn.execute(f"SELECT {fields} FROM {table} {where} ORDER BY {order} LIMIT ? OFFSET ?", (*params, limit, offset))]
    for row in rows:
        for field in ("detail", "provenance"):
            if field in row:
                row[field] = json.loads(row[field])
    return rows, total


def get(document_id: int, *, raw: bool = False):
    with db.connect() as conn:
        row = conn.execute("SELECT d.*,r.name,r.namespace,r.kind resource_kind FROM software_documents d JOIN software_resources r ON r.id=d.resource_id WHERE d.id=?", (document_id,)).fetchone()
    if row is None:
        return None
    value = dict(row)
    if not raw:
        value.pop("raw")
    value["normalized"] = json.loads(value["normalized"])
    value["provenance"] = json.loads(value["provenance"])
    return value
