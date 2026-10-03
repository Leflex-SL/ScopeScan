"""Versioned engine evidence and conservative continuity reconciliation."""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, replace
from datetime import datetime

from . import db
from .engine_contracts import EnginePlan, EngineResult
from .models import Assessment, Host, NmapRun, Port, Service, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS engine_results (
 id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
 engine TEXT NOT NULL,status TEXT NOT NULL,plan TEXT NOT NULL,plan_hash TEXT NOT NULL,
 provenance TEXT NOT NULL,normalized TEXT NOT NULL,raw BLOB NOT NULL,raw_sha256 TEXT NOT NULL,
 received_sha256 TEXT NOT NULL,redactions TEXT NOT NULL,raw_media_type TEXT NOT NULL,
 errors TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS engine_results_scan ON engine_results(scan_id,id);
"""

_SECRET = re.compile(r"(?:password|passwd|token|secret|authorization|cookie|private.?key|credential|client.?certificate)", re.IGNORECASE)
_URI_USERINFO = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://|(?<![\w:])//)[^\s/?#]*(?:@|%40)")


def redact_text(value: str) -> str:
    value = _URI_USERINFO.sub(r"\1",value)
    value = re.sub(r"(?im)^(authorization|proxy-authorization|set-cookie|cookie):[^\r\n]*", r"\1: [redacted]", value)
    return re.sub(r"(?i)(\b(?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*)[^\s&;,]+",r"\1[redacted]",value)


def migrate(conn):
    conn.executescript(SCHEMA)
    for table, additions in {
        "cve_candidates": {"cvss_version": "TEXT", "cvss_metrics": "TEXT", "feed_fetched_at": "TEXT", "feed_stale": "INTEGER", "feed_error": "TEXT", "feed_schema": "TEXT", "feed_provider": "TEXT"},
        "windows_patch_status": {"provider": "TEXT", "api_version": "TEXT", "schema_version": "TEXT", "coverage_description": "TEXT"},
    }.items():
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, kind in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {kind}")


def sanitize(raw: bytes, media_type: str) -> tuple[bytes, list[str]]:
    """Keep evidence but remove credential-bearing JSON fields and HTTP headers."""
    redactions = []
    def clean(value, path=""):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                safe_key = redact_text(key)
                if safe_key != key:
                    redactions.append("URI userinfo removed from JSON key")
                if _SECRET.search(key) or key.lower() in {"config", "configuration"}:
                    result[safe_key] = "[redacted]"
                    redactions.append(path + safe_key)
                else:
                    result[safe_key] = clean(item, path + safe_key + ".")
            return result
        if isinstance(value, list):
            return [clean(item, path) for item in value]
        if isinstance(value, str):
            cleaned = redact_text(value)
            if cleaned != value:
                redactions.append(path + "credential-bearing text redacted")
            return cleaned
        return value
    if not raw:
        return b"", redactions
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        # JSONL is the Nuclei protocol; arbitrary opaque raw can contain credentials.
        try:
            lines = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except (ValueError, UnicodeError):
            redactions.append("opaque evidence omitted; normalized evidence retained")
            return b"", redactions
        return b"\n".join(json.dumps(clean(line), ensure_ascii=True).encode() for line in lines), redactions
    return json.dumps(clean(value), ensure_ascii=True).encode(), redactions


def endpoint_condition(endpoint) -> str:
    """Logical application identity includes virtual host and transport semantics."""
    label = endpoint.service.lower()
    if label in {"https", "https-alt", "ssl/http", "http-ssl", "tls/http"}:
        label = "https"
    elif label in {"http", "http-alt", "http-proxy", "www"}:
        label = "http"
    elif label in {"ssl", "tls"}:
        label = "tls"
    identity = {"host":endpoint.host,"port":endpoint.port,"protocol":endpoint.protocol,
                "hostname":endpoint.hostname.lower() or endpoint.host,"service":label}
    return hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()


def validate(plan: EnginePlan, result: EngineResult) -> None:
    if result.engine != plan.engine:
        raise ValueError("Result engine differs from its plan")
    if len(result.raw) > plan.max_output_bytes:
        raise ValueError("Engine evidence exceeds plan limit")
    seen = set()
    for item in result.observations:
        if (item.outcome == "positive") != (item.finding is not None):
            raise ValueError("Only positive observations may contain a Finding")
        if item.endpoint not in plan.endpoints or item.rule_id not in plan.rules:
            raise ValueError("Engine observation escapes planned endpoint/rule")
        key = (item.endpoint, item.rule_id)
        if key in seen:
            raise ValueError("Conflicting or duplicate endpoint/rule observation")
        seen.add(key)
        if item.finding and (item.finding.rule_id != item.rule_id or item.finding.host != item.endpoint.host or item.finding.port != item.endpoint.port or item.finding.protocol != item.endpoint.protocol):
            raise ValueError("Mutable Finding no longer matches its observation")
        if item.finding:
            finding = item.finding
            if not isinstance(finding.severity, Severity) or not isinstance(finding.assessment, Assessment) or type(finding.confirmed) is not bool:
                raise ValueError("Invalid normalized Finding severity/assessment")
            if finding.cvss is not None and (type(finding.cvss) not in (int,float) or not math.isfinite(finding.cvss) or not 0<=finding.cvss<=10):
                raise ValueError("Invalid normalized Finding CVSS")
            if any(not isinstance(getattr(finding,key),str) for key in ("evidence","description","title","remediation","component","source","rule_id","service")):
                raise ValueError("Invalid normalized Finding text")


def persist(plan: EnginePlan, result: EngineResult, *, scan_id: int | None = None) -> int:
    validate(plan, result)
    grant_json = json.dumps(asdict(plan))
    if _URI_USERINFO.search(grant_json):
        raise ValueError("Execution grants cannot contain URI credentials; configure identities outside the plan")
    original_provenance = result.provenance
    safe_provenance = replace(original_provenance,
        engine_version=redact_text(original_provenance.engine_version),
        rules_version=redact_text(original_provenance.rules_version),source=redact_text(original_provenance.source),
        templates=tuple((redact_text(key),redact_text(value)) for key,value in original_provenance.templates),
        feeds=tuple((redact_text(key),redact_text(value)) for key,value in original_provenance.feeds))
    result = replace(result,provenance=safe_provenance)
    raw, redactions = sanitize(result.raw, result.raw_media_type)
    if original_provenance != safe_provenance:
        redactions.append("Credential-bearing provenance text redacted")
    if len(raw)>8_000_000:
        raise ValueError("Sanitized engine evidence exceeds 8 MB")
    imported = result.provenance.imported
    observations = []
    findings = []
    negatives = []
    assessed_endpoints = []
    hosts = {}
    for item in result.observations:
        source = f"engine:{plan.engine}:{item.rule_id}"
        finding = item.finding
        condition = endpoint_condition(item.endpoint)
        assessed_endpoints.append({"host":item.endpoint.host,"port":item.endpoint.port,"protocol":item.endpoint.protocol,"source":source,"condition":condition})
        if finding:
            finding = replace(finding, source=source, rule_id=item.rule_id,
                              component=redact_text(finding.component)+"::endpoint-v1:"+condition,service=redact_text(finding.service),
                              evidence=redact_text(finding.evidence),description=redact_text(finding.description),title=redact_text(finding.title),remediation=redact_text(finding.remediation),
                              assessment=Assessment.CANDIDATE if imported else finding.assessment,
                              confirmed=False if imported else finding.confirmed)
            findings.append(finding)
            if any(redact_text(getattr(item.finding,key)) != getattr(item.finding,key) for key in ("evidence","description","title","remediation","component","service")):
                redactions.append("Credential-bearing normalized Finding text redacted")
        data = asdict(item)
        data["evidence"] = redact_text(item.evidence)
        if data["evidence"] != item.evidence:
            redactions.append("Credential-bearing observation text redacted")
        if finding:
            data["finding"] = asdict(finding)
        data["condition"] = condition
        observations.append(data)
        endpoint = item.endpoint
        host = hosts.setdefault(endpoint.host, Host(endpoint.host, state="unknown"))
        if item.outcome in {"positive", "negative"}:
            host.state = "up"
        if item.outcome != "unknown" and endpoint.port is not None and not any(p.portid == endpoint.port and p.protocol == endpoint.protocol for p in host.ports):
            host.ports.append(Port(endpoint.port, endpoint.protocol, "open", service=Service(endpoint.service)))
        if item.outcome == "negative" and result.status == "complete" and not imported:
            negatives.append({"host": endpoint.host,"port": endpoint.port,"protocol": endpoint.protocol,"source":source,"condition":condition,"evidence":redact_text(item.evidence)})
    coverage = {"engine": plan.engine, "engine_version":result.provenance.engine_version,
        "rules_version":result.provenance.rules_version,"status": "complete" if result.status == "complete" else "partial",
        "provenance": "imported:"+result.provenance.source if imported else "local",
        "hosts":list(hosts),"protocols":{proto: sorted({e.port for e in plan.endpoints if e.protocol==proto}) for proto in {e.protocol for e in plan.endpoints}},
        "rules": list(plan.rules),"sources":[f"engine:{plan.engine}:{rule}" for rule in plan.rules],"negative_evidence":negatives}
    coverage["endpoints"] = assessed_endpoints
    coverage["templates"] = sorted(result.provenance.templates)
    coverage["feeds"] = sorted(result.provenance.feeds)
    coverage["evidence_version"] = hashlib.sha256(json.dumps({key:coverage[key] for key in ("engine_version","rules_version","templates","feeds")},sort_keys=True).encode()).hexdigest()
    normalized = json.dumps(observations, ensure_ascii=True)
    if len(normalized.encode()) > 8_000_000 or len(json.dumps(asdict(plan)).encode()) > 2_000_000:
        raise ValueError("Normalized engine evidence or execution grant exceeds bounds")
    if len(json.dumps(asdict(result.provenance)).encode())>1_000_000 or len(json.dumps(result.errors).encode())>1_000_000:
        raise ValueError("Engine provenance/errors exceed 1 MB")
    errors = tuple(redact_text(error) for error in result.errors)
    observed_stamps = {item.observed_at for item in result.observations}
    if imported and len(observed_stamps) > 1:
        raise ValueError("Imported evidence with mixed observation times requires separate results")
    observed_at = max((datetime.fromisoformat(stamp) for stamp in observed_stamps),default=None)
    if observed_at is None and (result.finished_at or result.started_at):
        observed_at = datetime.fromisoformat(result.finished_at or result.started_at)
    if scan_id is None:
        scan_id = db.create_scan(name=f"{plan.engine} assessment", targets=" ".join(sorted({e.host for e in plan.endpoints})),
            profile=plan.engine, authorized_by=plan.scope.authorized_by, scope_id=plan.scope.scope_id,
            execution_context={"namespace": plan.scope.namespace, "engine_plan": asdict(plan)})
    row = db.get_scan(scan_id)
    if row is None or row["deletion_pending"]:
        raise ValueError("Evidence scan is missing or pending deletion")
    context = json.loads(row["execution_context"] or "{}")
    if json.dumps(context.get("engine_plan"), sort_keys=True) != json.dumps(asdict(plan), sort_keys=True):
        raise ValueError("Engine result does not match stored execution grant")
    db.set_status(scan_id,"running")
    run = NmapRun(hosts=list(hosts.values()), hosts_up=sum(host.is_up for host in hosts.values()), hosts_total=len(hosts),
        start=int(observed_at.timestamp()) if observed_at else 0,
        scanner_version=result.provenance.engine_version,exit_status="success" if result.status=="complete" else "error",
        coverage=coverage,provenance=asdict(result.provenance))
    db.save_results(scan_id,run,findings,max((int(f.severity) for f in findings),default=0))
    with db.connect() as conn:
        conn.execute("INSERT INTO engine_results(scan_id,engine,status,plan,plan_hash,provenance,normalized,raw,raw_sha256,received_sha256,redactions,raw_media_type,errors,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id,plan.engine,result.status,json.dumps(asdict(plan)),plan.fingerprint,json.dumps(asdict(result.provenance)),normalized,raw,
            hashlib.sha256(raw).hexdigest(),hashlib.sha256(result.raw).hexdigest(),json.dumps(redactions),result.raw_media_type,json.dumps(errors),db.now()))
    db.set_status(scan_id,"done" if result.status=="complete" else "cancelled" if result.status=="cancelled" else "failed",error="; ".join(errors))
    return scan_id


def list_results(*, scan_id: int | None = None, limit: int = 50, offset: int = 0):
    limit = max(1,min(100,limit))
    offset = max(0,offset)
    with db.connect() as conn:
        where,args = (" WHERE scan_id=?",[scan_id]) if scan_id is not None else ("",[])
        total = conn.execute("SELECT COUNT(*) FROM engine_results"+where,args).fetchone()[0]
        rows = conn.execute("SELECT id,scan_id,engine,status,provenance,plan_hash,raw_sha256,errors,created_at FROM engine_results"+where+" ORDER BY id DESC LIMIT ? OFFSET ?",[*args,limit,offset]).fetchall()
    return [dict(row,provenance=json.loads(row["provenance"]),errors=json.loads(row["errors"])) for row in rows],total


def get_result(result_id: int, *, include_raw: bool = False):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM engine_results WHERE id=?",(result_id,)).fetchone()
    if row is None:
        raise ValueError("Engine evidence does not exist")
    data = dict(row)
    raw = data.pop("raw")
    for key in ("plan","provenance","normalized","redactions","errors"):
        data[key] = json.loads(data[key])
    if include_raw:
        data["raw"] = raw.decode("utf-8",errors="replace")
    return data
