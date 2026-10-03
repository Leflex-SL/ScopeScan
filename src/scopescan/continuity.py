"""Scoped identity, observation history and conservative assessment deltas.

All mutations operate on their caller's SQLite transaction. Findings are logical
rules at an asset/endpoint/component, not report titles. Legacy namespaces are
isolated until the operator explicitly associates an execution with a scope.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from .models import Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS saved_scopes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, specification TEXT NOT NULL,
 created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assets (
 id TEXT PRIMARY KEY, namespace TEXT NOT NULL, scope_id INTEGER, address TEXT NOT NULL,
 criticality INTEGER NOT NULL DEFAULT 1, latest_at TEXT, latest_scan_id INTEGER,
 latest_snapshot TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS asset_aliases (
 namespace TEXT NOT NULL, address TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES assets(id),
 kind TEXT NOT NULL DEFAULT 'address', actor TEXT NOT NULL DEFAULT 'observation',
 PRIMARY KEY(namespace,address,kind));
CREATE TABLE IF NOT EXISTS asset_observations (
 asset_id TEXT NOT NULL REFERENCES assets(id), scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
 observed_at TEXT NOT NULL, snapshot TEXT NOT NULL, coverage TEXT NOT NULL,
 PRIMARY KEY(asset_id,scan_id));
CREATE TABLE IF NOT EXISTS current_findings (
 id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id), rule_id TEXT NOT NULL,
 source TEXT NOT NULL, port INTEGER, protocol TEXT NOT NULL, component TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, evaluated_at TEXT NOT NULL,
 scan_id INTEGER NOT NULL, lifecycle TEXT NOT NULL DEFAULT 'observed',
 verification_scan_id INTEGER, payload TEXT NOT NULL,
 owner TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open', due_at TEXT,
 exception_until TEXT, closure_evidence TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS finding_observations (
 finding_id TEXT NOT NULL REFERENCES current_findings(id),
 scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
 observed_at TEXT NOT NULL, lifecycle TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(finding_id,scan_id));
CREATE TABLE IF NOT EXISTS remediation_actions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL REFERENCES current_findings(id),
 actor TEXT NOT NULL, created_at TEXT NOT NULL, before_state TEXT NOT NULL,
 after_state TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '', verification_scan_id INTEGER);
CREATE TRIGGER IF NOT EXISTS immutable_remediation_update BEFORE UPDATE ON remediation_actions
 BEGIN SELECT RAISE(ABORT,'immutable action history'); END;
CREATE TRIGGER IF NOT EXISTS immutable_remediation_delete BEFORE DELETE ON remediation_actions
 BEGIN SELECT RAISE(ABORT,'immutable action history'); END;
CREATE TABLE IF NOT EXISTS asset_actions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL REFERENCES assets(id),
 actor TEXT NOT NULL, created_at TEXT NOT NULL, action TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scan_deltas (
 scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE, delta TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrichment_observations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL REFERENCES assets(id),
 scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, observed_at TEXT NOT NULL, snapshot TEXT NOT NULL,
 coverage TEXT NOT NULL, provenance TEXT NOT NULL, findings TEXT NOT NULL);
"""


def timestamp(value: str | int | None = None) -> str:
    if isinstance(value, int) and value > 0:
        date = datetime.fromtimestamp(value, UTC)
    elif isinstance(value, str) and value:
        date = datetime.fromisoformat(value)
        if date.tzinfo is None:
            raise ValueError("Timestamp must include timezone")
    else:
        date = datetime.now(UTC)
    return date.astimezone(UTC).isoformat(timespec="microseconds")


def identity(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()[:32]


def migrate(conn) -> None:
    conn.executescript(SCHEMA)
    for table, additions in {
        "scans": [("scope_id", "INTEGER"), ("execution_context", "TEXT NOT NULL DEFAULT '{}'"),
                  ("coverage", "TEXT NOT NULL DEFAULT '{}'"), ("observed_at", "TEXT"),
                  ("continuity_pending", "TEXT")],
        "findings": [("rule_id", "TEXT NOT NULL DEFAULT ''"),
                     ("component", "TEXT NOT NULL DEFAULT ''"), ("stable_id", "TEXT")],
        "current_findings": [("baseline_coverage", "TEXT NOT NULL DEFAULT '{}'" )],
        "finding_observations": [("coverage", "TEXT NOT NULL DEFAULT '{}'" )],
        "cve_candidates": [("kev_assessed", "INTEGER"), ("kev_checked_at", "TEXT")],
    }.items():
        columns = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, declaration in additions:
            if name not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
    # Migrate only reports with recorded hosts. No inferred scope or coverage.
    for scan in list(conn.execute("SELECT * FROM scans WHERE id NOT IN (SELECT scan_id FROM scan_deltas) AND EXISTS (SELECT 1 FROM hosts WHERE scan_id=scans.id) ORDER BY created_at,id")):
        hosts = []
        for host in conn.execute("SELECT * FROM hosts WHERE scan_id=?", (scan["id"],)):
            ports = [dict(r) for r in conn.execute("SELECT * FROM ports WHERE host_id=?", (host["id"],))]
            hosts.append(dict(dict(host), ports=ports))
        findings = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan["id"],))]
        persist(conn, scan["id"], hosts, findings, {"status": "unknown", "reason": "legacy report"},
                scan["created_at"], success=scan["status"] == "done")


def asset_for(conn, namespace: str, scope_id: int | None, address: str):
    alias = conn.execute("SELECT asset_id FROM asset_aliases WHERE namespace=? AND address=? AND kind='address'", (namespace, address)).fetchone()
    if alias:
        return alias["asset_id"]
    asset_id = identity("asset-v1", namespace, address)
    conn.execute("INSERT OR IGNORE INTO assets(id,namespace,scope_id,address) VALUES(?,?,?,?)", (asset_id, namespace, scope_id, address))
    conn.execute("INSERT OR IGNORE INTO asset_aliases(namespace,address,asset_id) VALUES(?,?,?)", (namespace, address, asset_id))
    return asset_id


def finding_payload(row: dict) -> dict:
    item = dict(row)
    item["cve_ids"] = item.get("cve_ids", json.loads(item.get("cves") or "[]"))
    return item


def protocol_covers(coverage: dict, protocol: str, port: int | None) -> bool:
    if port is None:
        return True
    values = coverage.get("protocols", {}).get(protocol, [])
    if isinstance(values, list):
        return port in values
    if isinstance(values, str):
        for part in values.split(","):
            try:
                low, _, high = part.partition("-")
                if int(low) <= port <= int(high or low):
                    return True
            except ValueError:
                return False
    return False


def can_update_current(previous: dict, incoming: dict) -> bool:
    """External claims cannot replace local current evidence in any state view."""
    return (not previous or previous.get("provenance", "local") != "local"
            or incoming.get("provenance", "local") == "local")


def covered(previous: dict, coverage: dict, host: dict | None, finding: dict | None = None,
            protocol: str = "tcp", port: int | None = None) -> bool:
    if not host or host.get("state") != "up" or host.get("timed_out"):
        return False
    if coverage.get("hosts") and host["address"] not in coverage["hosts"]:
        return False
    if coverage.get("status") != "complete" or previous.get("status") != "complete":
        return False
    for field in ("engine", "engine_version", "rules_version"):
        if not previous.get(field) or previous.get(field) != coverage.get(field):
            return False
    if (previous.get("provenance", "local") != coverage.get("provenance", "local")
            and coverage.get("provenance", "local") != "local"):
        return False
    if finding:
        protocol, port = finding["protocol"], finding["port"]
        last_host = json.loads(finding.get("payload", "{}")).get("host")
        if last_host and last_host not in host.get("addresses", [host["address"]]):
            return False
        if coverage.get("hosts") and last_host and last_host not in coverage["hosts"]:
            return False
    if not protocol_covers(coverage, protocol, port):
        return False
    if finding:
        source = finding["source"]
        if source.startswith("auth:"):
            if source.startswith("auth:linux:ssh-"):
                endpoint = coverage.get("control_endpoints", {}).get(source, {})
                if (endpoint.get("host") != (last_host or host["address"])
                        or endpoint.get("port") != port or endpoint.get("protocol") != protocol):
                    return False
            return (source in coverage.get("rules", [])
                    and coverage.get("controls", {}).get(source) == "pass"
                    and bool(coverage.get("control_evidence", {}).get(source)))
        if source.startswith("nse:"):
            if not any(negative.get("host") == (last_host or host["address"])
                       and negative.get("port") == port and negative.get("protocol") == protocol
                       and negative.get("source") == source and negative.get("evidence", "").strip()
                       for negative in coverage.get("negative_evidence", [])):
                return False
        elif finding["rule_id"] not in coverage.get("rules", []) and source not in coverage.get("rules", []):
            return False
        if port is not None:
            endpoint = next((p for p in host.get("ports", []) if p.get("portid") == port
                             and p.get("protocol") == protocol
                             and p.get("address", host["address"]) == (last_host or host["address"])), None)
            if not endpoint or endpoint.get("state") not in {"open", "closed"}:
                return False
            if source.startswith("rule:") and endpoint.get("state") == "open":
                effective = coverage.get("endpoints", [])
                if effective and not any(e.get("host") == (last_host or host["address"]) and e.get("port") == port
                                         and e.get("protocol") == protocol
                                         and (source in e.get("rules", []) or finding["rule_id"] in e.get("rules", [])) for e in effective):
                    return False
                if source.endswith(("-antiguo", "-backdoor")) and not endpoint.get("version"):
                    return False
            if (endpoint.get("state") == "closed" and source.startswith("rule:")
                    and json.loads(finding.get("payload", "{}")).get("assessment") != "exposure"):
                # Endpoint disappearance establishes exposure removal, not patch installation.
                from .rules import SERVICE_RULES

                if source not in {"rule:" + rule.id for rule in SERVICE_RULES} | {"rule:amt-expuesto"}:
                    return False
    return True


def normal_host(host) -> dict:
    if isinstance(host, dict):
        return dict(host, ports=[dict(p, address=p.get("address", host["address"])) for p in host.get("ports", [])])
    value = asdict(host)
    for port in value["ports"]:
        service = port.pop("service")
        port.update({"service_name": service["name"], "product": service["product"], "version": service["version"]})
        port["address"] = host.address
    return value


def merge_snapshot(previous: dict, host: dict, coverage: dict, scan_id: int) -> dict:
    """Pure endpoint replay; untouched concrete endpoints keep their last evidence."""
    address = host["address"]
    merged = {(p.get("address", previous.get("address", address)), p["protocol"], p["portid"]): dict(p, current_assessment="not_assessed")
              for p in previous.get("ports", [])}
    for port in host.get("ports", []):
        key = (port.get("address", address), port["protocol"], port["portid"])
        old_port = merged.get(key, {})
        value = dict(port, current_assessment="observed",
                     network_scan_id=scan_id if coverage.get("engine") == "nmap" else old_port.get("network_scan_id"))
        if coverage.get("engine") != "nmap":
            for field in ("service_name", "product", "version", "cpes"):
                if not value.get(field) and old_port.get(field):
                    value[field] = old_port[field]
        merged[key] = value
    return dict(host, coverage=coverage, ports=list(merged.values()))


def persist(conn, scan_id: int, hosts: list, findings: list, coverage: dict,
            observed_at: str | int | None, *, success: bool,
            prefer_observed_at: bool = False) -> None:
    scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    context = json.loads(scan["execution_context"] or "{}")
    namespace = context.get("namespace") or (f"scope:{scan['scope_id']}" if scan["scope_id"] is not None else f"scan:{scan_id}")
    stamp = timestamp((observed_at if prefer_observed_at else context.get("observed_at")) or observed_at or scan["created_at"])
    coverage = dict(coverage)
    if not success:
        coverage["status"] = "partial"
    conn.execute("UPDATE scans SET coverage=?,observed_at=? WHERE id=?", (json.dumps(coverage), stamp, scan_id))
    delta = {"hosts": [], "ports": [], "services": [], "findings": [], "coverage": coverage,
             "warnings": [], "observed_at": stamp, "namespace": namespace}
    if coverage.get("status") != "complete":
        delta["warnings"].append("Incomplete or unknown coverage: absence is not evidence of remediation.")
    by_address = {}
    for raw_host in hosts:
        host = normal_host(raw_host)
        aid = asset_for(conn, namespace, scan["scope_id"], host["address"])
        if aid in by_address:
            combined = by_address[aid]
            combined["addresses"].append(host["address"])
            combined["ports"].extend(host.get("ports", []))
            combined["hostscripts"].extend(host.get("hostscripts", []))
            combined["timed_out"] = combined.get("timed_out", False) or host.get("timed_out", False)
        else:
            by_address[aid] = dict(host, addresses=[host["address"]],
                                   hostscripts=list(host.get("hostscripts", [])))
    seen_assets = set()
    for aid, host in by_address.items():
        address = host["address"]
        seen_assets.add(aid)
        old_asset = conn.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        previous = json.loads(old_asset["latest_snapshot"])
        prior_coverage = previous.get("coverage", {})
        fresh = old_asset["latest_at"] is None or stamp >= old_asset["latest_at"]
        conn.execute("INSERT OR REPLACE INTO asset_observations VALUES(?,?,?,?,?)", (aid, scan_id, stamp, json.dumps(host), json.dumps(coverage)))
        delta["hosts"].append({"asset_id": aid, "host": address, "change": "persistent" if previous else "new"})
        before = {(p.get("address", previous.get("address", address)), p["protocol"], p["portid"]): p for p in previous.get("ports", []) if p.get("state") == "open"}
        after = {(p.get("address", address), p["protocol"], p["portid"]): p for p in host.get("ports", []) if p.get("state") == "open"}
        for endpoint in before.keys() | after.keys():
            state = "new" if endpoint not in before else "persistent"
            if endpoint not in after:
                explicit = next((p for p in host.get("ports", []) if (p.get("address", address), p["protocol"], p["portid"]) == endpoint), {})
                baseline = prior_coverage
                if before[endpoint].get("network_scan_id"):
                    prior_scan = conn.execute("SELECT coverage FROM scans WHERE id=?", (before[endpoint]["network_scan_id"],)).fetchone()
                    if prior_scan:
                        baseline = json.loads(prior_scan[0])
                state = "closed" if explicit.get("state") == "closed" and covered(baseline, coverage, host, protocol=endpoint[1], port=endpoint[2]) else "not_assessed"
            delta["ports"].append({"asset_id": aid, "host": endpoint[0], "protocol": endpoint[1], "port": endpoint[2], "change": state})
            if endpoint in before and endpoint in after and coverage.get("engine") == "nmap":
                fields = ("service_name", "product", "version")
                if any(before[endpoint].get(f) != after[endpoint].get(f) for f in fields):
                    delta["services"].append({"asset_id": aid, "host": endpoint[0], "protocol": endpoint[1], "port": endpoint[2], "change": "changed", "before": {f: before[endpoint].get(f) for f in fields}, "after": {f: after[endpoint].get(f) for f in fields}})
        if fresh and success and can_update_current(prior_coverage, coverage):
            snapshot = merge_snapshot(previous, host, coverage, scan_id)
            conn.execute("UPDATE assets SET latest_at=?,latest_scan_id=?,latest_snapshot=?,address=? WHERE id=?", (stamp, scan_id, json.dumps(snapshot), address, aid))
        elif not fresh:
            delta["warnings"].append("Historical report retained without replacing newer current state.")
        observed_ids = set()
        for raw in findings:
            item = finding_payload(dict(raw) if isinstance(raw, dict) else asdict(raw))
            if item["host"] not in host["addresses"]:
                continue
            if "sources" in coverage and item["source"] not in coverage["sources"]:
                continue
            rule = item.get("rule_id") or item["source"]
            component = item.get("component", "")
            fid = identity("finding-v1", aid, item["source"], rule, item["host"], item.get("protocol", "tcp"), item.get("port"), component)
            observed_ids.add(fid)
            current = conn.execute("SELECT * FROM current_findings WHERE id=?", (fid,)).fetchone()
            protected = bool(current and not can_update_current(json.loads(current["baseline_coverage"]), coverage))
            item.update(id=fid, asset_id=aid, rule_id=rule)
            payload = json.dumps(item)
            if current is None:
                conn.execute("INSERT INTO current_findings(id,asset_id,rule_id,source,port,protocol,component,first_seen,last_seen,evaluated_at,scan_id,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (fid, aid, rule, item["source"], item.get("port"), item.get("protocol", "tcp"), component, stamp, stamp, stamp, scan_id, payload))
            elif stamp >= current["evaluated_at"] and not protected and scan["status"] in {"done", "failed", "cancelled"}:
                conn.execute("UPDATE current_findings SET payload=?,last_seen=?,evaluated_at=?,scan_id=?,lifecycle='observed',verification_scan_id=NULL,status=CASE WHEN status='closed' THEN 'open' ELSE status END WHERE id=?", (payload, stamp, stamp, scan_id, fid))
            if (current is None or stamp >= current["evaluated_at"] and not protected
                    and scan["status"] in {"done", "failed", "cancelled"}):
                conn.execute("UPDATE current_findings SET baseline_coverage=? WHERE id=?", (json.dumps(coverage), fid))
            conn.execute("INSERT OR REPLACE INTO finding_observations(finding_id,scan_id,observed_at,lifecycle,payload,coverage) VALUES(?,?,?,?,?,?)", (fid, scan_id, stamp, "observed", payload, json.dumps(coverage)))
            if item.get("id") and raw and isinstance(raw, dict) and isinstance(raw.get("id"), int):
                conn.execute("UPDATE findings SET stable_id=?,rule_id=?,component=? WHERE id=?", (fid, rule, component, raw["id"]))
            else:
                conn.execute("UPDATE findings SET stable_id=?,rule_id=?,component=? WHERE scan_id=? AND host=? AND source=? AND protocol=? AND port IS ? AND (rule_id='' OR rule_id=?) AND component=?", (fid, rule, component, scan_id, address, item["source"], item.get("protocol", "tcp"), item.get("port"), rule, component))
            delta["findings"].append({"id": fid, "asset_id": aid, "change": "persistent" if current else "new"})
        for current in list(conn.execute("SELECT * FROM current_findings WHERE asset_id=?", (aid,))):
            if current["id"] in observed_ids or current["lifecycle"] == "resolved":
                continue
            if "sources" in coverage and current["source"] not in coverage["sources"]:
                continue
            baseline = json.loads(current["baseline_coverage"])
            protected = not can_update_current(baseline, coverage)
            lifecycle = "resolved" if success and covered(baseline, coverage, host, dict(current)) else "not_assessed"
            delta["findings"].append({"id": current["id"], "asset_id": aid, "change": lifecycle})
            conn.execute("INSERT OR REPLACE INTO finding_observations(finding_id,scan_id,observed_at,lifecycle,payload,coverage) VALUES(?,?,?,?,?,?)", (current["id"], scan_id, stamp, lifecycle, current["payload"], json.dumps(coverage)))
            if stamp >= current["evaluated_at"] and not protected and scan["status"] in {"done", "failed", "cancelled"}:
                conn.execute("UPDATE current_findings SET lifecycle=?,evaluated_at=?,verification_scan_id=? WHERE id=?", (lifecycle, stamp, scan_id if lifecycle == "resolved" else None, current["id"]))
    for asset in conn.execute("SELECT * FROM assets WHERE namespace=?", (namespace,)):
        if asset["id"] in seen_assets:
            continue
        delta["hosts"].append({"asset_id": asset["id"], "host": asset["address"], "change": "not_assessed"})
        for current in conn.execute("SELECT * FROM current_findings WHERE asset_id=? AND lifecycle!='resolved'", (asset["id"],)):
            if "sources" in coverage and current["source"] not in coverage["sources"]:
                continue
            delta["findings"].append({"id": current["id"], "asset_id": asset["id"], "change": "not_assessed"})
            if (stamp >= current["evaluated_at"] and scan["status"] in {"done", "failed", "cancelled"}
                    and can_update_current(json.loads(current["baseline_coverage"]), coverage)):
                conn.execute("UPDATE current_findings SET lifecycle='not_assessed',evaluated_at=?,verification_scan_id=NULL WHERE id=?", (stamp, current["id"]))
    conn.execute("INSERT OR REPLACE INTO scan_deltas VALUES(?,?)", (scan_id, json.dumps(delta)))


def reconcile(conn, scan_id: int) -> None:
    """Terminal process status, not XML alone, permits negative evidence."""
    scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan or not scan["continuity_pending"]:
        return
    pending = json.loads(scan["continuity_pending"])
    persist(conn, scan_id, pending["hosts"], pending["findings"], pending["coverage"],
            pending["observed_at"], success=scan["status"] == "done" and pending["success"])


def sync_enrichment(conn, scan_id: int, host_address: str | None = None,
                    coverage: dict | None = None) -> None:
    """Authenticated/feed observations share identities, never invent negative checks."""
    scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if scan is None:
        return
    pending = json.loads(scan["continuity_pending"] or "{}")
    context = json.loads(scan["execution_context"] or "{}")
    hosts = pending.get("hosts", [])
    addresses = {h["address"] for h in hosts}
    if host_address and host_address not in addresses:
        hosts.append({"address": host_address, "state": "up", "ports": []})
    if host_address:
        hosts = [h for h in hosts if h["address"] == host_address]
    findings = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))]
    for candidate in conn.execute("SELECT * FROM cve_candidates WHERE scan_id=?", (scan_id,)):
        # Stable product identity discards observed version in CPE 2.2/2.3.
        cpe = candidate["detected_cpe"].split(":")
        component = ":".join(cpe[:5] if cpe[:2] == ["cpe", "2.3"] else cpe[:4])
        score = candidate["cvss"]
        findings.append({"host": candidate["host"], "port": candidate["port"],
                         "protocol": candidate["protocol"], "title": candidate["cve_id"],
                         "source": "nvd:" + candidate["cve_id"], "rule_id": candidate["cve_id"],
                         "component": component, "severity": int(Severity.from_cvss(score)) if score is not None else 2,
                         "assessment": "candidate", "confirmed": False,
                         "cve_ids": [candidate["cve_id"]], "evidence": candidate["matched_criteria"],
                         "description": candidate["summary"], "remediation": "Verify applicability and vendor advisory"})
    cov = coverage or {"status": "unknown", "reason": "Enrichment contains no explicit negative coverage"}
    if host_address:
        inventory_row = conn.execute("SELECT data FROM host_inventory WHERE scan_id=? AND host=?", (scan_id, host_address)).fetchone()
        if inventory_row and coverage is None:
            from .verification import authenticated_coverage

            inventory = json.loads(inventory_row[0])
            host = next((h for h in hosts if h["address"] == host_address), {})
            open_ports = {p["portid"] for p in host.get("ports", []) if p["protocol"] == "tcp" and p.get("state") == "open"}
            cov = authenticated_coverage(inventory.get("platform", "windows"), inventory, open_ports, host=host_address)
            cov["sources"] = [f["source"] for f in findings if f["source"].startswith("auth:")] + list(cov.get("controls", {}))
    else:
        cov["sources"] = [f["source"] for f in findings if f["source"].startswith("nvd:")]
    provenance = context.get("provenance", {})
    imported = isinstance(provenance, dict) and provenance.get("imported")
    stamp = timestamp(context.get("observed_at") if imported else None)
    old_observations = [dict(r) for r in conn.execute("SELECT * FROM asset_observations WHERE scan_id=?", (scan_id,))]
    old_delta = conn.execute("SELECT delta FROM scan_deltas WHERE scan_id=?", (scan_id,)).fetchone()
    persist(conn, scan_id, hosts, findings, cov, stamp, success=scan["status"] == "done", prefer_observed_at=True)
    for observation in conn.execute("SELECT * FROM asset_observations WHERE scan_id=?", (scan_id,)).fetchall():
        relevant = [f for f in findings if f["source"] in cov.get("sources", [])]
        conn.execute("INSERT INTO enrichment_observations(asset_id,scan_id,kind,observed_at,snapshot,coverage,provenance,findings) VALUES(?,?,?,?,?,?,?,?)", (observation["asset_id"], scan_id, cov.get("engine", "nvd"), stamp, observation["snapshot"], json.dumps(cov), json.dumps(provenance), json.dumps(relevant)))
    conn.execute("DELETE FROM asset_observations WHERE scan_id=?", (scan_id,))
    for observation in old_observations:
        conn.execute("INSERT INTO asset_observations VALUES(?,?,?,?,?)", tuple(observation[k] for k in ("asset_id", "scan_id", "observed_at", "snapshot", "coverage")))
    conn.execute("UPDATE scans SET coverage=?,observed_at=? WHERE id=?", (scan["coverage"], scan["observed_at"], scan_id))
    if old_delta:
        conn.execute("UPDATE scan_deltas SET delta=? WHERE scan_id=?", (old_delta[0], scan_id))


def current_item(row) -> dict:
    item = json.loads(row["payload"])
    item.update({key: row[key] for key in ("id", "asset_id", "owner", "status", "due_at", "exception_until", "closure_evidence", "lifecycle", "verification_scan_id", "scan_id", "first_seen", "last_seen", "evaluated_at")})
    item["exception_expired"] = bool(item["status"] == "exception" and item["exception_until"] and timestamp(item["exception_until"]) <= timestamp())
    return item


def after_scan_deletion(conn, scan_id: int) -> None:
    """Rebuild current evidence from surviving reports; retain immutable audits."""
    for asset in list(conn.execute("""SELECT * FROM assets a WHERE latest_scan_id=? OR EXISTS (
            SELECT 1 FROM json_each(a.latest_snapshot,'$.ports') p
            WHERE json_extract(p.value,'$.network_scan_id')=?)""", (scan_id, scan_id))):
        observations = conn.execute("""SELECT o.* FROM (
            SELECT asset_id,scan_id,observed_at,snapshot,coverage FROM asset_observations
            UNION ALL SELECT asset_id,scan_id,observed_at,snapshot,coverage FROM enrichment_observations)
            o JOIN scans s ON s.id=o.scan_id WHERE asset_id=? AND s.status='done'
            ORDER BY observed_at,scan_id""", (asset["id"],)).fetchall()
        snapshot, latest = {}, None
        for observation in observations:
            coverage = json.loads(observation["coverage"])
            if not can_update_current(snapshot.get("coverage", {}), coverage):
                continue
            snapshot = merge_snapshot(snapshot, normal_host(json.loads(observation["snapshot"])), coverage, observation["scan_id"])
            latest = observation
        if latest:
            conn.execute("UPDATE assets SET latest_scan_id=?,latest_at=?,latest_snapshot=?,address=? WHERE id=?", (latest["scan_id"], latest["observed_at"], json.dumps(snapshot), snapshot["address"], asset["id"]))
        else:
            conn.execute("UPDATE assets SET latest_scan_id=NULL,latest_at=NULL,latest_snapshot='{}' WHERE id=?", (asset["id"],))
    for current in list(conn.execute("SELECT * FROM current_findings WHERE scan_id=? OR verification_scan_id=?", (scan_id, scan_id))):
        positive = conn.execute("""SELECT * FROM finding_observations WHERE finding_id=? AND lifecycle='observed'
            ORDER BY CASE WHEN COALESCE(json_extract(coverage,'$.provenance'),'local')='local' THEN 1 ELSE 0 END DESC,
            observed_at DESC,scan_id DESC LIMIT 1""", (current["id"],)).fetchone()
        if positive:
            # Deleted closure cannot retain a positive proof. Restore last positive.
            conn.execute("UPDATE current_findings SET payload=?,scan_id=?,last_seen=?,evaluated_at=?,baseline_coverage=?,lifecycle='observed',verification_scan_id=NULL,status=CASE WHEN status='closed' THEN 'open' ELSE status END,closure_evidence='' WHERE id=?", (positive["payload"], positive["scan_id"], positive["observed_at"], positive["observed_at"], positive["coverage"], current["id"]))
        else:
            payload = json.loads(current["payload"])
            for field in ("evidence", "description", "remediation"):
                payload[field] = ""
            payload["title"] = current["rule_id"] + " (report evidence deleted)"
            conn.execute("UPDATE current_findings SET payload=?,scan_id=0,lifecycle='evidence_unavailable',verification_scan_id=NULL,closure_evidence='',baseline_coverage='{}' WHERE id=?", (json.dumps(payload), current["id"]))
