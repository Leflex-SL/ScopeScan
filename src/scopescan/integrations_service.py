"""Connector orchestration: web requests enqueue, worker handlers perform I/O."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from . import analysis, db, defectdojo, durable_jobs, faraday, greenbone, integrations_store
from .engine_store import sanitize
from .importers import _host, _records, _text, _timestamp
from .models import Assessment, Finding, Host, NmapRun, Port, Service, Severity


def import_evidence(kind, payload, *, scope_id, destination_id=None):
    if kind not in {"faraday", "greenbone"}:
        raise ValueError("Import kind must be faraday or greenbone")
    saved = db.get_scope(scope_id)
    if saved is None or not saved["authorized_by"]:
        raise ValueError("Choose a saved authorized scope before importing")
    normalized = faraday.normalize(payload) if kind == "faraday" else greenbone.normalize(payload)
    if destination_id is not None:
        destination = integrations_store.get_destination(destination_id)
        if destination["kind"] != kind:
            raise ValueError("Import destination kind does not match")
        # Server responses must never retain worker credentials, even in free text.
        from .destinations import credential
        secrets = [credential(destination, key) for key in ("password_env",) if key in destination["settings"]]
        from ._integration_http import redact_known
        normalized = redact_known(normalized, *secrets)
    observed_at = _timestamp(normalized["observed_at"])
    hosts, findings, endpoint_count = {}, [], 0
    for record in _records(normalized["hosts"]):
        address = _host(record["address"])
        if address not in saved["pinned_targets"]:
            raise ValueError("Imported address is outside the saved pinned scope; select an appropriate scope")
        host = hosts.setdefault(address, Host(address=address, addrtype="ipv6" if ":" in address else "ipv4", state="unknown"))
        for endpoint in _records(record.get("ports", [])):
            port, protocol = endpoint["port"], endpoint["protocol"]
            if type(port) is not int or not 1 <= port <= 65535 or protocol not in {"tcp", "udp", "sctp"}:
                raise ValueError("Imported service endpoint is invalid")
            endpoint_count += 1
            if endpoint_count > 10000:
                raise ValueError("Imported services exceed 10000 endpoints")
            service = endpoint.get("service", {})
            host.ports.append(Port(portid=port, protocol=protocol, state="unknown", service=Service(name=_text(service.get("name", ""), limit=1024), version=_text(service.get("version", ""), limit=1024))))
    for record in _records(normalized["findings"]):
        address, port, protocol = _host(record["host"]), record.get("port"), record["protocol"]
        if address not in hosts or (port is not None and (type(port) is not int or not 1 <= port <= 65535)) or protocol not in {"tcp", "udp", "sctp", "host"}:
            raise ValueError("Imported finding endpoint is invalid")
        cves = [_text(value, limit=64) for value in _records(record.get("cve_ids", []))]
        rule = _text(record["rule_id"], limit=160)
        findings.append(Finding(title=_text(record["title"], limit=1024), severity=Severity[record["severity"].upper()], source="external:" + rule,
            host=address, port=port, protocol=protocol, rule_id=rule, confirmed=False, assessment=Assessment.CANDIDATE,
            description=_text(record.get("description", "")), evidence="[External claim; not locally verified] " + _text(record.get("evidence", "")),
            remediation=_text(record.get("remediation", "")), cve_ids=cves, cvss=record.get("cvss")))
    if not hosts:
        # Empty evidence is still a viewable import; it cannot create absence/closure.
        import_id = integrations_store.store_import(kind, payload, normalized, scope_id=scope_id, destination_id=destination_id)
        return {"import_id": import_id, "scan_id": None, "status": "partial", "error": "Report has no concrete observed hosts; evidence retained without local reconciliation"}
    safe, _ = sanitize(json.dumps(normalized, ensure_ascii=True, allow_nan=False).encode(), "application/json")
    if len(safe) > 8_000_000:
        raise ValueError("Normalized evidence exceeds 8 MB; use smaller reports")
    normalized = json.loads(safe)
    run = NmapRun(scanner_version=normalized["engine_version"], start=int(datetime.fromisoformat(observed_at).timestamp()),
        exit_status="success", hosts=list(hosts.values()), hosts_total=len(hosts), hosts_up=0)
    run.coverage = {"status": "partial", "engine": kind, "engine_version": normalized["engine_version"], "rules_version": "external-import-v1",
        "provenance": "external", "hosts": sorted(hosts), "protocols": {}, "rules": []}
    run.provenance = {"imported": True, "engine": kind, "engine_version": normalized["engine_version"], "observed_at": observed_at,
        "source_timestamp": observed_at, "sha256": hashlib.sha256(payload).hexdigest(), "claim_status": "external_unverified", "coverage_description": normalized["coverage"]}
    from .importers import _copy_raw
    raw_path, _ = _copy_raw(safe, ".json")
    run.provenance["raw_path"] = str(raw_path)
    scan_id = db.create_scan(name=f"Imported {kind} evidence", targets=" ".join(hosts), profile="imported", authorized_by=saved["authorized_by"], scope_id=scope_id,
        execution_context={"namespace": f"scope:{scope_id}", "observed_at": observed_at, "coverage": run.coverage, "provenance": run.provenance})
    db.set_nmap_args(scan_id, "", str(raw_path))
    db.save_results(scan_id, run, findings, analysis.risk_score(findings))
    db.set_status(scan_id, "done")
    db.set_progress(scan_id, 100, "External candidates imported; no local negative proof")
    import_id = integrations_store.store_import(kind, payload, normalized, scope_id=scope_id, scan_id=scan_id, destination_id=destination_id)
    return {"import_id": import_id, "scan_id": scan_id, "status": "partial" if normalized["status"] == "partial" else "done", "error": "; ".join(normalized.get("errors", []))[:2000]}


def enqueue_delivery(destination_id, scan_id, *, engagement_id=None, test_id=None):
    destination = integrations_store.get_destination(destination_id)
    if destination["kind"] != "defectdojo":
        raise ValueError("Only a DefectDojo destination accepts deliveries; Faraday/GMP use pull")
    payload = defectdojo.generic_findings(scan_id)
    delivery_id = integrations_store.create_delivery(destination, scan_id, payload, engagement_id=engagement_id, test_id=test_id)
    job_id = durable_jobs.enqueue("integrations.deliver", {"delivery_id": delivery_id}, scan_id=scan_id, idempotency_key=f"delivery:{delivery_id}", retry_safe=False, max_attempts=1)
    with db.connect() as conn:
        conn.execute("UPDATE integration_deliveries SET job_id=? WHERE id=?", (job_id, delivery_id))
    return {"delivery_id": delivery_id, "job_id": job_id}


def enqueue_poll(delivery_id, *, remote_test_id=None):
    delivery = integrations_store.get_delivery(delivery_id)
    if remote_test_id is not None:
        if delivery["remote_test_id"] and delivery["remote_test_id"] != remote_test_id:
            raise ValueError("Remote test reference is already known and cannot be replaced")
        integrations_store.checkpoint(delivery_id, "polling", remote_test_id=remote_test_id)
    elif not delivery["remote_test_id"]:
        raise ValueError("Reconcile in DefectDojo and supply the actual remote test ID first")
    return {"job_id": durable_jobs.enqueue("integrations.poll", {"delivery_id": delivery_id}, retry_safe=True, max_attempts=3)}


def enqueue_pull(destination_id, scope_id, *, report_id=""):
    destination = integrations_store.get_destination(destination_id)
    scope = db.get_scope(scope_id)
    if destination["kind"] not in {"faraday", "greenbone"} or scope is None:
        raise ValueError("Choose a Faraday/GMP destination and saved scope")
    if destination["kind"] == "greenbone":
        import uuid
        try:
            report_id = str(uuid.UUID(report_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("GMP pull requires the existing report UUID") from exc
    from .destinations import fingerprint
    return {"job_id": durable_jobs.enqueue("integrations.pull", {"destination_id": destination_id, "destination_hash": fingerprint(destination), "scope_id": scope_id,
        "authorized_by": scope["authorized_by"], "pinned_targets": scope["pinned_targets"], "report_id": report_id}, retry_safe=True, max_attempts=3)}


def register_jobs():
    from .worker import register_handler
    def deliver(payload, context):
        context.check_cancelled()
        result = defectdojo.deliver(payload["delivery_id"], cancel=context.cancel)
        return {"status": "done", "delivery_id": result["id"], "remote_test_id": result["remote_test_id"]}
    def poll(payload, context):
        context.check_cancelled()
        result = defectdojo.poll(payload["delivery_id"], cancel=context.cancel)
        return {"status": "done", "delivery_id": result["id"], "remote_test_id": result["remote_test_id"]}
    def pull(payload, context):
        from .destinations import fingerprint
        destination = integrations_store.get_destination(payload["destination_id"])
        scope = db.get_scope(payload["scope_id"])
        if fingerprint(destination) != payload["destination_hash"] or scope is None or scope["authorized_by"] != payload["authorized_by"] or scope["pinned_targets"] != payload["pinned_targets"]:
            raise ValueError("Destination or scope authorization changed; prepare a new pull")
        context.check_cancelled()
        raw = faraday.pull(destination, cancel=context.cancel) if destination["kind"] == "faraday" else greenbone.pull(destination, payload["report_id"], cancel=context.cancel)
        context.check_cancelled()
        return import_evidence(destination["kind"], raw, scope_id=payload["scope_id"], destination_id=destination["id"])
    register_handler("integrations.deliver", deliver)
    register_handler("integrations.poll", poll)
    register_handler("integrations.pull", pull)
