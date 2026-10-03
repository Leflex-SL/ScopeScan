"""Generic Findings Import export and resumable DefectDojo API v2 delivery.

Wire contracts: https://docs.defectdojo.com/supported_tools/parsers/file/generic/
https://docs.defectdojo.com/automation/api/api-v2-docs/
"""
from __future__ import annotations

import hashlib
import json
import time
from importlib.metadata import version

from . import destinations, export, integrations_store
from ._integration_http import ConnectorError, check, pause, redact_known, request_json, session
from .engine_store import sanitize


def generic_findings(scan_id):
    snapshot = export.scan_payload(scan_id)
    scan = snapshot["scan"]
    observed_at = snapshot.get("observation", {}).get("observed_at") or scan.get("finished_at") or scan.get("started_at") or scan["created_at"]
    items = []
    identities = {}

    def append(record, *, candidate=False):
        host = record.get("host", "")
        port = record.get("port")
        protocol = record.get("protocol", "host" if port is None else "tcp")
        rule = record.get("rule_id") or record.get("source") or record.get("cve_id", "unknown")
        from .nvd import normalize_cpe
        cpe = record.get("detected_cpe") or record.get("queried_cpe", "")
        normalized_cpe = normalize_cpe(cpe) if cpe else None
        product = ":".join(normalized_cpe.split(":")[:5]) if normalized_cpe else cpe
        identity = [snapshot.get("observation", {}).get("namespace", f"scan:{scan_id}"), host, port, protocol, rule, record.get("component") or product, record.get("cve_id", "")]
        logical_id = record.get("stable_id") or hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
        severity = record.get("severity_slug", "info")
        cvss = record.get("cvss")
        if candidate and type(cvss) in (int, float):
            severity = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low" if cvss > 0 else "info"
        description = record.get("description") or record.get("summary") or "Observed finding"
        evidence = record.get("evidence", "")
        location = f"{host}:{port}/{protocol}" if port is not None else host
        description += f"\n\nScopeScan source: {rule}\nObserved: {observed_at}\nLocation: {location}\nAssessment: {'candidate' if candidate else record.get('assessment', 'exposure')}"
        if cvss is not None:
            description += f"\nReported CVSS: {cvss}; version/provider: {record.get('cvss_version', 'unknown')}/{record.get('cvss_source', 'unknown')}"
        if evidence:
            description += "\nEvidence: " + evidence
        if candidate:
            description += f"\nDetected/queried CPE: {record.get('detected_cpe', '')}/{record.get('queried_cpe', '')}; match: {record.get('match_type', 'unknown')}; stale feed: {record.get('feed_stale', 'unknown')}; feed date: {record.get('feed_fetched_at', 'unknown')}"
        if logical_id in identities:
            identities[logical_id]["description"] += "\n\nAdditional evidence: " + description
            return
        finding = {"title": (record.get("title") or record.get("cve_id") or "ScopeScan finding")[:511],
            "severity": severity.title(), "description": description, "date": observed_at,
            "verified": bool(not candidate and record.get("confirmed") and record.get("assessment") == "confirmed"),
            "active": True, "mitigation": record.get("remediation", ""), "unique_id_from_tool": logical_id,
            "vuln_id_from_tool": str(rule)[:500], "tags": ["scopescan", "candidate" if candidate else str(record.get("assessment", "exposure"))]}
        cves = record.get("cves", []) or ([record["cve_id"]] if record.get("cve_id") else [])
        if cves:
            finding["vulnerability_ids"] = cves
        if host:
            endpoint = {"host": host}
            if port is not None:
                endpoint["port"] = port
                endpoint["protocol"] = protocol
            finding["endpoints"] = [endpoint]
        vector = record.get("cvss_vector", "")
        if vector.startswith("CVSS:3."):
            finding["cvssv3"] = vector
        elif vector.startswith("CVSS:4.0/"):
            finding["cvssv4"] = vector
        items.append(finding)
        identities[logical_id] = finding

    for finding in snapshot["findings"]:
        append(finding)
    for candidate in snapshot.get("cve_candidates", []):
        append(candidate, candidate=True)
    for candidate in snapshot.get("windows_patch_candidates", []):
        append(dict(candidate, port=None, protocol="host", source="msrc:" + candidate.get("cve_id", "unknown")), candidate=True)
    report = {"findings": items, "version": version("scopescan"),
        "description": f"ScopeScan scan {scan_id}; original observation {observed_at}; evidence is limited to supplied coverage"}
    payload, _ = sanitize(json.dumps(report, ensure_ascii=True, allow_nan=False).encode(), "application/json")
    return payload


def _destination(delivery):
    destination = integrations_store.get_destination(delivery["destination_id"])
    if destination["kind"] != "defectdojo" or destinations.fingerprint(destination) != delivery["destination_hash"]:
        raise ConnectorError("Delivery destination changed; reconcile the previous operation before preparing another")
    return destination


def poll(delivery_id, *, cancel=None, deadline=None, client=None, poll_interval=2):
    delivery = integrations_store.get_delivery(delivery_id)
    destination = _destination(delivery)
    if delivery["state"] == "done":
        return delivery
    remote_id = delivery["remote_test_id"]
    if not remote_id:
        raise ConnectorError("Remote test ID is unknown; reconcile the remote import before polling or creating another")
    deadline = deadline or time.monotonic() + destination["settings"]["timeout"]
    own = client is None
    client = client or session()
    try:
        token = destinations.credential(destination, "token_env")
        while True:
            response = request_json(client, "GET", f"{destination['url']}/api/v2/tests/{remote_id}/", headers={"Authorization": "Token " + token}, cancel=cancel, deadline=deadline, max_bytes=1_000_000)
            status = response.get("status")
            if status not in {"Processing", "Post Processing - Deduplication", "Post Processing - False Positive History", "Processed", "Failed"}:
                raise ConnectorError("DefectDojo test lifecycle is unsupported; check server API v2 compatibility")
            if status != "Failed" and (type(response.get("processing")) is not bool or response["processing"] != (status != "Processed")):
                raise ConnectorError("DefectDojo test status and processing state are inconsistent; resume polling after checking the server")
            checkpoint = {"status": status, "processing": response.get("processing"), "test_id": remote_id}
            if status == "Processed":
                integrations_store.checkpoint(delivery_id, "done", response=checkpoint)
                return integrations_store.get_delivery(delivery_id)
            if status == "Failed":
                integrations_store.checkpoint(delivery_id, "failed", response=checkpoint, error="Remote import failed; inspect DefectDojo test and reconcile before another import")
                raise ConnectorError("DefectDojo import failed")
            integrations_store.checkpoint(delivery_id, "polling", response=checkpoint)
            pause(poll_interval, cancel=cancel, deadline=deadline)
    finally:
        if own:
            client.close()


def deliver(delivery_id, *, cancel=None, client=None):
    delivery = integrations_store.get_delivery(delivery_id, include_payload=True)
    destination = _destination(delivery)
    if delivery["state"] == "done":
        return integrations_store.get_delivery(delivery_id)
    if delivery["remote_test_id"]:
        return poll(delivery_id, cancel=cancel, client=client)
    if delivery["state"] != "prepared":
        raise ConnectorError("Delivery may already have reached the server; automatic POST retry refused. Reconcile the remote test ID")
    token = destinations.credential(destination, "token_env")
    deadline = time.monotonic() + destination["settings"]["timeout"]
    own = client is None
    client = client or session()
    try:
        check(cancel, deadline)
        if not integrations_store.checkpoint(delivery_id, "posting", posting=True):
            raise ConnectorError("Another worker already claimed this delivery; reconcile its state")
        # API-wide verified overrides would erase each finding's evidence state.
        params = {"scan_type": "Generic Findings Import", "close_old_findings": "false", "background_import": "true", "minimum_severity": "Info"}
        if delivery["test_id"] is not None:
            params["test"] = str(delivery["test_id"])
            path = "reimport-scan"
        else:
            params["engagement"] = str(delivery["engagement_id"])
            path = "import-scan"
        try:
            response = request_json(client, "POST", f"{destination['url']}/api/v2/{path}/", headers={"Authorization": "Token " + token},
                data=params, files={"file": ("scopescan.json", delivery["payload"], "application/json")}, cancel=cancel, deadline=deadline, max_bytes=1_000_000)
            remote_id = response.get("test_id", response.get("test"))
            if isinstance(remote_id, dict):
                remote_id = remote_id.get("id")
            if type(remote_id) is not int or remote_id <= 0:
                raise ConnectorError("DefectDojo did not return a valid remote test ID")
            if delivery["test_id"] is not None and remote_id != delivery["test_id"]:
                raise ConnectorError("DefectDojo reimport returned a different test ID; reconcile the server operation")
            summary = {key: response[key] for key in ("background_import", "status", "findings_parsed", "test_id", "statistics", "deduplication_complete") if key in response}
            summary = redact_known(summary, token)
            # Persist the remote reference before polling; crashes after POST never resend it.
            integrations_store.checkpoint(delivery_id, "polling", remote_test_id=remote_id, response=summary)
        except ConnectorError:
            integrations_store.checkpoint(delivery_id, "action_required", error="POST outcome is uncertain; inspect DefectDojo and attach its test ID before resuming")
            raise
        if response.get("background_import") is True:
            return poll(delivery_id, cancel=cancel, deadline=deadline, client=client)
        if not isinstance(response.get("statistics"), dict):
            raise ConnectorError("DefectDojo response lacks synchronous statistics; resume polling the known test ID")
        integrations_store.checkpoint(delivery_id, "done", response=summary)
        return integrations_store.get_delivery(delivery_id)
    finally:
        if own:
            client.close()
