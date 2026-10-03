"""Read-only Faraday API v3 import using cookie authentication and real parents.

https://docs.faradaysec.com/API-Server/
https://github.com/infobyte/faraday/blob/master/faraday/server/api/modules/vulns_base.py
"""
from __future__ import annotations

import ipaddress
import json
import time

from . import db, destinations
from ._integration_http import ConnectorError, check, request_json, session
from .engine_store import sanitize
from .importers import _timestamp

LIMIT = 10_000


def collection(client, destination, kind, *, cancel, deadline):
    key = "vulnerabilities" if kind == "vulns" else kind
    items, seen, total = [], set(), None
    workspace = destination["settings"]["workspace"]
    for number in range(1, 102):
        check(cancel, deadline)
        value = request_json(client, "GET", f"{destination['url']}/_api/v3/ws/{workspace}/{kind}/", params={"page": number, "page_size": 100}, cancel=cancel, deadline=deadline)
        if isinstance(value, dict):
            rows = value.get(key, value.get("rows"))
            count = value.get("count")
            if type(count) is not int or not 0 <= count <= LIMIT or (total is not None and count != total):
                raise ConnectorError("Faraday pagination count is invalid or changed; repeat a stable snapshot")
            total = count
        else:
            rows = value
        if not isinstance(rows, list) or len(rows) > 100:
            raise ConnectorError("Faraday pagination envelope is unsupported")
        for row in rows:
            if not isinstance(row, dict):
                raise ConnectorError("Faraday page contains an invalid record")
            record = row.get("value", row)
            if not isinstance(record, dict):
                raise ConnectorError("Faraday record value is invalid")
            identity = record.get("_id", record.get("id", row.get("id")))
            if type(identity) not in (int, str) or str(identity) in seen:
                raise ConnectorError("Faraday pagination repeated or omitted an object ID")
            seen.add(str(identity))
            items.append(dict(record, remote_id=str(identity)))
        if len(items) > LIMIT:
            raise ConnectorError("Faraday collection exceeds 10000 objects")
        if total is not None and len(items) == total:
            return items
        if len(rows) < 100:
            if total is not None and len(items) != total:
                raise ConnectorError("Faraday pagination ended before the declared count")
            return items
    raise ConnectorError("Faraday pagination exceeds its bound")


def pull(destination, *, cancel=None, client=None):
    own = client is None
    client = client or session()
    deadline = time.monotonic() + destination["settings"]["timeout"]
    try:
        request_json(client, "POST", destination["url"] + "/_api/login", json={"email": destinations.credential(destination, "username_env"), "password": destinations.credential(destination, "password_env")},
            headers={"Origin": destination["url"], "Content-Type": "application/json"}, cancel=cancel, deadline=deadline, max_bytes=1_000_000)
        data = {kind: collection(client, destination, kind, cancel=cancel, deadline=deadline) for kind in ("hosts", "services", "vulns")}
        data.update(observed_at=db.now(), timestamp_inferred=True, engine_version="api-v3", workspace=destination["settings"]["workspace"])
        raw = json.dumps(data, ensure_ascii=True).encode()
        if len(raw) > 8_000_000:
            raise ConnectorError("Faraday aggregate exceeds 8 MB; narrow the workspace")
        return raw
    finally:
        if own:
            client.close()


def normalize(payload):
    if len(payload) > 8_000_000:
        raise ValueError("Faraday evidence exceeds 8 MB")
    try:
        def reject_constant(value):
            raise ValueError("Non-finite JSON values are forbidden")
        data = json.loads(payload, parse_constant=reject_constant)
        if not isinstance(data, dict):
            raise TypeError
        observed_at = _timestamp(data["observed_at"])
        for key in ("hosts", "services", "vulns"):
            if not isinstance(data[key], list) or len(data[key]) > LIMIT:
                raise ValueError
        hosts, services, findings, errors = {}, {}, [], []
        for row in data["hosts"]:
            identity = str(row.get("remote_id", row.get("_id", row.get("id", ""))))
            address = str(ipaddress.ip_address(row["ip"]))
            if not identity or identity in hosts:
                raise ValueError
            hosts[identity] = {"address": address, "state": "unknown", "ports": [], "remote_id": identity}
        for row in data["services"]:
            identity = str(row.get("remote_id", row.get("_id", row.get("id", ""))))
            parent = str(row.get("parent", row.get("host_id", "")))
            if parent not in hosts or not identity or identity in services:
                errors.append("Service parent is absent from the supplied host snapshot")
                continue
            ports = row.get("ports", [row["port"]] if "port" in row else [])
            protocol = row.get("protocol", "tcp")
            if not isinstance(ports, list) or len(ports) > 100 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports) or protocol not in {"tcp", "udp", "sctp"}:
                errors.append("Service ports or protocol are unsupported")
                continue
            services[identity] = (parent, ports, protocol)
            for port in ports:
                hosts[parent]["ports"].append({"port": port, "protocol": protocol, "state": "unknown", "service": {"name": str(row.get("name", ""))[:1024], "version": str(row.get("version", ""))[:1024]}})
        for row in data["vulns"]:
            parent = str(row.get("parent", ""))
            if row.get("parent_type") == "Service" and parent in services:
                host_id, ports, protocol = services[parent]
            elif row.get("parent_type") == "Host" and parent in hosts:
                host_id, ports, protocol = parent, [None], "host"
            else:
                errors.append("Vulnerability parent is absent or unsupported")
                continue
            remote_id = str(row.get("remote_id", row.get("_id", row.get("id", ""))))
            if not remote_id:
                errors.append("Vulnerability ID missing")
                continue
            # Remote closed/risk accepted states are preserved, never local closure proof.
            if row.get("status", "open") not in {"open", "opened", "re-opened"}:
                continue
            severity = {"med": "medium", "informational": "info"}.get(row.get("severity"), row.get("severity", "info"))
            if severity not in {"critical", "high", "medium", "low", "info"}:
                errors.append("Unknown Faraday severity")
                severity = "info"
            for port in ports:
                findings.append({"host": hosts[host_id]["address"], "port": port, "protocol": protocol, "rule_id": "faraday:" + remote_id,
                    "title": str(row.get("name", "Faraday finding"))[:1024], "severity": severity,
                    "description": str(row.get("desc", row.get("description", "")))[:16000], "evidence": str(row.get("data", ""))[:16000],
                    "remediation": str(row.get("resolution", ""))[:16000], "cve_ids": row.get("cve", []) if isinstance(row.get("cve", []), list) else [],
                    "remote_confirmed": row.get("confirmed") is True, "remote_status": row.get("status"),
                    "remote_observed_at": row.get("metadata", {}).get("create_time") if isinstance(row.get("metadata"), dict) else None})
        normalized = {"kind": "faraday", "engine_version": str(data.get("engine_version", "api-v3"))[:160], "observed_at": observed_at,
            "timestamp_inferred": data.get("timestamp_inferred") is True, "status": "partial" if errors else "complete", "errors": errors[:100],
            "hosts": list(hosts.values()), "findings": findings, "coverage": "Supplied external hosts/services/vulnerabilities; no negative local evidence", "external_snapshot": data}
        safe, _ = sanitize(json.dumps(normalized, ensure_ascii=True).encode(), "application/json")
        return json.loads(safe)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        raise ValueError("Faraday import requires bounded hosts/services/vulns arrays, concrete IPs and observed_at with timezone") from exc
