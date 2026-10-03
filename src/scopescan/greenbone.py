"""Greenbone GMP 22.5 report pull over verified TLS or a configured Unix socket.

https://docs.greenbone.net/API/GMP/gmp-22.5.html
Only authenticate/get_reports are sent; this adapter never launches scans.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
import socket
import ssl
import time
import uuid
from urllib.parse import urlsplit
from xml.etree import ElementTree
from xml.parsers import expat

from defusedxml import ElementTree as SafeXML

from . import destinations
from ._integration_http import ConnectorError, check
from .engine_store import sanitize
from .importers import _timestamp

MAX_BYTES = 8_000_000


def parse_xml(payload):
    if len(payload) > MAX_BYTES:
        raise ValueError("GMP XML exceeds 8 MB")
    try:
        root = SafeXML.fromstring(payload, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        stack, nodes = [(root, 0)], 0
        while stack:
            element, depth = stack.pop()
            nodes += 1
            if nodes > 100_000 or depth > 64:
                raise ValueError("GMP XML exceeds structural bounds")
            stack.extend((child, depth + 1) for child in element)
        return root
    except Exception as exc:
        raise ValueError("GMP XML is invalid, unsafe or exceeds structural bounds") from exc


def _exchange(stream, command, *, cancel, deadline):
    check(cancel, deadline)
    stream.sendall(ElementTree.tostring(command, encoding="utf-8"))
    parser = expat.ParserCreate()
    # GMP keeps the socket open between XML documents. Expat's reparse deferral
    # can postpone a small response's closing callback forever while we wait.
    # Immediate callbacks require our own unfinished-token cap (64 KiB), in
    # addition to whole-document/depth/node/deadline limits.
    # https://docs.python.org/3/library/pyexpat.html#xmlparser.SetReparseDeferralEnabled
    if hasattr(parser, "SetReparseDeferralEnabled"):
        parser.SetReparseDeferralEnabled(False)
    depth, complete, nodes = 0, False, 0

    def start(name, attrs):
        nonlocal depth, nodes
        depth += 1
        nodes += 1
        if depth > 64 or nodes > 100_000:
            raise ConnectorError("GMP XML exceeds structural bounds")

    def end(name):
        nonlocal depth, complete
        depth -= 1
        if depth == 0:
            complete = True

    def forbidden(*args):
        raise ConnectorError("GMP entities and DTDs are forbidden")

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    raw = bytearray()
    while not complete:
        check(cancel, deadline)
        try:
            chunk = stream.recv(16_384)
        except TimeoutError:
            continue
        if not chunk:
            raise ConnectorError("GMP connection ended before a complete response")
        raw.extend(chunk)
        if len(raw) > MAX_BYTES:
            raise ConnectorError("GMP response exceeds 8 MB")
        if len(raw) - parser.CurrentByteIndex > 65536:
            raise ConnectorError("GMP XML token exceeds 64 KiB")
        try:
            parser.Parse(chunk, False)
        except expat.ExpatError as exc:
            raise ConnectorError("GMP response framing is invalid") from exc
    check(cancel, deadline)
    response = parse_xml(bytes(raw))
    if response.get("status") != "200":
        raise ConnectorError("GMP command failed; verify credentials and report permissions")
    return bytes(raw)


def pull(destination, report_id, *, cancel=None, stream=None):
    try:
        report_id = str(uuid.UUID(report_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("GMP report ID must be a UUID") from exc
    parts = urlsplit(destination["url"])
    deadline = time.monotonic() + destination["settings"]["timeout"]
    own = stream is None
    if own:
        check(cancel, deadline)
        try:
            if parts.scheme == "unix":
                stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                stream.settimeout(min(3, deadline - time.monotonic()))
                stream.connect(parts.path)
            else:
                connection = socket.create_connection((parts.hostname, parts.port or 9390), timeout=min(3, deadline - time.monotonic()))
                try:
                    stream = ssl.create_default_context().wrap_socket(connection, server_hostname=parts.hostname)
                except Exception:
                    connection.close()
                    raise
        except (OSError, AttributeError) as exc:
            if stream is not None:
                stream.close()
            raise ConnectorError("GMP connection unavailable; configure verified TLS or a supported worker Unix socket") from exc
    try:
        stream.settimeout(.25)
        command = ElementTree.Element("authenticate")
        credentials = ElementTree.SubElement(command, "credentials")
        ElementTree.SubElement(credentials, "username").text = destinations.credential(destination, "username_env")
        ElementTree.SubElement(credentials, "password").text = destinations.credential(destination, "password_env")
        _exchange(stream, command, cancel=cancel, deadline=deadline)
        command = ElementTree.Element("get_reports", {"report_id": report_id, "details": "1", "filter": "first=1 rows=-1"})
        return _exchange(stream, command, cancel=cancel, deadline=deadline)
    except ConnectorError:
        raise
    except (OSError, ValueError) as exc:
        raise ConnectorError("GMP report retrieval failed; inspect permissions and TLS/service availability") from exc
    finally:
        if own:
            stream.close()


def normalize(payload):
    root = parse_xml(payload)
    if root.tag == "get_reports_response" and root.get("status") != "200":
        raise ValueError("GMP report response did not succeed")
    reports = [item for item in root.iter("report") if item.find("results") is not None]
    if len(reports) != 1:
        raise ValueError("Import one detailed XML GMP report containing results")
    report = reports[0]
    observed_at = report.findtext("scan_end") or report.findtext("scan_start")
    if not observed_at:
        raise ValueError("GMP report requires its original scan timestamp")
    # GMP schema uses UTC ISO dates; its own examples omit Z on some dates.
    if not re.search(r"(?:Z|[+-]\d\d:\d\d)$", observed_at):
        observed_at += "+00:00"
    observed_at = _timestamp(observed_at)
    hosts, findings, records, errors = {}, [], [], []
    results = report.findall("./results/result")
    if len(results) > 10_000:
        raise ValueError("GMP report exceeds 10000 results")
    for result in results:
        try:
            host = str(ipaddress.ip_address((result.findtext("host") or "").strip()))
        except ValueError as exc:
            raise ValueError("GMP results must identify concrete IP addresses") from exc
        hosts.setdefault(host, {"address": host, "state": "unknown", "ports": []})
        port_string = result.findtext("port") or "general/tcp"
        match = re.fullmatch(r"(\d{1,5})/(tcp|udp)", port_string)
        port, protocol = (int(match[1]), match[2]) if match else (None, "host")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("GMP result contains an invalid port")
        nvt = result.find("nvt")
        oid = nvt.get("oid", "") if nvt is not None else ""
        if not re.fullmatch(r"[0-9.]{1,128}", oid):
            errors.append("GMP result without a stable NVT OID")
            continue
        score_text = result.findtext("severity")
        try:
            score = float(score_text)
            if not math.isfinite(score) or not -1 <= score <= 10:
                raise ValueError
        except (ValueError, TypeError):
            score = None
            errors.append("GMP result severity is unknown")
        cves = sorted({ref.get("id") for ref in nvt.findall("./refs/ref") if ref.get("type") == "cve" and re.fullmatch(r"CVE-\d{4}-\d+", ref.get("id", ""))})
        cves.extend(value for value in re.findall(r"CVE-\d{4}-\d+", nvt.findtext("cve") or "") if value not in cves)
        qod = result.findtext("./qod/value")
        record = {"result_id": result.get("id", ""), "host": host, "port": port, "protocol": protocol, "nvt_oid": oid,
            "qod": int(qod) if qod and qod.isdecimal() and 0 <= int(qod) <= 100 else None, "qod_type": result.findtext("./qod/type"),
            "threat": result.findtext("threat"), "severity": score, "cve_ids": cves, "creation_time": result.findtext("creation_time"),
            "title": result.findtext("name") or nvt.findtext("name") or oid, "description": result.findtext("description") or "",
            "solution": nvt.findtext("./solution") or ""}
        records.append(record)
        if score is None or score <= 0 or record["threat"] == "False Positive":
            continue
        findings.append({"host": host, "port": port, "protocol": protocol, "rule_id": "greenbone:" + oid, "title": record["title"][:1024],
            "severity": "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low", "cvss": score,
            "description": record["description"][:16000], "evidence": f"External NVT {oid}; result {record['result_id']}; QoD {record['qod']} ({record['qod_type']}); not locally verified",
            "remediation": record["solution"][:16000], "cve_ids": cves})
    scan_status = report.findtext("scan_run_status") or "unknown"
    if scan_status != "Done":
        errors.append("GMP report scan is incomplete or has unknown status")
    filtered = report.findtext("./result_count/filtered")
    if filtered and (not filtered.isdecimal() or int(filtered) != len(results)):
        errors.append("GMP result list is incomplete")
    normalized = {"kind": "greenbone", "engine_version": report.findtext("./gmp/version") or "unknown", "observed_at": observed_at,
        "report_id": report.get("id", ""), "scan_status": scan_status, "status": "partial" if errors else "complete", "errors": errors,
        "hosts": list(hosts.values()), "findings": findings, "results": records,
        "coverage": "Supplied external GMP report results only; QoD is remote metadata, not local proof"}
    safe, _ = sanitize(json.dumps(normalized, ensure_ascii=True).encode(), "application/json")
    return json.loads(safe)
