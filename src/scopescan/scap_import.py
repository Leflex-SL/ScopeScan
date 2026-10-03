"""XCCDF 1.1/1.2 and ARF imports preserve controls and reported coverage."""
from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET

from defusedxml import ElementTree as SafeET

from .engine_store import redact_text, sanitize
from .sbom import MAX_BYTES, MAX_ITEMS, timestamp

XCCDF_NAMESPACES = {"http://checklists.nist.gov/xccdf/1.2", "http://checklists.nist.gov/xccdf/1.1"}
RESULTS = {"pass", "fail", "error", "unknown", "notapplicable", "notchecked", "informational", "fixed"}


def local(element):
    return element.tag.rsplit("}", 1)[-1]


def content(element):
    return " ".join("".join(element.itertext()).split())[:16000] if element is not None else ""


def children(element, name):
    return [child for child in element if local(child) == name]


def parse(payload: bytes) -> dict:
    if not isinstance(payload, bytes) or len(payload) > MAX_BYTES:
        raise ValueError("SCAP evidence exceeds 8 MB")
    try:
        root = SafeET.fromstring(payload, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except Exception as exc:
        raise ValueError("Invalid or unsafe SCAP XML") from exc
    pending = [(root, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 64 or count > 200_000:
            raise ValueError("SCAP depth/node budget exceeded")
        pending.extend((child, depth + 1) for child in node)
    if local(root) not in {"Benchmark", "TestResult", "asset-report-collection"}:
        raise ValueError("Expected XCCDF Benchmark/TestResult or ARF asset-report-collection")
    root_namespace = root.tag.split("}")[0].lstrip("{")
    if root_namespace not in XCCDF_NAMESPACES | {"http://scap.nist.gov/schema/asset-reporting-format/1.1"}:
        raise ValueError("Unsupported SCAP namespace")
    results = [node for node in root.iter() if local(node) == "TestResult" and node.tag.split("}")[0].lstrip("{") in XCCDF_NAMESPACES]
    if len(results) != 1:
        raise ValueError("Import one XCCDF TestResult at a time; multiple reports are ambiguous")
    result = results[0]
    targets = [content(node) for node in children(result, "target")]
    if len(set(targets)) > 1:
        raise ValueError("SCAP TestResult contains multiple targets; split evidence by resource")
    benchmark_nodes = [node for node in root.iter() if local(node) == "Benchmark"]
    benchmark = benchmark_nodes[0] if len(benchmark_nodes) == 1 else None
    rules = {}
    if benchmark is not None:
        for rule in benchmark.iter():
            if local(rule) == "Rule":
                rules[rule.get("id", "")] = rule
    observations = []
    for entry in children(result, "rule-result"):
        if len(observations) >= MAX_ITEMS:
            raise ValueError("Too many SCAP rule results")
        rule_id = entry.get("idref")
        states = children(entry, "result")
        if not rule_id or len(rule_id) > 4096 or len(states) != 1 or content(states[0]) not in RESULTS:
            raise ValueError("Invalid SCAP rule result")
        rule = rules.get(rule_id)
        state = content(states[0])
        criteria = []
        for check in children(entry, "check") or (children(rule, "check") if rule is not None else []):
            criteria.append({"system": check.get("system", ""), "selector": check.get("selector", ""),
                             "references": [dict(node.attrib) for node in children(check, "check-content-ref")],
                             "content": content(check)})
        observations.append({"component_ref": targets[0] if targets else "", "rule_id": rule_id,
                             "outcome": state, "severity": entry.get("severity", rule.get("severity", "unknown") if rule is not None else "unknown"),
                             "title": content(children(rule, "title")[0]) if rule is not None and children(rule, "title") else rule_id,
                             "description": content(children(rule, "description")[0]) if rule is not None and children(rule, "description") else "",
                             "criteria": criteria, "references": [dict(node.attrib) | {"text": content(node)} for node in children(rule, "reference")] if rule is not None else [],
                             "messages": [{"severity": node.get("severity", ""), "text": content(node)} for node in children(entry, "message")],
                             "observed_at": timestamp(entry.get("time") or result.get("end-time")),
                             "confirmed": False, "source": "imported-xccdf"})
    if len({x["rule_id"] for x in observations}) != len(observations):
        raise ValueError("Duplicate SCAP rule identities require split reports")
    profile_nodes = children(result, "profile")
    benchmark_refs = children(result, "benchmark")
    normalized = {"format": "xccdf", "format_version": result.tag.split("}")[0].rsplit("/", 1)[-1],
                  "observed_at": timestamp(result.get("end-time")), "test_result_id": result.get("id", ""),
                  "benchmark_id": benchmark.get("id", "") if benchmark is not None else "",
                  "benchmark_version": content(children(benchmark, "version")[0]) if benchmark is not None and children(benchmark, "version") else "",
                  "benchmark_references": [dict(node.attrib) for node in benchmark_refs],
                  "profile": profile_nodes[0].get("idref", "") if profile_nodes else "", "targets": targets,
                  "observations": observations, "coverage": "reported_rules_only", "certification": False,
                  "components": [], "errors": [], "status": "partial" if any(x["outcome"] in {"unknown", "error", "notchecked"} for x in observations) else "complete"}
    encoded, redactions = sanitize(json.dumps(normalized).encode(), "application/json")
    normalized = json.loads(encoded)
    # Preserve inspectable XML, redacting all text/attributes rather than opaque suppression.
    for node in root.iter():
        secret_node = any(word in local(node).lower() for word in ("password", "secret", "token", "credential"))
        node.text = "[redacted]" if secret_node else redact_text(node.text or "")
        node.tail = redact_text(node.tail or "")
        for key, value in list(node.attrib.items()):
            node.set(key, "[redacted]" if any(word in key.lower() for word in ("password", "secret", "token", "credential")) else redact_text(value))
    safe = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    normalized.update(raw=safe, received_sha256=hashlib.sha256(payload).hexdigest(), raw_sha256=hashlib.sha256(safe).hexdigest(), redactions=redactions)
    return normalized
