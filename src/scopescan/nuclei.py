"""Nuclei 3.11.1 process adapter; only byte-pinned, reviewed HTTP GET checks.

Flags/schema: projectdiscovery/nuclei v3.11.1 cmd/nuclei/main.go and
pkg/output/output.go. Config isolation also covers pkg/catalog/config/constants.go.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from ._adapter_support import (
    checked_plan,
    command_for,
    isolated_environment,
    observation,
    result,
    stamp,
)
from .engine_contracts import Endpoint, EnginePlan, EngineResult, Provenance, ScanScope
from .models import Severity
from .process_runner import run_process

VERSION = "3.11.1"
# Hashes attest these exact project-owned bytes, not arbitrary user manifests/signatures.
CATALOG = {
    "scopescan-http-missing-nosniff": (
        "5c524885d9212537572e3fc96cd0505b133487cd0ba7e8ae317a196c9ca52384",
        "x-content-type-options", "HTTP response lacks X-Content-Type-Options"),
    "scopescan-http-missing-hsts": (
        "4b29bd2f136f55ed28eaaf9bc2abf120c33ae052070cc903e07b2d4d5e8f4ecf",
        "strict-transport-security", "HTTPS response lacks Strict-Transport-Security"),
}
TEMPLATE_ROOT = Path(__file__).with_name("engine_templates")
HTTP_SERVICES = {"http", "http-alt", "http-proxy", "www", "https", "https-alt", "ssl/http", "http-ssl", "tls/http"}
TLS_SERVICES = {"https", "https-alt", "ssl/http", "http-ssl", "tls/http"}


def _scheme(endpoint: Endpoint) -> str:
    return "https" if endpoint.service.lower() in TLS_SERVICES else "http"


def _url(endpoint: Endpoint) -> str:
    address = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    return f"{_scheme(endpoint)}://{address}:{endpoint.port}"


def _rules(endpoint: Endpoint) -> tuple[str, ...]:
    return tuple(rule for rule in CATALOG if rule != "scopescan-http-missing-hsts" or _scheme(endpoint) == "https")


def _headers(response) -> dict[str, str] | None:
    if not isinstance(response, str) or len(response) > 65536 or "\x00" in response:
        return None
    head, separator, _ = response.replace("\r\n", "\n").partition("\n\n")
    if not separator:
        return None
    lines = head.split("\n")
    if not re.fullmatch(r"HTTP/(?:1\.[01]|2(?:\.0)?) [2-5][0-9]{2}(?: [^\r\n]*)?", lines[0]):
        return None
    headers = {}
    for line in lines[1:]:
        key, colon, value = line.partition(":")
        key = key.lower()
        if not colon or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", key) or key in headers or any(ord(x) < 32 and x != "\t" for x in value):
            return None
        headers[key] = value.strip()
    return headers


def _event_result(event, endpoint: Endpoint, rule: str) -> tuple[bool | None, str]:
    """An owned matcher and a concrete HTTP response must agree; absence proves nothing."""
    if not isinstance(event, dict) or event.get("template-id") != rule or event.get("type") != "http":
        return None, "Unexpected template/protocol event"
    try:
        if str(ipaddress.ip_address(event.get("ip", ""))) != endpoint.host or event.get("port") != str(endpoint.port) or event.get("scheme") != _scheme(endpoint):
            raise ValueError()
        target = urlsplit(event.get("url") or event.get("matched-at") or "")
        if target.hostname != endpoint.host or target.port != endpoint.port or target.scheme != _scheme(endpoint) or target.path not in {"", "/"} or target.query or target.fragment or target.username or target.password:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        return None, "Event does not bind to the exact pinned endpoint"
    if type(event.get("matcher-status")) is not bool or event.get("error") not in {None, ""}:
        return None, "Matcher did not complete successfully"
    headers = _headers(event.get("response"))
    if headers is None:
        return None, "HTTP response headers are missing, malformed, duplicated or truncated"
    header = CATALOG[rule][1]
    missing = header not in headers
    if missing != event["matcher-status"]:
        return None, "Matcher status contradicts the observed HTTP headers"
    # These checks prove header absence/presence, not validity of a present policy value.
    evidence = f"GET / at {_url(endpoint)}; complete HTTP headers; {header}: " + ("absent" if missing else headers[header][:2048])
    return missing, evidence


class NucleiAdapter:
    name = "nuclei"

    def __init__(self, *, command: tuple[str, ...] | None = None):
        self._command = command

    def _probe(self, root: Path, *, deadline: float | None = None, cancel=None):
        command = command_for(self.name, self._command)
        probe = run_process([*command, "-version", "-duc"], timeout=10, deadline=deadline,
                            cancel=cancel, env=isolated_environment(root), cwd=root, max_output_chars=16384)
        text = probe.stdout + "\n" + probe.stderr
        if probe.cancelled or probe.timed_out or probe.returncode != 0 or not re.search(r"(?i)\bnuclei(?:\s+(?:engine\s+)?version)?\s*:?\s*v?3\.11\.1\b", text):
            raise RuntimeError("Nuclei 3.11.1 is required; check the optional executable and its version")
        return command

    def available(self) -> tuple[bool, str]:
        try:
            with tempfile.TemporaryDirectory(prefix="scopescan-nuclei-probe-") as directory:
                self._probe(Path(directory))
            return True, f"Nuclei {VERSION} (reviewed HTTP catalog only)"
        except (OSError, RuntimeError) as exc:
            return False, str(exc)

    def plan(self, scope: ScanScope, *, timeout: float = 120) -> EnginePlan:
        endpoints = tuple(e for e in scope.endpoints if e.protocol == "tcp" and e.port is not None and e.service.lower() in HTTP_SERVICES)
        if not endpoints:
            raise ValueError("Nuclei needs an authorized TCP endpoint explicitly identified as HTTP/HTTPS")
        rules = tuple(rule for rule in CATALOG if any(rule in _rules(e) for e in endpoints))
        if len(endpoints) * len(rules) > 10000:
            raise ValueError("Nuclei plan exceeds 10000 observations")
        return EnginePlan(self.name, scope, endpoints, rules, timeout)

    def execute(self, plan: EnginePlan, *, cancel: threading.Event | None = None) -> EngineResult:
        checked_plan(self, plan)
        started, deadline = stamp(), time.monotonic() + plan.timeout
        versions = tuple((rule, CATALOG[rule][0]) for rule in plan.rules)
        digest = hashlib.sha256(Path(__file__).read_bytes() + repr(versions).encode()).hexdigest()
        provenance = Provenance(self.name, VERSION, digest, templates=versions)
        observations, raw, errors = [], [], []
        cancelled = failed = False
        with tempfile.TemporaryDirectory(prefix="scopescan-nuclei-") as directory:
            root = Path(directory)
            try:
                command = self._probe(root, deadline=deadline, cancel=cancel)
                copied = {}
                for rule, expected in versions:
                    # Read once, validate bytes, execute the exact private copy; no TOCTOU reread.
                    with (TEMPLATE_ROOT / f"{rule}.yaml").open("rb") as stream:
                        content = stream.read(16385)
                    if len(content) > 16384 or hashlib.sha256(content).hexdigest() != expected:
                        raise ValueError(f"Reviewed template integrity check failed: {rule}")
                    target = root / f"{rule}.yaml"
                    target.write_bytes(content)
                    copied[rule] = target
                env = isolated_environment(root)
                config = root / "minimal.yaml"
                config.write_text("{}\n", encoding="utf-8")
                received = 0
                for number, endpoint in enumerate(plan.endpoints):
                    for rule in _rules(endpoint):
                        vulnerable, evidence = None, "Check did not complete"
                        if cancel is not None and cancel.is_set():
                            cancelled = True
                        elif time.monotonic() >= deadline or received >= plan.max_output_bytes:
                            errors.append("Whole-job deadline or output budget exhausted")
                        else:
                            output = root / f"result-{number}-{rule}.jsonl"
                            args = [*command, "-u", _url(endpoint), "-t", str(copied[rule]), "-config", str(config),
                                    "-j", "-jle", str(output), "-ms", "-ot", "-nc", "-dr", "-ni", "-duc", "-pt", "http",
                                    "-rl", "2", "-c", "1", "-bs", "1", "-timeout", "5", "-retries", "0",
                                    "-rsr", "65536", "-rss", "65536"]
                            if endpoint.hostname:
                                args += ["-sni", endpoint.hostname, "-H", f"Host: {endpoint.hostname}"]
                            execution = run_process(args, deadline=deadline, cancel=cancel, env=env, cwd=root,
                                                    file_limits={output: plan.max_output_bytes - received},
                                                    max_output_chars=min(plan.max_output_bytes, 65536))
                            cancelled |= execution.cancelled
                            if execution.returncode or execution.timed_out or execution.cancelled or execution.file_limit_exceeded or execution.output_truncated:
                                errors.append("Nuclei check interrupted, failed or exceeded its output bound")
                            else:
                                content = output.read_bytes() if output.exists() else b""
                                received += len(content)
                                try:
                                    events = [json.loads(line) for line in content.splitlines() if line.strip()]
                                    if len(events) != 1:
                                        raise ValueError("Missing or ambiguous matcher event")
                                    vulnerable, evidence = _event_result(events[0], endpoint, rule)
                                    # Retain only sanitized HTTP headers, never request/body secrets.
                                    raw.append({"template-id": rule, "endpoint": _url(endpoint), "outcome": vulnerable,
                                                "evidence": evidence, "response_headers": (events[0].get("response", "").split("\r\n\r\n")[0].split("\n\n")[0])})
                                except (ValueError, TypeError, AttributeError) as exc:
                                    evidence = str(exc)
                        observations.append(observation(endpoint, rule, vulnerable, evidence, CATALOG[rule][2],
                                                        Severity.LOW, engine=self.name, exposure=True))
            except (OSError, RuntimeError, ValueError) as exc:
                failed = True
                cancelled = cancel is not None and cancel.is_set()
                errors.append(str(exc))
                seen = {(o.endpoint, o.rule_id) for o in observations}
                for endpoint in plan.endpoints:
                    for rule in _rules(endpoint):
                        if (endpoint, rule) not in seen:
                            observations.append(observation(endpoint, rule, None, "Engine unavailable or catalog invalid", CATALOG[rule][2], engine=self.name))
        return result(self.name, provenance, observations, raw, errors, started,
                      cancelled=cancelled, failed=failed, maximum=plan.max_output_bytes)
