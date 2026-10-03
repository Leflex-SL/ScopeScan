"""SSLyze 6.3.1 external process adapter, without importing its AGPL library.

Primary schemas: nabla-c0d3/sslyze/6.3.1/sslyze/json/json_output.py,
plugins/certificate_info/json_output.py and plugins/openssl_cipher_suites/json_output.py.
CLI syntax follows cli/command_line_parser.py and cli/server_string_parser.py.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

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

VERSION = "6.3.1"
TLS_SERVICES = {"https", "https-alt", "ssl/http", "http-ssl", "tls/http", "ssl", "tls", "imaps", "pop3s", "smtps", "ldaps", "ftps"}
CERT_RULES = {
    "tls-certificate-hostname": "Certificate SAN does not match the requested identity",
    "tls-certificate-expired": "TLS certificate has expired",
    "tls-certificate-not-yet-valid": "TLS certificate is not yet valid",
    "tls-certificate-untrusted": "TLS certificate is untrusted by the assessed trust stores",
}
PROTOCOL_RULES = {
    "tls-deprecated-ssl2": ("ssl_2_0_cipher_suites", "SSL_2_0", "sslv2"),
    "tls-deprecated-ssl3": ("ssl_3_0_cipher_suites", "SSL_3_0", "sslv3"),
    "tls-deprecated-tls10": ("tls_1_0_cipher_suites", "TLS_1_0", "tlsv1"),
    "tls-deprecated-tls11": ("tls_1_1_cipher_suites", "TLS_1_1", "tlsv1_1"),
}
RULES = tuple(CERT_RULES) + tuple(PROTOCOL_RULES)


def _target(endpoint: Endpoint) -> str:
    if endpoint.hostname:
        return f"{endpoint.hostname}:{endpoint.port}{{{endpoint.host}}}"
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    # Explicit address binding also prevents DNS fallback for address-only endpoints.
    return f"{host}:{endpoint.port}{{{endpoint.host}}}"


def san_matches(reference: str, san) -> bool | None:
    """RFC 9525 DNS-ID/IP-ID; no CN fallback, only a complete leftmost wildcard.

    https://www.rfc-editor.org/rfc/rfc9525.html sections 6.3 and 6.4.
    Invalid/missing SAN data is unknown, never a fabricated hostname field.
    """
    if not isinstance(san, dict) or not isinstance(san.get("dns_names"), list) or not isinstance(san.get("ip_addresses"), list):
        return None
    if any(not isinstance(value, str) for value in san["dns_names"] + san["ip_addresses"]):
        return None
    try:
        addresses = [ipaddress.ip_address(value) for value in san["ip_addresses"]]
    except ValueError:
        return None
    try:
        address = ipaddress.ip_address(reference)
    except ValueError:
        address = None
    if address is not None:
        return address in addresses if addresses or san["dns_names"] else None
    patterns = san["dns_names"]
    if not patterns:
        return False if san["ip_addresses"] else None
    matched = False
    ref = reference.lower().split(".")
    for pattern in patterns:
        if not isinstance(pattern, str) or len(pattern) > 253:
            return None
        labels = pattern.lower().split(".")
        wildcard = labels[0] == "*"
        if (wildcard and len(labels) < 2) or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in (labels[1:] if wildcard else labels)):
            return None
        matched |= (len(labels) == len(ref) and ref[1:] == labels[1:]) if wildcard else labels == ref
    return matched


def _date(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except (ValueError, TypeError):
        return None


def _completed(attempt) -> dict | None:
    if (not isinstance(attempt, dict) or attempt.get("status") != "COMPLETED"
            or attempt.get("error_reason") is not None or attempt.get("error_trace") not in {None, ""}
            or not isinstance(attempt.get("result"), dict)):
        return None
    return attempt["result"]


def _certificates(endpoint: Endpoint, attempt) -> tuple[dict, dict[str, str], list]:
    values = {rule: (None, "Certificate command unavailable or incomplete") for rule in CERT_RULES}
    providers, retained = {}, []
    certificate = _completed(attempt)
    reference = endpoint.hostname or endpoint.host
    if not certificate or certificate.get("hostname_used_for_server_name_indication") != reference:
        return values, providers, retained
    deployments = certificate.get("certificate_deployments")
    if not isinstance(deployments, list) or not 1 <= len(deployments) <= 32:
        return values, providers, retained
    host_checks, expired_checks, future_checks, trust_checks = [], [], [], []
    now = datetime.now(UTC)
    for deployment in deployments:
        if not isinstance(deployment, dict):
            return values, providers, retained
        chain = deployment.get("received_certificate_chain")
        if not isinstance(chain, list) or not 1 <= len(chain) <= 32 or any(not isinstance(cert, dict) for cert in chain):
            return values, providers, retained
        leaf = chain[0]
        matches = san_matches(reference, leaf.get("subject_alternative_name"))
        host_checks.append(None if matches is None else not matches)
        before, after = _date(leaf.get("not_valid_before")), _date(leaf.get("not_valid_after"))
        valid_dates = before is not None and after is not None and before < after
        expired_checks.append(now > after if valid_dates else None)
        future_checks.append(now < before if valid_dates else None)
        validations = deployment.get("path_validation_results")
        valid_results, stores = [], []
        if not isinstance(validations, list) or not 1 <= len(validations) <= 100:
            trust_checks.append(None)
        else:
            for validation in validations:
                if not isinstance(validation, dict):
                    valid_results.append(None)
                    continue
                store = validation.get("trust_store")
                successful = validation.get("was_validation_successful")
                if (not isinstance(store, dict) or not isinstance(store.get("name"), str) or not store["name"].strip()
                        or not isinstance(store.get("version"), str) or not store["version"].strip()
                        or type(successful) is not bool
                        or successful and validation.get("validation_error") not in {None, ""}):
                    valid_results.append(None)
                    continue
                name, version = store["name"], store["version"]
                if name in providers and providers[name] != version:
                    valid_results.append(None)
                    continue
                providers[name] = version
                valid_results.append(successful)
                stores.append({"name": name, "version": version, "successful": successful,
                               "validation_error": validation.get("validation_error")})
            trust_checks.append(None if None in valid_results else not any(valid_results))
        retained.append({"reference": reference, "subject_alternative_name": leaf.get("subject_alternative_name"),
                         "not_valid_before": leaf.get("not_valid_before"), "not_valid_after": leaf.get("not_valid_after"),
                         "received_certificate_chain": chain, "path_validation_results": stores})
    summary = json.dumps(retained, ensure_ascii=True, default=str)[:16384]
    # A positive in any deployment demonstrates an issue; a negative needs every deployment assessed.
    def aggregate(items):
        return True if True in items else None if None in items else False
    for rule, items in zip(CERT_RULES, (host_checks, expired_checks, future_checks, trust_checks), strict=True):
        values[rule] = (aggregate(items), f"Reference {reference}; {rule}; certificate deployments: {summary}")
    return values, providers, retained


def _parse(document, endpoint: Endpoint) -> tuple[dict, dict[str, str], list]:
    values = {rule: (None, "TLS server/command evidence unavailable") for rule in RULES}
    if not isinstance(document, dict) or document.get("sslyze_version") != VERSION or document.get("invalid_server_strings") != []:
        return values, {}, []
    servers = document.get("server_scan_results")
    if not isinstance(servers, list) or len(servers) != 1 or not isinstance(servers[0], dict):
        return values, {}, []
    server = servers[0]
    location, network = server.get("server_location"), server.get("network_configuration")
    try:
        if (not isinstance(location, dict) or not isinstance(network, dict)
                or str(ipaddress.ip_address(location.get("ip_address", ""))) != endpoint.host
                or type(location.get("port")) is not int or location["port"] != endpoint.port
                or location.get("hostname") != (endpoint.hostname or endpoint.host)
                or location.get("connection_type") != "DIRECT" or location.get("http_proxy_settings") is not None
                or network.get("tls_server_name_indication") != (endpoint.hostname or endpoint.host)
                or network.get("tls_opportunistic_encryption") is not None):
            return values, {}, []
    except (TypeError, ValueError):
        return values, {}, []
    commands = server.get("scan_result")
    if (server.get("connectivity_status") != "COMPLETED" or server.get("scan_status") != "COMPLETED"
            or server.get("connectivity_error_trace") not in {None, ""}
            or not isinstance(server.get("connectivity_result"), dict) or not isinstance(commands, dict)):
        return values, {}, []
    cert_values, providers, retained = _certificates(endpoint, commands.get("certificate_info"))
    values.update(cert_values)
    for rule, (field, tls_version, _) in PROTOCOL_RULES.items():
        protocol = _completed(commands.get(field))
        if not protocol or protocol.get("tls_version_used") != tls_version:
            continue
        supported, accepted, rejected = protocol.get("is_tls_version_supported"), protocol.get("accepted_cipher_suites"), protocol.get("rejected_cipher_suites")
        if type(supported) is not bool or not isinstance(accepted, list) or not isinstance(rejected, list):
            continue
        if supported != bool(accepted) or not accepted and not rejected:
            continue
        if any(not isinstance(item, dict) or not isinstance(item.get("cipher_suite"), dict) or not isinstance(item["cipher_suite"].get("name"), str) for item in accepted + rejected):
            continue
        cipher_names = [item["cipher_suite"]["name"] for item in accepted]
        values[rule] = (supported, f"SSLyze {VERSION}; {tls_version}; command COMPLETED; accepted={cipher_names}; rejected={len(rejected)}")
    return values, providers, retained


class SSLyzeAdapter:
    name = "sslyze"

    def __init__(self, *, command: tuple[str, ...] | None = None):
        self._command = command

    def _probe(self, root: Path, *, deadline=None, cancel=None):
        command = command_for(self.name, self._command)
        probe = run_process([*command, "--help"], timeout=10, deadline=deadline, cancel=cancel,
                            env=isolated_environment(root), cwd=root, max_output_chars=32768)
        if probe.returncode or probe.timed_out or probe.cancelled or not re.search(r"(?i)\bsslyze\s+(?:version\s+)?v?6\.3\.1\b", probe.stdout + "\n" + probe.stderr):
            raise RuntimeError("SSLyze 6.3.1 is required; check the optional executable and --help banner")
        return command

    def available(self) -> tuple[bool, str]:
        try:
            with tempfile.TemporaryDirectory(prefix="scopescan-sslyze-probe-") as directory:
                self._probe(Path(directory))
            return True, f"SSLyze {VERSION} (external process; direct TLS only)"
        except (OSError, RuntimeError) as exc:
            return False, str(exc)

    def plan(self, scope: ScanScope, *, timeout: float = 120) -> EnginePlan:
        endpoints = tuple(e for e in scope.endpoints if e.protocol == "tcp" and e.port is not None and e.service.lower() in TLS_SERVICES)
        if not endpoints:
            raise ValueError("SSLyze needs an authorized TCP endpoint explicitly identified as direct TLS")
        if len(endpoints) * len(RULES) > 10000:
            raise ValueError("SSLyze plan exceeds 10000 observations")
        return EnginePlan(self.name, scope, endpoints, RULES, timeout)

    def execute(self, plan: EnginePlan, *, cancel: threading.Event | None = None) -> EngineResult:
        checked_plan(self, plan)
        started, deadline = stamp(), time.monotonic() + plan.timeout
        digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        observations, raw, errors, feeds = [], [], [], {}
        cancelled = failed = False
        with tempfile.TemporaryDirectory(prefix="scopescan-sslyze-") as directory:
            root = Path(directory)
            try:
                command = self._probe(root, deadline=deadline, cancel=cancel)
                env = isolated_environment(root)
                received = 0
                for number, endpoint in enumerate(plan.endpoints):
                    values = {rule: (None, "TLS check did not complete") for rule in RULES}
                    if cancel is not None and cancel.is_set():
                        cancelled = True
                    elif time.monotonic() >= deadline or received >= plan.max_output_bytes:
                        errors.append("Whole-job deadline or output budget exhausted")
                    else:
                        output = root / f"tls-{number}.json"
                        args = [*command, "--json_out", str(output), "--quiet", "--slow_connection", "--mozilla_config", "disable", "--certinfo"]
                        args += [f"--{option}" for _, _, option in PROTOCOL_RULES.values()]
                        if endpoint.hostname:
                            args += ["--sni", endpoint.hostname]
                        args += [_target(endpoint)]
                        execution = run_process(args, deadline=deadline, cancel=cancel, env=env, cwd=root,
                                                file_limits={output: plan.max_output_bytes - received},
                                                max_output_chars=min(plan.max_output_bytes, 65536))
                        cancelled |= execution.cancelled
                        if execution.returncode or execution.timed_out or execution.cancelled or execution.file_limit_exceeded or execution.output_truncated:
                            errors.append("SSLyze interrupted, failed or exceeded its output bound")
                        else:
                            try:
                                content = output.read_bytes() if output.exists() else b""
                                received += len(content)
                                document = json.loads(content)
                                values, providers, certificates = _parse(document, endpoint)
                                for provider, version in providers.items():
                                    if provider in feeds and feeds[provider] != version:
                                        errors.append("Trust-store version changed within the job")
                                        values["tls-certificate-untrusted"] = (None, "Inconsistent trust-store versions")
                                    feeds[provider] = version
                                raw.append({"endpoint": _target(endpoint), "sslyze_version": document.get("sslyze_version"),
                                            "certificate_deployments": certificates,
                                            "observations": {rule: {"vulnerable": value[0], "evidence": value[1]} for rule, value in values.items()}})
                            except (ValueError, TypeError, AttributeError) as exc:
                                errors.append(f"Invalid SSLyze JSON: {exc}")
                    for rule in RULES:
                        vulnerable, evidence = values[rule]
                        title = CERT_RULES.get(rule, f"Deprecated TLS protocol supported: {rule}")
                        observations.append(observation(endpoint, rule, vulnerable, evidence, title,
                                                        Severity.MEDIUM, engine=self.name))
            except (OSError, RuntimeError) as exc:
                failed = True
                cancelled = cancel is not None and cancel.is_set()
                errors.append(str(exc))
                seen = {(o.endpoint, o.rule_id) for o in observations}
                for endpoint in plan.endpoints:
                    for rule in RULES:
                        if (endpoint, rule) not in seen:
                            observations.append(observation(endpoint, rule, None, "TLS engine unavailable", CERT_RULES.get(rule, rule), engine=self.name))
        provenance = Provenance(self.name, VERSION, digest, feeds=tuple(sorted(feeds.items())))
        return result(self.name, provenance, observations, raw, errors, started,
                      cancelled=cancelled, failed=failed, maximum=plan.max_output_bytes)
