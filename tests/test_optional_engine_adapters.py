"""Owned fixtures follow Nuclei 3.11.1 / SSLyze 6.3.1 primary JSON schemas.

Only Python fake programs run: no installed scanners or network connections.
"""
import copy
import json
import sys
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scopescan.engine_contracts import Endpoint, ScanScope
from scopescan.models import Assessment
from scopescan.nuclei import CATALOG, NucleiAdapter, _event_result
from scopescan.sslyze_adapter import (
    PROTOCOL_RULES,
    SSLyzeAdapter,
    _parse,
    _target,
    san_matches,
)


def scope(*, tls=False, host="192.0.2.1", hostname=""):
    endpoint = Endpoint(host, 443 if tls else 80, service="https" if tls else "http", hostname=hostname)
    return ScanScope("fixture", "test operator", (endpoint,),
                     resolutions=((hostname, (host,)),) if hostname else ())


def nuclei_event(endpoint=None, *, missing=True):
    endpoint = endpoint or scope().endpoints[0]
    scheme = "https" if endpoint.service == "https" else "http"
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    response = "HTTP/1.1 200 OK\r\nServer: fixture\r\n"
    if not missing:
        response += "X-Content-Type-Options: nosniff\r\nStrict-Transport-Security: max-age=31536000\r\n"
    response += "Set-Cookie: SESSION=private-secret\r\n\r\nfixture"
    return {"template-id": "scopescan-http-missing-nosniff", "type": "http",
            "host": endpoint.host, "port": str(endpoint.port), "scheme": scheme,
            "url": f"{scheme}://{host}:{endpoint.port}", "ip": endpoint.host,
            "matcher-status": missing, "response": response, "timestamp": datetime.now(UTC).isoformat()}


def fake_nuclei(tmp_path, *, mode="normal", missing=True):
    script, log = tmp_path / "nuclei_fake.py", tmp_path / "nuclei_log.jsonl"
    script.write_text(
        "import json,sys,pathlib,os,time\n"
        "from urllib.parse import urlsplit\n"
        "a=sys.argv[1:]\n"
        "if '-version' in a:\n print('Nuclei Engine Version: v3.11.1'); sys.exit(0)\n"
        f"mode={mode!r}; missing={missing!r}\n"
        f"log=pathlib.Path({str(log)!r})\n"
        "with log.open('a') as f: f.write(json.dumps({'args':a,'env':dict(os.environ)})+'\\n')\n"
        "if mode=='after-first' and len(log.read_text().splitlines())>1: time.sleep(20)\n"
        "out=pathlib.Path(a[a.index('-jle')+1])\n"
        "if mode=='slow': time.sleep(20)\n"
        "if mode=='oversize': out.write_bytes(b'x'*100000); time.sleep(20)\n"
        "if mode=='blank': out.touch(); sys.exit(0)\n"
        "u=urlsplit(a[a.index('-u')+1]); rule=pathlib.Path(a[a.index('-t')+1]).stem\n"
        "header='x-content-type-options' if rule.endswith('nosniff') else 'strict-transport-security'\n"
        "response='HTTP/1.1 200 OK\\r\\nSet-Cookie: SESSION=private-secret\\r\\n'\n"
        "if not missing: response+=header+': good\\r\\n'\n"
        "response+='\\r\\nbody-secret'\n"
        "e={'template-id':rule,'type':'http','host':u.hostname,'port':str(u.port),'scheme':u.scheme,'url':u.geturl(),'ip':u.hostname,'matcher-status':missing,'response':response}\n"
        "out.write_text(json.dumps(e)+'\\n')\n", encoding="utf-8")
    return NucleiAdapter(command=(sys.executable, str(script))), log


def tls_document(endpoint=None):
    """Fields from SSLyze's JSON models; no invented hostname_matches_cert boolean."""
    endpoint = endpoint or scope(tls=True, hostname="service.example.test").endpoints[0]
    now = datetime.now(UTC)
    cert = {"as_pem": "PUBLIC FIXTURE CERTIFICATE", "fingerprint_sha256": "fixture-public-hash",
            "subject_alternative_name": {"dns_names": [endpoint.hostname] if endpoint.hostname else [],
                                         "ip_addresses": [] if endpoint.hostname else [endpoint.host]},
            "not_valid_before": (now - timedelta(days=30)).isoformat(),
            "not_valid_after": (now + timedelta(days=90)).isoformat(),
            "subject": {"rfc4514_string": "CN=ignored.example.test"}, "issuer": {"rfc4514_string": "CN=Fixture CA"}}
    deployment = {"received_certificate_chain": [cert], "path_validation_results": [
        {"trust_store": {"name": "Mozilla", "version": "2026-09-01", "path": "fixture.pem"},
         "was_validation_successful": True, "validation_error": None, "verified_certificate_chain": [cert]}]}
    commands = {"certificate_info": {"status": "COMPLETED", "error_reason": None, "error_trace": None,
                                     "result": {"hostname_used_for_server_name_indication": endpoint.hostname or endpoint.host,
                                                "certificate_deployments": [deployment]}}}
    for field, version, _ in PROTOCOL_RULES.values():
        commands[field] = {"status": "COMPLETED", "error_reason": None, "error_trace": None,
                           "result": {"tls_version_used": version, "is_tls_version_supported": False,
                                      "accepted_cipher_suites": [], "rejected_cipher_suites": [
                                          {"cipher_suite": {"name": "FIXTURE_REJECTED"}, "error_message": "rejected"}]}}
    return {"sslyze_version": "6.3.1", "invalid_server_strings": [], "server_scan_results": [
        {"server_location": {"hostname": endpoint.hostname or endpoint.host, "port": endpoint.port,
                             "ip_address": endpoint.host, "connection_type": "DIRECT", "http_proxy_settings": None},
         "network_configuration": {"tls_server_name_indication": endpoint.hostname or endpoint.host,
                                   "tls_opportunistic_encryption": None},
         "connectivity_status": "COMPLETED", "connectivity_error_trace": None,
         "connectivity_result": {"highest_tls_version_supported": "TLS_1_3"},
         "scan_status": "COMPLETED", "scan_result": commands}],
        "date_scans_started": now.isoformat(), "date_scans_completed": now.isoformat()}


def fake_sslyze(tmp_path, document, *, mode="normal"):
    script, log = tmp_path / "sslyze_fake.py", tmp_path / "sslyze_log.jsonl"
    script.write_text(
        "import json,sys,pathlib,os,time\n"
        "a=sys.argv[1:]\n"
        "if '--help' in a:\n print('SSLyze version 6.3.1'); sys.exit(0)\n"
        f"mode={mode!r}; document={document!r}\n"
        f"log=pathlib.Path({str(log)!r})\n"
        "with log.open('a') as f: f.write(json.dumps({'args':a,'env':dict(os.environ)})+'\\n')\n"
        "if mode=='after-first' and len(log.read_text().splitlines())>1: time.sleep(20)\n"
        "out=pathlib.Path(a[a.index('--json_out')+1])\n"
        "if mode=='slow': time.sleep(20)\n"
        "if mode=='oversize': out.write_bytes(b'x'*100000); time.sleep(20)\n"
        "out.write_text(json.dumps(document))\n", encoding="utf-8")
    return SSLyzeAdapter(command=(sys.executable, str(script))), log


def leaf(document):
    return document["server_scan_results"][0]["scan_result"]["certificate_info"]["result"]["certificate_deployments"][0]["received_certificate_chain"][0]


def test_nuclei_fake_execution_positive_exact_endpoint_and_config_isolation(tmp_path, monkeypatch):
    for key in ("NUCLEI_CONFIG_DIR", "NUCLEI_FOO", "HTTP_PROXY", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(key, "private-parent-secret")
    adapter, log = fake_nuclei(tmp_path)
    grant = scope(host="2001:db8::1", hostname="operator.example.test")
    output = adapter.execute(adapter.plan(grant))
    assert output.status == "complete"
    assert output.observations[0].outcome == "positive"
    assert output.observations[0].finding.assessment == Assessment.EXPOSURE
    assert output.observations[0].finding.port == 80
    assert b"private-secret" not in output.raw and b"body-secret" not in output.raw
    row = json.loads(log.read_text().splitlines()[0])
    args = row["args"]
    assert args[args.index("-u") + 1] == "http://[2001:db8::1]:80"
    assert args[args.index("-H") + 1] == "Host: operator.example.test"
    assert args[args.index("-sni") + 1] == "operator.example.test"
    assert {"-dr", "-ni", "-duc", "-ms", "-pt", "-rsr", "-rss"} <= set(args)
    assert row["env"]["NUCLEI_CONFIG_DIR"] != "private-parent-secret"
    assert not {"NUCLEI_FOO", "HTTP_PROXY", "AWS_SECRET_ACCESS_KEY"} & row["env"].keys()
    assert not Path(args[args.index("-t") + 1]).exists()  # private copies cleaned up


def test_nuclei_fake_complete_negative_and_https_hsts(tmp_path):
    adapter, _ = fake_nuclei(tmp_path, missing=False)
    output = adapter.execute(adapter.plan(scope(tls=True)))
    assert output.status == "complete"
    assert len(output.observations) == 2
    assert all(o.outcome == "negative" and o.evidence for o in output.observations)
    assert len(output.provenance.templates) == 2


def test_nuclei_blank_output_never_resolves(tmp_path):
    adapter, _ = fake_nuclei(tmp_path, mode="blank")
    output = adapter.execute(adapter.plan(scope()))
    assert output.status == "partial"
    assert output.observations[0].outcome == "unknown"


@pytest.mark.parametrize("mutation", [
    {"port": 80}, {"ip": "192.0.2.2"}, {"url": "http://outside.test:80/"},
    {"template-id": "custom-unsafe"}, {"type": "code"}, {"matcher-status": "false"},
    {"error": "timeout"}, {"response": "HTTP/1.1 200 OK\r\nServer: incomplete"},
    {"response": "HTTP/1.1 200 OK\r\nX-Test: first\r\nX-Test: second\r\n\r\n"},
    {"response": "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n"},
])
def test_nuclei_rejects_unbound_incomplete_or_contradictory_events(mutation):
    event = nuclei_event()
    event.update(mutation)
    assert _event_result(event, scope().endpoints[0], "scopescan-http-missing-nosniff")[0] is None


def test_nuclei_template_tamper_refused_before_scan(tmp_path, monkeypatch):
    from scopescan import nuclei
    adapter, log = fake_nuclei(tmp_path)
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    (catalog / "scopescan-http-missing-nosniff.yaml").write_text("id: attacker\ncode: []")
    monkeypatch.setattr(nuclei, "TEMPLATE_ROOT", catalog)
    output = adapter.execute(adapter.plan(scope()))
    assert output.status == "failed"
    assert "integrity" in output.errors[0]
    assert not log.exists()


def test_reviewed_templates_are_only_get_baseurl_fixed_bytes():
    import hashlib

    from scopescan import nuclei
    for rule, (digest, _, _) in CATALOG.items():
        content = (nuclei.TEMPLATE_ROOT / f"{rule}.yaml").read_bytes()
        assert hashlib.sha256(content).hexdigest() == digest
        assert b"method: GET" in content and b'"{{BaseURL}}/"' in content
        assert b"redirects: false" in content
        assert all(token not in content for token in (b"raw:", b"flow:", b"code:", b"headless:", b"interactsh", b"workflows:"))


@pytest.mark.parametrize("adapter_name", ["nuclei", "sslyze"])
def test_adapters_silent_file_overflow_and_precancel(tmp_path, adapter_name):
    grant = scope(tls=adapter_name == "sslyze")
    adapter, _ = fake_nuclei(tmp_path, mode="oversize") if adapter_name == "nuclei" else fake_sslyze(tmp_path, tls_document(grant.endpoints[0]), mode="oversize")
    plan = replace(adapter.plan(grant), max_output_bytes=1024)
    output = adapter.execute(plan)
    assert output.status == "partial"
    assert all(o.outcome == "unknown" for o in output.observations)
    assert any("bound" in e for e in output.errors)
    cancel = threading.Event()
    cancel.set()
    assert adapter.execute(plan, cancel=cancel).status == "cancelled"


def test_sslyze_fake_execution_real_flags_complete_proof_and_trust_versions(tmp_path):
    grant = scope(tls=True, host="2001:db8::2", hostname="service.example.test")
    adapter, log = fake_sslyze(tmp_path, tls_document(grant.endpoints[0]))
    output = adapter.execute(adapter.plan(grant))
    assert output.status == "complete"
    assert all(o.outcome == "negative" and o.evidence for o in output.observations)
    assert output.provenance.feeds == (("Mozilla", "2026-09-01"),)
    assert b"received_certificate_chain" in output.raw and b"PUBLIC FIXTURE CERTIFICATE" in output.raw
    args = json.loads(log.read_text().splitlines()[0])["args"]
    assert args[-1] == "service.example.test:443{2001:db8::2}"
    assert args[args.index("--sni") + 1] == "service.example.test"
    assert args[args.index("--mozilla_config") + 1] == "disable"
    assert args[args.index("--json_out") + 1] != "-"
    assert {"--quiet", "--slow_connection", "--certinfo", "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1"} <= set(args)
    assert "--json_outfile" not in args and "--version" not in args and "--max_connections" not in args
    assert _target(scope(tls=True, host="2001:db8::2").endpoints[0]) == "[2001:db8::2]:443{2001:db8::2}"


def test_sslyze_positive_hostname_dates_trust_and_protocol_are_separate(tmp_path):
    grant = scope(tls=True, hostname="service.example.test")
    document = tls_document(grant.endpoints[0])
    leaf(document)["subject_alternative_name"]["dns_names"] = ["different.example.test"]
    leaf(document)["not_valid_after"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    commands = document["server_scan_results"][0]["scan_result"]
    validation = commands["certificate_info"]["result"]["certificate_deployments"][0]["path_validation_results"][0]
    validation.update(was_validation_successful=False, validation_error="certificate expired")
    commands["tls_1_0_cipher_suites"]["result"].update(is_tls_version_supported=True,
        accepted_cipher_suites=[{"cipher_suite": {"name": "FIXTURE_ACCEPTED"}}])
    adapter, _ = fake_sslyze(tmp_path, document)
    output = adapter.execute(adapter.plan(grant))
    assert output.status == "complete"
    positives = {o.rule_id for o in output.observations if o.outcome == "positive"}
    assert positives == {"tls-certificate-hostname", "tls-certificate-expired", "tls-certificate-untrusted", "tls-deprecated-tls10"}
    assert all(o.finding.assessment == Assessment.CONFIRMED for o in output.observations if o.finding)


@pytest.mark.parametrize("mutation", [
    {"sslyze_version": "6.3.2"}, {"invalid_server_strings": [{"error_message": "failed"}]},
    {"server_scan_results": []},
])
def test_sslyze_wrong_version_invalid_or_missing_server_is_unknown(mutation):
    document = tls_document()
    document.update(mutation)
    assert all(v[0] is None for v in _parse(document, scope(tls=True, hostname="service.example.test").endpoints[0])[0].values())


@pytest.mark.parametrize("path,value", [
    (("server_location", "ip_address"), "192.0.2.9"),
    (("server_location", "port"), "443"),
    (("network_configuration", "tls_server_name_indication"), "unrequested.example.test"),
    (("connectivity_status",), "ERROR"), (("scan_status",), "ERROR_NO_CONNECTIVITY"),
])
def test_sslyze_unbound_or_failed_connection_never_proves_negative(path, value):
    document = tls_document()
    row = document["server_scan_results"][0]
    for key in path[:-1]:
        row = row[key]
    row[path[-1]] = value
    assert all(v[0] is None for v in _parse(document, scope(tls=True, hostname="service.example.test").endpoints[0])[0].values())


@pytest.mark.parametrize("status", ["ERROR", "NOT_SCHEDULED", None])
def test_sslyze_incomplete_certificate_command_is_unknown(status):
    document = tls_document()
    document["server_scan_results"][0]["scan_result"]["certificate_info"]["status"] = status
    values, _, _ = _parse(document, scope(tls=True, hostname="service.example.test").endpoints[0])
    assert all(v[0] is None for rule, v in values.items() if rule.startswith("tls-certificate"))


def test_sslyze_missing_san_invalid_dates_and_unavailable_trust_remain_unknown():
    document = tls_document()
    cert = leaf(document)
    cert.pop("subject_alternative_name")
    cert["not_valid_after"] = "invalid"
    document["server_scan_results"][0]["scan_result"]["certificate_info"]["result"]["certificate_deployments"][0]["path_validation_results"] = []
    values, _, _ = _parse(document, scope(tls=True, hostname="service.example.test").endpoints[0])
    assert all(v[0] is None for rule, v in values.items() if rule.startswith("tls-certificate"))


@pytest.mark.parametrize("reference,names,ips,expected", [
    ("www.example.test", ["WWW.EXAMPLE.TEST"], [], True),
    ("www.example.test", ["*.example.test"], [], True),
    ("deep.www.example.test", ["*.example.test"], [], False),
    ("example.test", ["*.example.test"], [], False),
    ("www.example.test", ["w*.example.test"], [], None),
    ("www.example.test", ["*.*.test"], [], None),
    ("192.0.2.1", [], ["192.0.2.1"], True),
    ("192.0.2.1", ["192.0.2.1"], [], False),
    ("2001:db8::1", [], ["2001:0db8::1"], True),
    ("www.example.test", [], [], None),
])
def test_san_matching_rfc9525_no_common_name_fallback(reference, names, ips, expected):
    assert san_matches(reference, {"dns_names": names, "ip_addresses": ips}) is expected


@pytest.mark.parametrize("adapter", [NucleiAdapter(), SSLyzeAdapter()])
def test_plan_rejects_host_controls_nonservice_and_unreviewed_options(adapter):
    host_grant = ScanScope("test", "operator", (Endpoint("192.0.2.1", None, "host"),))
    with pytest.raises(ValueError):
        adapter.plan(host_grant)
    grant = scope(tls=True)
    plan = adapter.plan(grant)
    with pytest.raises(ValueError, match="reviewed"):
        adapter.execute(replace(plan, options=(("arbitrary_cli", "-code"),)))


def test_optional_engine_unavailable_is_actionable(tmp_path):
    adapter = NucleiAdapter(command=(str(tmp_path / "missing_engine.exe"),))
    okay, message = adapter.available()
    assert not okay and "unavailable" in message


@pytest.mark.parametrize("engine", ["nuclei", "sslyze"])
def test_whole_job_deadline_across_multiple_endpoints(tmp_path, engine):
    initial = scope(tls=engine == "sslyze")
    grant = replace(initial, endpoints=initial.endpoints + (replace(initial.endpoints[0], host="192.0.2.2"),))
    adapter, log = (fake_nuclei(tmp_path, mode="after-first") if engine == "nuclei"
                    else fake_sslyze(tmp_path, tls_document(grant.endpoints[0]), mode="after-first"))
    started = time.monotonic()
    output = adapter.execute(adapter.plan(grant, timeout=4))
    elapsed = time.monotonic() - started
    assert output.status == "partial"
    assert any(o.outcome != "unknown" and o.endpoint.host == "192.0.2.1" for o in output.observations)
    assert all(o.outcome == "unknown" for o in output.observations if o.endpoint.host == "192.0.2.2")
    assert 3 < elapsed < 6
    assert len(log.read_text().splitlines()) == 2


@pytest.mark.parametrize("engine", ["nuclei", "sslyze"])
def test_cancel_actual_silent_engine_operation(tmp_path, engine):
    grant = scope(tls=engine == "sslyze")
    adapter, log = (fake_nuclei(tmp_path, mode="slow") if engine == "nuclei"
                    else fake_sslyze(tmp_path, tls_document(grant.endpoints[0]), mode="slow"))
    cancel = threading.Event()
    timer = threading.Timer(3, cancel.set)
    timer.start()
    try:
        output = adapter.execute(adapter.plan(grant), cancel=cancel)
    finally:
        timer.cancel()
    assert output.status == "cancelled"
    assert all(o.outcome == "unknown" for o in output.observations)
    assert log.exists()


def test_multiple_certificate_deployments_any_bad_and_all_required_for_negative():
    grant = scope(tls=True, hostname="service.example.test")
    document = tls_document(grant.endpoints[0])
    deployments = document["server_scan_results"][0]["scan_result"]["certificate_info"]["result"]["certificate_deployments"]
    bad = copy.deepcopy(deployments[0])
    bad["received_certificate_chain"][0]["subject_alternative_name"]["dns_names"] = ["other.example.test"]
    bad["received_certificate_chain"][0]["not_valid_after"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    deployments.append(bad)
    values, _, _ = _parse(document, grant.endpoints[0])
    assert values["tls-certificate-hostname"][0] is True
    assert values["tls-certificate-expired"][0] is True
    bad["received_certificate_chain"][0].pop("subject_alternative_name")
    values, _, _ = _parse(document, grant.endpoints[0])
    assert values["tls-certificate-hostname"][0] is None


def test_present_but_malformed_san_never_proves_identity():
    assert san_matches("service.example.test", {"dns_names": ["service.example.test"], "ip_addresses": ["invalid"]}) is None
    assert san_matches("192.0.2.1", {"dns_names": [12], "ip_addresses": ["192.0.2.1"]}) is None


def test_normalized_and_raw_evidence_redacts_embedded_secret_values():
    from scopescan._adapter_support import observation, sanitized
    proof = "Header evidence token=private-token\nSet-Cookie: private-cookie\napi_key=private-key"
    output = observation(scope().endpoints[0], "fixture-rule", True, proof, "Fixture", engine="nuclei")
    assert "private-" not in output.evidence
    assert "private-" not in output.finding.evidence
    assert b"private-" not in sanitized({"evidence": proof})
