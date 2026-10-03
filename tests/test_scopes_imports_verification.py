from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scopescan import db, importers, msf, nmap_parser, nmap_runner, scopes, service, verification
from scopescan.models import Finding, Host, NmapRun, Port, ScriptResult, Severity
from scopescan.targets import InvalidTarget


def test_scope_pins_dns_excludes_and_worker_never_resolves_again(monkeypatch, tmp_path):
    answers = [(2, 1, 6, "", ("192.168.1.10", 0)), (2, 1, 6, "", ("192.168.1.11", 0))]
    monkeypatch.setattr(scopes.socket, "getaddrinfo", lambda *a, **k: answers)
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda: "nmap")
    sid = scopes.create_scope(name="Lab", targets="lab.example", exclusions="192.168.1.11",
                              authorized_by="owner", profile="rapido")
    preview = scopes.preview_scope(sid)
    assert preview.target_set.argv == ["192.168.1.10"]
    monkeypatch.setattr(scopes.socket, "getaddrinfo", lambda *a, **k: pytest.fail("DNS rebinding"))
    scan_id = scopes.queue_scope(sid)
    executed = []
    monkeypatch.setattr(nmap_runner, "run", lambda argv, **kwargs:
                        (executed.append(argv) or nmap_runner.NmapExecution(
                            argv, tmp_path / "absent.xml", 1, "", "fake failure")))
    service.execute(scan_id)
    assert executed[0][:-2] == preview.argv_preview[:-2]
    assert executed[0][-1] == "192.168.1.10"
    assert "lab.example" not in executed[0]


def test_scope_namespace_cannot_accept_unrelated_targets():
    sid = scopes.create_scope(name="Lab", targets="192.168.1.10", authorized_by="owner")
    with pytest.raises(InvalidTarget, match="no coincide"):
        service.queue_scan(service.ScanRequest(targets="8.8.8.8", scope_id=sid))


def test_scope_ranges_bounded_ipv6_and_mixed_rejected():
    assert scopes.pin_targets("10.0.0.1-3", "10.0.0.2").target_set.argv == ["10.0.0.1", "10.0.0.3"]
    with pytest.raises(InvalidTarget):
        scopes.pin_targets("10.0.0.0/8", force=True)
    with pytest.raises(InvalidTarget, match="mezcla"):
        scopes.pin_targets("192.168.1.1 ::1")
    argv = nmap_runner.build_argv(targets=["::1"], profile_args=["-sT"],
                                   xml_path=Path("output.xml"), nmap_path="nmap")
    assert "-6" in argv and "-n" in argv


def test_scope_update_repins_without_mutating_historical_job():
    sid = scopes.create_scope(name="Lab", targets="192.168.1.10", authorized_by="owner")
    scan_id = scopes.queue_scope(sid)
    scopes.update_scope(sid, name="Lab", targets="192.168.1.11", authorized_by="owner")
    assert json.loads(db.get_scan(scan_id)["execution_context"])["pinned_targets"] == ["192.168.1.10"]
    assert scopes.get_scope(sid)["pinned_targets"] == ["192.168.1.11"]


def test_parser_actual_coverage_and_timeouts(nmap_xml):
    run = nmap_parser.parse_string(nmap_xml.replace('<host starttime=', '<host timedout="true" starttime=', 1))
    assert run.coverage["status"] == "partial"
    assert len(run.coverage["protocols"]["tcp"]) == 65535
    assert run.coverage["timed_out_hosts"] == ["192.168.1.10"]
    assert run.provenance["finished_exit"] == "success"


def test_parser_no_finished_success_no_complete(nmap_xml):
    run = nmap_parser.parse_string(nmap_xml.replace('exit="success"', ''))
    assert run.coverage["status"] == "partial"


def test_xml_harmless_dtd_allowed_entities_rejected(tmp_path):
    xml = '<!DOCTYPE nmaprun SYSTEM "nmap.dtd"><nmaprun version="7.95"/>'
    assert nmap_parser.parse_string(xml).scanner_version == "7.95"
    attack = '<!DOCTYPE nmaprun [<!ENTITY x "private">]><nmaprun>&x;</nmaprun>'
    path = tmp_path / "hostile.xml"
    path.write_text(attack)
    with pytest.raises(nmap_parser.NmapParseError):
        nmap_parser.parse_file(path)


def test_xml_depth_and_size_bounds(monkeypatch):
    with pytest.raises(nmap_parser.NmapParseError, match="profundidad"):
        nmap_parser.parse_string('<nmaprun>' + '<a>' * 101 + '</a>' * 101 + '</nmaprun>')
    monkeypatch.setattr(nmap_parser, "MAX_XML_BYTES", 10)
    with pytest.raises(nmap_parser.NmapParseError, match="limite"):
        nmap_parser.parse_string('<nmaprun version="7.95"/>')


def test_import_nmap_raw_copy_hash_and_claims(xml_file):
    scan_id = importers.import_nmap(xml_file, namespace="lab", name="external")
    row = db.get_scan(scan_id)
    context = json.loads(row["execution_context"])
    path = Path(row["raw_xml_path"])
    assert path != xml_file and path.read_bytes() == xml_file.read_bytes()
    assert context["provenance"]["sha256"] == hashlib.sha256(xml_file.read_bytes()).hexdigest()
    assert context["provenance"]["imported"] is True
    findings = db.get_findings(scan_id)
    assert findings and all(not f["confirmed"] and f["assessment"] == "candidate" for f in findings)
    second = importers.import_nmap(xml_file)
    assert db.get_scan(second)["raw_xml_path"] != str(path)
    with pytest.raises(ValueError, match="no es una orden"):
        service.rerun(scan_id)
    with pytest.raises(msf.MsfScopeError, match="importado"):
        msf.verify_scan(scan_id)


def _external():
    return {"schema": importers.EXTERNAL_SCHEMA, "engine": "scanner", "engine_version": "1",
            "rules_version": "rules-1", "observed_at": "2026-09-30T10:00:00Z",
            "coverage": {"status": "complete", "protocols": {"tcp": [23]}, "rules": ["telnet"]},
            "hosts": [{"address": "192.168.1.10", "state": "up", "ports": [
                {"port": 23, "protocol": "tcp", "state": "open", "service": {"name": "telnet"}}]}],
            "findings": [{"host": "192.168.1.10", "port": 23, "protocol": "tcp",
                          "rule_id": "telnet", "title": "Telnet", "severity": "high",
                          "confirmed": True, "assessment": "confirmed", "module": "malicious"}],
            "raw_xml_path": "C:/secret", "job_id": 1, "args": "--script evil"}


def test_external_json_normalized_contract_ignores_instructions(tmp_path):
    path = tmp_path / "external.json"
    path.write_text(json.dumps(_external()))
    sid = importers.import_external_json(path)
    row = db.get_scan(sid)
    findings = db.get_findings(sid)
    assert findings[0]["source"] == "external:scanner:telnet"
    assert findings[0]["confirmed"] == 0
    assert row["nmap_args"] == ""
    assert db.get_msf_results(sid) == []
    assert json.loads(row["execution_context"])["coverage"]["protocols"] == {"tcp": [23]}


@pytest.mark.parametrize("field,value", [("schema", "bogus"), ("engine", "--script evil"),
                                         ("observed_at", "yesterday")])
def test_external_invalid_contract_rejected(tmp_path, field, value):
    document = _external()
    document[field] = value
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(document))
    with pytest.raises(importers.ImportError):
        importers.import_external_json(path)


def _current(source, port=23, protocol="tcp"):
    sid = db.create_scan(name="baseline", targets="192.168.1.10", profile="rapido")
    db.set_scan_context(sid, execution_context={"namespace": "lab"})
    run = NmapRun(hosts=[Host(address="192.168.1.10", state="up", ports=[Port(portid=23, state="open")])])
    db.save_results(sid, run, [Finding(title="issue", severity=Severity.HIGH, source=source,
                                      host="192.168.1.10", port=port, protocol=protocol)], 50)
    db.set_status(sid, "done")
    return next(f["id"] for f in db.list_current_findings()[0] if f["source"] == source)


def test_verification_owned_rule_and_unknown_imported_script(monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda: "nmap")
    fid = _current("rule:telnet-claro")
    plan = verification.plan_verification([fid], authorized_by="owner")
    assert plan.requests[0]["verification"]["ports"] == [23]
    assert plan.previews[0][-1] == "192.168.1.10"
    sid = verification.queue_verification(plan)[0]
    context = json.loads(db.get_scan(sid)["execution_context"])
    assert context["namespace"] == "lab" and context["verification_of"] == [fid]
    evil = _current("nse:../../evil")
    assert verification.plan_verification([evil], authorized_by="owner").missing_controls
    with pytest.raises(ValueError, match="lista permitida"):
        verification.nmap_args_for_verification({"protocol": "tcp", "ports": [23], "scripts": ["evil"]},
                                                privileged=False)


def test_authenticated_unknown_vs_known_control_evidence():
    unknown = verification.authenticated_coverage("linux", {}, set())
    assert unknown["controls"]["auth:linux:aslr"] == "unknown"
    assert "auth:linux:aslr" not in unknown["control_evidence"]
    good = verification.authenticated_coverage("linux", {"aslr": 2}, set())
    assert good["controls"]["auth:linux:aslr"] == "pass"
    assert "observed=2" in good["control_evidence"]["auth:linux:aslr"]


def test_authenticated_verification_configured_identity_executes_owned_collector(monkeypatch):
    from scopescan import linux_inventory
    fid = _current("auth:linux:aslr", port=None, protocol="host")
    assert verification.plan_verification([fid], authorized_by="owner", identity_configured=True).missing_controls
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    monkeypatch.setattr(linux_inventory, "collect", lambda host, **kwargs:
                        {"platform": "linux", "aslr": 2, "ssh_port": 22})
    plan = verification.plan_verification([fid], authorized_by="owner")
    sid = verification.queue_verification(plan)[0]
    service.execute(sid)
    assert db.get_scan(sid)["status"] == "done"
    coverage = json.loads(db.get_scan(sid)["execution_context"])["coverage"]
    assert coverage["controls"]["auth:linux:aslr"] == "pass"
    assert db.get_host_inventories(sid)["192.168.1.10"]["aslr"] == 2


AUTH_CASES = [
    ("linux", "ssh-root", {"sshd": {"permit_root_login": "yes"}}, {"sshd": {"permit_root_login": "no"}}),
    ("linux", "ssh-password", {"sshd": {"password_authentication": "yes"}}, {"sshd": {"password_authentication": "no"}}),
    ("linux", "ssh-empty-passwords", {"sshd": {"permit_empty_passwords": "yes"}}, {"sshd": {"permit_empty_passwords": "no"}}),
    ("linux", "ssh-max-auth-tries", {"sshd": {"max_auth_tries": "10"}}, {"sshd": {"max_auth_tries": "6"}}),
    ("linux", "firewall", {"firewall": {"observed": True, "active": False}}, {"firewall": {"observed": True, "active": True}}),
    ("linux", "aslr", {"aslr": 0}, {"aslr": 2}),
    ("linux", "selinux", {"os_id": "fedora", "selinux": "disabled"}, {"os_id": "fedora", "selinux": "enforcing"}),
    ("linux", "apparmor", {"apparmor": "n"}, {"apparmor": "y"}),
    ("linux", "reboot", {"reboot_required": True}, {"reboot_required": False}),
    ("linux", "security-updates", {"security_updates_checked": True, "security_updates": [{"name": "package"}]},
     {"security_updates_checked": True, "security_updates": []}),
    ("windows", "smb1", {"smb_server": {"smb1_enabled": True}}, {"smb_server": {"smb1_enabled": False}}),
    ("windows", "smb-signing", {"smb_server": {"signing_required": False}}, {"smb_server": {"signing_required": True}}),
    ("windows", "rdp-nla", {"rdp": {"nla_required": False}}, {"rdp": {"nla_required": True}}),
    ("windows", "winrm-unencrypted", {"winrm": {"allow_unencrypted": True}}, {"winrm": {"allow_unencrypted": False}}),
    ("windows", "winrm-basic", {"winrm": {"basic_auth": True}}, {"winrm": {"basic_auth": False}}),
    ("windows", "guest", {"guest_account": {"enabled": True}}, {"guest_account": {"enabled": False}}),
    ("windows", "remote-registry", {"remote_registry": {"running": True}}, {"remote_registry": {"running": False}}),
    ("windows", "uac", {"uac_enabled": False}, {"uac_enabled": True}),
    ("windows", "secure-boot", {"secure_boot_enabled": False}, {"secure_boot_enabled": True}),
    ("windows", "llmnr", {"llmnr_enabled": True}, {"llmnr_enabled": False}),
    ("windows", "bitlocker", {"bitlocker": {"protection_status": "Off"}}, {"bitlocker": {"protection_status": "On"}}),
    ("windows", "defender-realtime", {"defender": {"antivirus_enabled": True, "realtime_enabled": False}},
     {"defender": {"antivirus_enabled": True, "realtime_enabled": True}}),
    ("windows", "defender-signatures", {"defender": {"antivirus_enabled": True, "signature_age_days": 8}},
     {"defender": {"antivirus_enabled": True, "signature_age_days": 1}}),
    ("windows", "firewall:public", {"firewall_profiles": [{"name": "Public", "active": True, "enabled": False}]},
     {"firewall_profiles": [{"name": "Public", "active": True, "enabled": True}]}),
]


@pytest.mark.parametrize("platform,key,bad,good", AUTH_CASES)
def test_authenticated_predicates_match_real_finding_rules(platform, key, bad, good):
    from scopescan import authenticated_checks
    source = f"auth:{platform}:{key}"
    if platform == "linux" and key.startswith("ssh-"):
        bad = {**bad, "ssh_port": 22}
        good = {**good, "ssh_port": 22}
    ports = {22, 445, 3389, 5985}
    findings = getattr(authenticated_checks, f"{platform}_findings")
    assert source in {f.source for f in findings("192.168.1.10", bad, ports)}
    assert source not in {f.source for f in findings("192.168.1.10", good, ports)}
    assert verification.authenticated_coverage(platform, bad, ports)["controls"][source] == "fail"
    assert verification.authenticated_coverage(platform, good, ports)["controls"][source] == "pass"
    assert verification.authenticated_coverage(platform, {}, ports, sources=[source])["controls"][source] == "unknown"


def test_cancel_after_collection_never_reconciles_negative_evidence(monkeypatch):
    import threading

    from scopescan import linux_inventory
    fid = _current("auth:linux:aslr", port=None, protocol="host")
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    cancel = threading.Event()
    def collect(host, **kwargs):
        cancel.set()
        return {"platform": "linux", "aslr": 2, "ssh_port": 22}
    monkeypatch.setattr(linux_inventory, "collect", collect)
    sid = verification.queue_verification(verification.plan_verification([fid], authorized_by="owner"))[0]
    service.execute(sid, cancel=cancel)
    assert db.get_scan(sid)["status"] == "cancelled"
    assert db.get_finding(fid)["lifecycle"] != "resolved"


def test_queued_cancel_never_invokes_auth_collector(monkeypatch):
    import threading

    from scopescan import linux_inventory
    fid = _current("auth:linux:aslr", port=None, protocol="host")
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    monkeypatch.setattr(linux_inventory, "collect", lambda *a, **k: pytest.fail("collector called"))
    sid = verification.queue_verification(verification.plan_verification([fid], authorized_by="owner"))[0]
    cancel = threading.Event()
    cancel.set()
    service.execute(sid, cancel=cancel)
    assert db.get_scan(sid)["status"] == "cancelled"


def test_older_external_import_does_not_replace_current_newer(tmp_path):
    path = tmp_path / "current.json"
    document = _external()
    document["observed_at"] = "2026-10-03T10:00:00Z"
    document["findings"][0]["title"] = "Latest title"
    path.write_text(json.dumps(document))
    first = importers.import_external_json(path, namespace="external-lab")
    document["observed_at"] = "2026-09-30T10:00:00Z"
    document["findings"][0]["title"] = "Older title"
    path.write_text(json.dumps(document))
    importers.import_external_json(path, namespace="external-lab")
    current = db.list_current_findings()[0][0]
    assert current["title"] == "Latest title" and current["scan_id"] == first


@pytest.mark.parametrize("output,expected", [("anything", False), ("State: NOT VULNERABLE", True),
    ("State: NOT VULNERABLE\nERROR: skipped", False), ("State: VULNERABLE", False),
    ("NOT VULNERABLE", False), ("State: NOT VULNERABLE\nState: LIKELY VULNERABLE", False)])
def test_nse_negative_requires_explicit_complete_owned_state(output, expected):
    assert bool(verification.nse_negative_evidence(ScriptResult("ssl-heartbleed", output))) == expected


def test_ssl_cert_negative_requires_both_validity_dates():
    assert not verification.nse_negative_evidence(ScriptResult("ssl-cert", "Subject: CN=example"))
    assert not verification.nse_negative_evidence(ScriptResult("ssl-cert", "Not valid after: 2099-01-01T00:00:00"))
    script = ScriptResult("ssl-cert", "Not valid before: 2020-01-01T00:00:00\nNot valid after: 2099-01-01T00:00:00")
    assert verification.nse_negative_evidence(script)


@pytest.mark.parametrize("change", [
    ('portid="22"', 'portid="999999"'), ('protocol="tcp" portid="22"', 'protocol="evil" portid="22"'),
    ('addr="192.168.1.10"', 'addr="not-an-ip"'), ('elapsed="121.45"', 'elapsed="NaN"'),
    ('id="ssl-cert"', 'id="../../evil"'), ('state="open"', 'state="garbage"')])
def test_nmap_import_rejects_invalid_normalized_fields(tmp_path, nmap_xml, change):
    path = tmp_path / "invalid.xml"
    path.write_text(nmap_xml.replace(*change))
    with pytest.raises(importers.ImportError):
        importers.import_nmap(path)


def test_authenticated_complete_fix_closes_with_actual_predicate(monkeypatch):
    from scopescan import authenticated_checks, linux_inventory
    fid = _current("auth:linux:aslr", port=None, protocol="host")
    baseline = db.get_finding(fid)["scan_id"]
    bad = {"platform": "linux", "aslr": 0, "ssh_port": 22}
    db.save_host_inventory(baseline, "192.168.1.10", bad, "openssh",
        findings=authenticated_checks.linux_findings("192.168.1.10", bad, set()))
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    monkeypatch.setattr(linux_inventory, "collect", lambda host, **kwargs:
                        {"platform": "linux", "aslr": 2, "ssh_port": 22})
    sid = verification.queue_verification(verification.plan_verification([fid], authorized_by="owner"))[0]
    service.execute(sid)
    assert db.get_finding(fid)["lifecycle"] == "resolved"
    assert db.get_finding(fid)["verification_scan_id"] == sid


@pytest.mark.parametrize("certificate_output,expected", [
    ("Subject: CN=example", "not_assessed"),
    ("Not valid before: 2020-01-01T00:00:00&#10;Not valid after: 2099-01-01T00:00:00", "resolved")])
def test_certificate_closure_requires_complete_negative_coverage(nmap_xml, certificate_output, expected):
    from scopescan import analysis
    expired = nmap_xml.replace("Subject: commonName=servidor.local",
                              "Not valid before: 2000-01-01T00:00:00&#10;Not valid after: 2001-01-01T00:00:00")
    def save(xml, observed_at):
        run = nmap_parser.parse_string(xml)
        verification.enrich_coverage(run)
        sid = db.create_scan(name="local", targets="192.168.1.10", profile="auditoria-tls")
        db.set_scan_context(sid, execution_context={"namespace": "tls-lab", "observed_at": observed_at})
        db.save_results(sid, run, analysis.analyze(run), 20)
        db.set_status(sid, "done")
        return sid
    save(expired, "2026-10-03T10:00:00Z")
    fid = next(f["id"] for f in db.list_current_findings()[0] if f["source"] == "nse:ssl-cert")
    fresh = nmap_xml.replace("Subject: commonName=servidor.local", certificate_output)
    sid = save(fresh, "2026-10-04T10:00:00Z")
    assert db.get_finding(fid)["lifecycle"] == expected
    if expected == "resolved":
        assert db.get_finding(fid)["verification_scan_id"] == sid
