"""Offline regressions for scope, endpoint identity and package evidence."""

from __future__ import annotations

import base64

import pytest

from scopescan import analysis, compliance, db, linux_inventory, msf, msf_modules, nmap_parser
from scopescan.targets import parse_target, parse_targets


@pytest.mark.parametrize("value", [
    "10-11.0.0.1", "172.15-16.0.1", "172.31-32.0.1", "192.168-169.1.1",
    "169.253-254.1.1", "126-127.0.0.1", "0-255.0-255.0-255.0-255",
])
def test_ranges_covering_public_addresses_are_not_private(value):
    assert not parse_target(value).private
    assert not parse_targets(value, force=True).all_private


@pytest.mark.parametrize("value", [
    "10.0-255.0-255.0-255", "172.16-31.0-255.0-255", "192.168.0-255.0-255",
    "169.254.0-255.0-255", "127.0-255.0-255.0-255", "fc00::/7", "fe80::/10", "::1",
])
def test_complete_private_ranges_are_recognized_without_enumeration(value):
    assert parse_target(value).private


@pytest.mark.parametrize("value", ["192.0.2.1", "198.51.100.0/24", "0.0.0.0", "::", "2001:db8::1"])
def test_reserved_or_documentation_space_is_not_implicitly_authorized(value):
    assert not parse_target(value).private


MODULE = "exploit/windows/smb/ms17_010_eternalblue"


def _scan(xml):
    run = nmap_parser.parse_string(xml)
    sid = db.create_scan(name="regression", targets="192.168.1.10", profile="vulnerabilidades",
                         target_private=True)
    db.save_results(sid, run, analysis.analyze(run), 0)
    return sid


def _verdict(sid, *, port=445, protocol="tcp", module=MODULE, result=msf_modules.VULNERABLE):
    db.save_msf_results(sid, [{"host": "192.168.1.10", "port": port, "protocol": protocol,
                              "module": module, "module_kind": "exploit", "action": "check",
                              "result": result, "detail": "offline fixture"}])


def test_verification_does_not_authorize_another_port(nmap_xml):
    sid = _scan(nmap_xml)
    _verdict(sid)
    with pytest.raises(msf.MsfScopeError, match="puerto TCP"):
        msf._validated_exploit_context(sid, host="192.168.1.10", port=1445, module_path=MODULE)


def test_udp_verification_does_not_authorize_tcp(nmap_xml):
    sid = _scan(nmap_xml)
    _verdict(sid, protocol="udp")
    with pytest.raises(msf.MsfScopeError):
        msf._validated_exploit_context(sid, host="192.168.1.10", port=445, module_path=MODULE)
    assert msf.exploitable_results(sid) == []


def test_omitted_port_resolves_to_unique_verified_endpoint(nmap_xml, monkeypatch, tmp_path):
    sid = _scan(nmap_xml)
    _verdict(sid, port=1445)
    monkeypatch.setattr(msf, "raw_dir", lambda: tmp_path)
    monkeypatch.setattr(msf, "msf_lhost", lambda: "192.168.1.50")
    _path, text = msf.prepare_exploit_resource(sid, host="192.168.1.10", port=None,
                                             module_path=MODULE)
    assert "set RPORT 1445" in text
    assert db.get_exploit_runs(sid)[0]["port"] == 1445


def test_omitted_port_rejects_ambiguous_verified_endpoints(nmap_xml):
    sid = _scan(nmap_xml)
    monkey_rows = [{"host": "192.168.1.10", "port": port, "protocol": "tcp",
                   "module": MODULE, "module_kind": "exploit", "action": "check",
                   "result": msf_modules.VULNERABLE, "detail": "fixture"} for port in (445, 1445)]
    db.save_msf_results(sid, monkey_rows)
    with pytest.raises(msf.MsfScopeError, match="inequivoca"):
        msf._validated_exploit_context(sid, host="192.168.1.10", port=None, module_path=MODULE)


def test_plan_filters_udp_services_and_udp_cves(nmap_xml):
    sid = _scan(nmap_xml.replace('protocol="tcp"', 'protocol="udp"'))
    assert msf.plan_scan(sid) == []
    assert msf_modules.candidates_for(service_name="ssh", product="", protocol="udp") == []


def test_cve_does_not_cross_protocol(nmap_xml, monkeypatch):
    # Same numeric port is open for TCP and UDP; only UDP has a CVE.
    xml = nmap_xml.replace('<script id="smb-vuln-ms17-010"', '<script id="unrelated"')
    xml = xml.replace('IDs:  CVE:CVE-2017-0143', 'IDs: none')
    sid = _scan(xml)
    monkey_finding = [{"host": "192.168.1.10", "port": 445, "protocol": "udp",
                       "cves": '["CVE-2017-0144"]'}]
    # Feed exact rows via monkeypatch, keeping the real observed TCP services.
    monkeypatch.setattr(db, "get_findings", lambda _sid: monkey_finding)
    assert not any(mod.path == MODULE for _host, _port, _svc, mod in msf.plan_scan(sid))


def test_concrete_public_host_is_revalidated(nmap_xml, monkeypatch):
    sid = _scan(nmap_xml.replace("192.168.1.10", "11.0.0.1"))
    invoked = []
    monkeypatch.setattr(msf.msf_runner, "run", lambda *args, **kwargs: invoked.append(args))
    with pytest.raises(msf.MsfScopeError, match="11.0.0.1"):
        msf.verify_scan(sid)
    assert invoked == []


def test_protocol_is_part_of_finding_deduplication(nmap_xml):
    xml = nmap_xml.replace('<port protocol="tcp" portid="23">',
                          '<port protocol="udp" portid="23">', 1)
    # Both protocol copies have the same script and hence the same finding title.
    start = xml.index('<port protocol="udp" portid="23">')
    end = xml.index('</port>', start) + len('</port>')
    udp = xml[start:end].replace('</port>',
        '<script id="test-vuln" output="State: VULNERABLE&#10;Risk factor: HIGH"/></port>')
    xml = xml[:start] + udp + udp.replace('protocol="udp"', 'protocol="tcp"') + xml[end:]
    findings = [f for f in analysis.analyze(nmap_parser.parse_string(xml))
                if f.source == "nse:test-vuln"]
    assert {f.protocol for f in findings} == {"tcp", "udp"}


def test_msf_output_cannot_attribute_other_endpoint_verdict():
    execution = msf.msf_runner.MsfExecution(
        argv=[], rc_path=None, returncode=0,
        stdout="[+] 192.168.1.10:445 - The target is vulnerable.", stderr="",
    )
    mod = msf_modules.module_by_path(MODULE)
    rows = msf._rows_from(1, mod, 1445, ["192.168.1.10"], execution)
    assert rows[0]["result"] == msf_modules.UNKNOWN


@pytest.mark.parametrize("flag", ["timed_out", "cancelled", "output_truncated"])
def test_incomplete_msf_run_cannot_authorize_exploitation(flag):
    execution = msf.msf_runner.MsfExecution(
        argv=[], rc_path=None, returncode=0,
        stdout="[+] 192.168.1.10:445 - The target is vulnerable.", stderr="",
        **{flag: True},
    )
    rows = msf._rows_from(1, msf_modules.module_by_path(MODULE), 445,
                          ["192.168.1.10"], execution)
    assert rows[0]["result"] == msf_modules.ERROR


@pytest.mark.parametrize("line,name,version", [
    ("openssl-3.3.2-r0", "openssl", "3.3.2-r0"),
    ("libcrypto3-3.3.2-r10", "libcrypto3", "3.3.2-r10"),
    ("py3-my-lib-1.2.3_rc1-r2", "py3-my-lib", "1.2.3_rc1-r2"),
    ("linux-lts\t6.6.12-r1", "linux-lts", "6.6.12-r1"),
])
def test_apk_versions_keep_package_name_and_revision(line, name, version):
    assert linux_inventory._packages(line, "apk") == [{"name": name, "version": version}]


def _inventory(**records):
    records = {"KERNEL": "6.6", "OS_RELEASE": "ID=alpine\nVERSION_ID=3.20", **records}
    output = "\n".join(f"{key}\t{base64.b64encode(str(value).encode()).decode()}"
                       for key, value in records.items())
    return linux_inventory.parse_inventory(output)


def test_inventory_preserves_unknown_and_truncated_metadata():
    unknown = _inventory()
    assert unknown["reboot_required"] is None
    assert unknown["packages_complete"] is None
    controls = compliance.linux_controls(unknown, set())
    assert next(c for c in controls if c["control_id"] == "LINUX-REBOOT")["status"] == "unknown"
    truncated = _inventory(PACKAGE_MANAGER="apk", PACKAGES="openssl\t3.3.2-r0",
                           PACKAGES_CHECKED="yes", PACKAGE_TOTAL="5001")
    assert truncated["packages_truncated"] is True
    assert truncated["packages_complete"] is False
    assert truncated["package_total"] == 5001
    complete = _inventory(PACKAGE_MANAGER="apk", PACKAGES="openssl\t3.3.2-r0",
                          PACKAGES_CHECKED="yes", PACKAGE_TOTAL="1")
    assert complete["packages_complete"] is True
    malformed = _inventory(PACKAGE_MANAGER="apk", PACKAGES="unrecognized record",
                           PACKAGES_CHECKED="yes", PACKAGE_TOTAL="1")
    assert malformed["packages_complete"] is False
    assert malformed["packages_truncated"] is False
    assert malformed["packages_unparsed"] == 1
