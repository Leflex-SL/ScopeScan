from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest

from scopescan import authenticated_checks, compliance, db, linux_inventory, service, verification
from scopescan.models import Host, NmapRun, Port

HOST = "192.168.1.10"
SOURCE = "auth:linux:ssh-root"


def _data(port=22, root="yes"):
    return {"platform": "linux", "ssh_port": port, "sshd": {"permit_root_login": root}}


def _baseline(port=22):
    sid = db.create_scan(name="SSH baseline", targets=HOST, profile="authenticated", authorized_by="owner")
    data = _data(port)
    coverage = verification.authenticated_coverage("linux", data, {22, 2222}, HOST)
    db.set_scan_context(sid, execution_context={"namespace": "two-listeners",
                        "coverage": coverage, "observed_at": datetime.now(UTC).isoformat()})
    run = NmapRun(exit_status="success", hosts_up=1, hosts_total=1, coverage=coverage,
                  hosts=[Host(address=HOST, state="up", ports=[Port(portid=p, state="open") for p in (22, 2222)])])
    findings = authenticated_checks.linux_findings(HOST, data, {22, 2222})
    db.save_results(sid, run, findings, 40)
    db.set_status(sid, "done")
    return next(f["id"] for f in db.list_current_findings()[0] if f["source"] == SOURCE and f["port"] == port)


def test_plan_rejects_ssh_identity_using_other_listener(monkeypatch):
    fid = _baseline(22)
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    monkeypatch.setenv("SCOPESCAN_VERIFY_SSH_PORT", "2222")
    plan = verification.plan_verification([fid], authorized_by="owner")
    assert plan.requests == [] and "SCOPESCAN_VERIFY_SSH_PORT=22" in plan.missing_controls[0]["reason"]
    assert db.get_finding(fid)["lifecycle"] != "resolved"


@pytest.mark.parametrize("moment", ["queue", "execute"])
def test_identity_port_change_after_preview_revalidated(monkeypatch, moment):
    fid = _baseline(22)
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    monkeypatch.setenv("SCOPESCAN_VERIFY_SSH_PORT", "22")
    monkeypatch.setattr(linux_inventory, "collect", lambda *a, **k: pytest.fail("Wrong listener collected"))
    plan = verification.plan_verification([fid], authorized_by="owner")
    if moment == "queue":
        before = len(db.list_scans())
        monkeypatch.setenv("SCOPESCAN_VERIFY_SSH_PORT", "2222")
        with pytest.raises(ValueError, match="otro puerto"):
            verification.queue_verification(plan)
        assert len(db.list_scans()) == before
    else:
        sid = verification.queue_verification(plan)[0]
        monkeypatch.setenv("SCOPESCAN_VERIFY_SSH_PORT", "2222")
        service.execute(sid)
        assert db.get_scan(sid)["status"] == "failed"
        assert "otro puerto" in db.get_scan(sid)["error"]
    assert db.get_finding(fid)["lifecycle"] != "resolved"


def test_nondefault_listener_positive_and_negative_are_bound(monkeypatch):
    other = _baseline(22)
    fid = _baseline(2222)
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    monkeypatch.setenv("SCOPESCAN_VERIFY_SSH_PORT", "2222")
    def collect(host, **kwargs):
        assert host == HOST and kwargs["port"] == 2222
        return _data(2222, "no")
    monkeypatch.setattr(linux_inventory, "collect", collect)
    plan = verification.plan_verification([fid], authorized_by="owner")
    sid = verification.queue_verification(plan)[0]
    service.execute(sid)
    assert db.get_scan(sid)["status"] == "done"
    assert db.get_finding(fid)["lifecycle"] == "resolved"
    assert db.get_finding(other)["lifecycle"] != "resolved"
    coverage = json.loads(db.get_scan(sid)["coverage"])
    assert coverage["control_endpoints"][SOURCE] == {"host": HOST, "port": 2222, "protocol": "tcp"}


def test_enrichment_negative_on_2222_cannot_close_listener_22():
    fid = _baseline(22)
    sid = db.create_scan(name="new inventory", targets=HOST, profile="rapido")
    db.set_scan_context(sid, execution_context={"namespace": "two-listeners"})
    run = NmapRun(exit_status="success", hosts_up=1, hosts_total=1,
        hosts=[Host(address=HOST, state="up", ports=[Port(portid=p, state="open") for p in (22, 2222)])])
    db.save_results(sid, run, [], 0)
    db.set_status(sid, "done")
    db.save_host_inventory(sid, HOST, _data(2222, "no"), "openssh", findings=[])
    assert db.get_finding(fid)["lifecycle"] != "resolved"


def test_legacy_inventory_without_collection_port_stays_unknown():
    data = {"sshd": {"permit_root_login": "yes", "password_authentication": "yes"}, "aslr": 0}
    findings = authenticated_checks.linux_findings(HOST, data, {22, 2222})
    assert not any(f.source.startswith("auth:linux:ssh-") for f in findings)
    assert any(f.source == "auth:linux:aslr" for f in findings)
    coverage = verification.authenticated_coverage("linux", data, {22, 2222}, HOST)
    assert coverage["controls"][SOURCE] == "unknown"
    assert SOURCE not in coverage["control_endpoints"]
    assert all(c["status"] == "unknown" for c in compliance.linux_controls(data, {22, 2222})
               if c["control_id"].startswith("LINUX-SSH-"))


@pytest.mark.parametrize("port", [None, True, "2222", 0, 65536, []])
def test_invalid_inventory_port_does_not_establish_binding(port):
    data = _data(port)
    assert authenticated_checks.linux_findings(HOST, data, {22, 2222}) == []
    assert verification.authenticated_coverage("linux", data, {22, 2222}, HOST)["controls"][SOURCE] == "unknown"


def test_real_inventory_parser_retains_explicit_nondefault_collection_port():
    output = "\n".join(f"{key}\t{base64.b64encode(value.encode()).decode()}" for key, value in {
        "KERNEL": "6.8", "OS_RELEASE": "ID=ubuntu", "SSHD_EFFECTIVE": "permitrootlogin yes"}.items())
    data = linux_inventory.parse_inventory(output, ssh_port=2222)
    assert data["ssh_port"] == 2222
    assert {f.port for f in authenticated_checks.linux_findings(HOST, data, {22, 2222})} == {2222}


def test_mismatched_collected_metadata_never_closes_even_if_config_matches(monkeypatch):
    fid = _baseline(22)
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    monkeypatch.setenv("SCOPESCAN_VERIFY_SSH_PORT", "22")
    monkeypatch.setattr(linux_inventory, "collect", lambda *a, **k: _data(2222, "no"))
    sid = verification.queue_verification(verification.plan_verification([fid], authorized_by="owner"))[0]
    service.execute(sid)
    assert db.get_scan(sid)["status"] == "failed"
    assert db.get_finding(fid)["lifecycle"] != "resolved"


def test_host_control_can_collect_via_nondefault_ssh_port(monkeypatch):
    sid = db.create_scan(name="ASLR baseline", targets=HOST, profile="authenticated")
    data = {"platform": "linux", "ssh_port": 2222, "aslr": 0}
    coverage = verification.authenticated_coverage("linux", data, {2222}, HOST)
    db.set_scan_context(sid, execution_context={"namespace": "host-control", "coverage": coverage})
    run = NmapRun(exit_status="success", hosts=[Host(address=HOST, state="up")], coverage=coverage)
    db.save_results(sid, run, authenticated_checks.linux_findings(HOST, data, {2222}), 40)
    db.set_status(sid, "done")
    fid = next(f["id"] for f in db.list_current_findings()[0] if f["source"] == "auth:linux:aslr")
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    monkeypatch.setenv("SCOPESCAN_VERIFY_SSH_PORT", "2222")
    monkeypatch.setattr(linux_inventory, "collect", lambda host, **kwargs:
                        {"platform": "linux", "ssh_port": 2222, "aslr": 2})
    new = verification.queue_verification(verification.plan_verification([fid], authorized_by="owner"))[0]
    service.execute(new)
    assert db.get_scan(new)["status"] == "done" and db.get_finding(fid)["lifecycle"] == "resolved"
