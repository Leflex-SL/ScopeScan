from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scopescan import (
    analysis,
    authenticated_checks,
    db,
    importers,
    linux_inventory,
    nmap_runner,
    scopes,
    service,
    verification,
)
from scopescan.models import Finding, Host, NmapRun, Port, Service, Severity


def _finding(source="rule:telnet-claro", *, scope_id=None):
    namespace = f"scope:{scope_id}" if scope_id is not None else "office"
    sid = db.create_scan(name="baseline", targets="192.168.1.10", profile="rapido",
                         authorized_by="owner")
    db.set_scan_context(sid, scope_id=scope_id, execution_context={"namespace": namespace})
    run = NmapRun(scanner_version="7.95", exit_status="success", hosts_up=1, hosts_total=1,
        hosts=[Host(address="192.168.1.10", state="up", ports=[Port(portid=23, state="open",
            service=Service(name="telnet", method="probed", confidence=10))])],
        coverage={"status": "complete", "engine": "nmap", "engine_version": "7.95",
                  "protocols": {"tcp": [23]}, "hosts": ["192.168.1.10"],
                  "endpoints": [{"host": "192.168.1.10", "port": 23, "protocol": "tcp"}]})
    verification.enrich_coverage(run)
    finding = Finding(title="issue", severity=Severity.HIGH, source=source, host="192.168.1.10",
                      port=None if source.startswith("auth:") else 23,
                      protocol="host" if source.startswith("auth:") else "tcp")
    db.save_results(sid, run, [finding], analysis.risk_score([finding]))
    db.set_status(sid, "done")
    if source.startswith("auth:"):
        bad = {"platform": "linux", "aslr": 0, "ssh_port": 22}
        db.save_host_inventory(sid, "192.168.1.10", bad, "openssh",
            findings=authenticated_checks.linux_findings("192.168.1.10", bad, set()))
    return next(f["id"] for f in db.list_current_findings()[0] if f["source"] == source)


def _queue(fid):
    return verification.queue_verification(
        verification.plan_verification([fid], authorized_by="owner"))[0]


def test_rerun_network_preserves_identity_and_can_close_original_finding(monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda: "fixture-nmap")
    fid = _finding()
    original = _queue(fid)
    repeated = service.rerun(original)
    context = json.loads(db.get_scan(repeated)["execution_context"])
    assert context["namespace"] == "office" and context["verification_of"] == [fid]
    def execute(argv, **kwargs):
        path = Path(argv[argv.index("-oX") + 1])
        stamp = int(datetime.now(UTC).timestamp()) + 5
        path.write_text(f'<nmaprun version="7.95" start="{stamp}">'
            '<scaninfo type="connect" protocol="tcp" numservices="1" services="23"/>'
            '<host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="23"><state state="closed"/></port></ports></host>'
            '<runstats><finished exit="success" elapsed="1"/></runstats></nmaprun>')
        return nmap_runner.NmapExecution(argv, path, 0, "", "")
    monkeypatch.setattr(nmap_runner, "run", execute)
    service.execute(repeated)
    assert db.get_scan(repeated)["status"] == "done"
    assert db.get_finding(fid)["lifecycle"] == "resolved"
    assert db.get_finding(fid)["verification_scan_id"] == repeated


def test_rerun_authenticated_replans_and_executes_current_identity(monkeypatch):
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    fid = _finding("auth:linux:aslr")
    original = _queue(fid)
    repeated = service.rerun(original)
    context = json.loads(db.get_scan(repeated)["execution_context"])
    assert context["namespace"] == "office" and context["verification_of"] == [fid]
    assert db.get_scan(repeated)["profile"] == "authenticated"
    monkeypatch.setattr(linux_inventory, "collect", lambda host, **kwargs:
                        {"platform": "linux", "aslr": 2, "ssh_port": 22})
    service.execute(repeated)
    assert db.get_scan(repeated)["status"] == "done"
    assert db.get_finding(fid)["lifecycle"] == "resolved"


def test_rerun_authenticated_requires_identity_still_configured(monkeypatch):
    monkeypatch.setenv("SCOPESCAN_VERIFY_LINUX_IDENTITY", "1")
    original = _queue(_finding("auth:linux:aslr"))
    monkeypatch.delenv("SCOPESCAN_VERIFY_LINUX_IDENTITY")
    with pytest.raises(ValueError, match="identidad.*Verificar"):
        service.rerun(original)


@pytest.mark.parametrize("change", [
    {"namespace": "unrelated"}, {"pinned_targets": ["192.168.1.11"]},
    {"verification_of": []}, {"verification_of": ["missing-current-id"]},
    {"verification": {}},
    {"verification": {"protocol": "tcp", "ports": [80], "rules": ["rule:telnet-claro"], "scripts": []}},
    {"verification": {"protocol": "tcp", "ports": [23], "rules": [], "scripts": ["evil"]}},
    {"verification": {"protocol": [], "ports": [23], "rules": [], "scripts": []}},
])
def test_rerun_rejects_stale_or_mutated_plan_without_creating_job(change):
    original = _queue(_finding())
    db.set_scan_context(original, execution_context=change)
    before = len(db.list_scans())
    with pytest.raises(ValueError):
        service.rerun(original)
    assert len(db.list_scans()) == before


@pytest.mark.parametrize("change", ["targets", "authorization"])
def test_rerun_revalidates_current_saved_scope(change):
    scope_id = scopes.create_scope(name="office", targets="192.168.1.10", authorized_by="owner")
    original = _queue(_finding(scope_id=scope_id))
    scopes.update_scope(scope_id, name="office", targets="192.168.1.11" if change == "targets" else "192.168.1.10",
                         authorized_by="new-owner" if change == "authorization" else "owner")
    with pytest.raises(ValueError, match="alcance.*Verificar"):
        service.rerun(original)


def test_legacy_authenticated_row_without_owned_context_has_actionable_error():
    sid = db.create_scan(name="legacy", targets="192.168.1.10", profile="authenticated")
    with pytest.raises(ValueError, match="usa Verificar"):
        service.rerun(sid)


def test_adhoc_repeat_retains_namespace_and_current_finding_identity(monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda: "fixture-nmap")
    original = service.queue_scan(service.ScanRequest(targets="192.168.1.10", profile="rapido",
                                                       authorized_by="owner"))
    run = NmapRun(exit_status="success", hosts_up=1, hosts_total=1,
        hosts=[Host(address="192.168.1.10", state="up", ports=[Port(portid=23, state="open")])])
    finding = Finding(title="Telnet", source="rule:telnet-claro", severity=Severity.HIGH,
                      host="192.168.1.10", port=23)
    db.save_results(original, run, [finding], 50)
    db.set_status(original, "done")
    first = db.list_current_findings()[0][0]
    repeated = service.rerun(original)
    context = json.loads(db.get_scan(repeated)["execution_context"])
    assert context["namespace"] == f"scan:{original}"
    assert context["pinned_targets"] == ["192.168.1.10"]
    db.save_results(repeated, run, [finding], 50)
    db.set_status(repeated, "done")
    findings, total = db.list_current_findings()
    assert total == 1 and findings[0]["id"] == first["id"]


def test_imported_provenance_never_replays_even_with_nonimport_profile():
    sid = service.queue_scan(service.ScanRequest(targets="192.168.1.10", profile="rapido"))
    db.set_scan_context(sid, execution_context={"provenance": {"imported": True}})
    with pytest.raises(ValueError, match="importado"):
        service.rerun(sid)


def _document():
    return {"schema": importers.EXTERNAL_SCHEMA, "engine": "scanner", "engine_version": "1",
            "observed_at": "2026-10-03T10:00:00Z",
            "coverage": {"status": "complete", "protocols": {"tcp": [23]}},
            "hosts": [{"address": "192.168.1.10", "state": "up", "ports": [
                {"port": 23, "protocol": "tcp", "state": "open"}]}],
            "findings": [{"host": "192.168.1.10", "port": 23, "protocol": "tcp",
                          "rule_id": "rule", "title": "issue", "severity": "high"}]}


@pytest.mark.parametrize("field,value", [
    ("coverage.status", []), ("coverage.status", {}), ("hosts.0.state", {}),
    ("hosts.0.address", None), ("hosts.0.address", 1), ("hosts.0.address", True),
    ("hosts.0.ports.0.protocol", []), ("hosts.0.ports.0.state", {}),
    ("hosts.0.ports.0.port", True), ("hosts.0.ports.0.port", None),
    ("findings.0.protocol", []), ("findings.0.host", []), ("findings.0.port", False),
    ("findings.0.cvss", float("nan")), ("findings.0.cvss", float("inf")),
    ("findings.0.cvss", True), ("findings.0.cvss", {}), ("findings.0.severity", []),
    ("observed_at", True), ("observed_at", 1), ("observed_at", None),
])
def test_external_structural_primitives_have_actionable_error(tmp_path, field, value):
    document = _document()
    keys = field.split(".")
    current = document
    for key in keys[:-1]:
        current = current[int(key)] if isinstance(current, list) else current[key]
    current[int(keys[-1]) if isinstance(current, list) else keys[-1]] = value
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(document))
    with pytest.raises(importers.ImportError):
        importers.import_external_json(path)
    assert db.list_scans() == []


@pytest.mark.parametrize("kind", ["xml", "json"])
def test_future_import_rejected_before_raw_copy_or_current_state(tmp_path, nmap_xml, kind):
    future = datetime.now(UTC) + timedelta(days=365)
    if kind == "xml":
        path = tmp_path / "future.xml"
        path.write_text(nmap_xml.replace('start="1758200000"', f'start="{int(future.timestamp())}"'))
        importer = importers.import_nmap
    else:
        document = _document()
        document["observed_at"] = future.isoformat()
        path = tmp_path / "future.json"
        path.write_text(json.dumps(document))
        importer = importers.import_external_json
    with pytest.raises(importers.ImportError, match="futuro.*corrige"):
        importer(path, namespace="office")
    assert db.list_scans() == [] and db.list_current_findings()[1] == 0
    assert not list(importers.raw_dir().glob("import-*"))


@pytest.mark.parametrize("kind", ["xml", "json"])
def test_import_accepts_bounded_clock_skew(tmp_path, nmap_xml, kind):
    observed = datetime.now(UTC) + timedelta(minutes=4)
    if kind == "xml":
        path = tmp_path / "skew.xml"
        path.write_text(nmap_xml.replace('start="1758200000"', f'start="{int(observed.timestamp())}"'))
        importer = importers.import_nmap
    else:
        document = _document()
        document["observed_at"] = observed.isoformat()
        path = tmp_path / "skew.json"
        path.write_text(json.dumps(document))
        importer = importers.import_external_json
    sid = importer(path)
    assert db.get_scan(sid)["status"] == "done"
