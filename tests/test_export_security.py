"""Evidence preservation and export consistency regressions."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest

from scopescan import db, export, report
from scopescan.models import Finding, Host, NmapRun, Severity


def scan_with_evidence(value: str) -> int:
    scan_id = db.create_scan(name="snapshot", targets="10.0.0.1", profile="rapido")
    db.save_results(scan_id, NmapRun(hosts=[Host(address="10.0.0.1", state="up")]), [
        Finding(title="old", severity=Severity.HIGH, source="fixture", host="10.0.0.1",
                evidence=value, remediation=value)
    ], 7)
    return scan_id


@pytest.mark.parametrize("value", ["=1+1", "+SUM(A1)", "-1+2", "@SUM(A1)",
                                  " \t=1+1", "\r\n+CMD()", "\ufeff@x", "\x00-1"])
def test_csv_formula_neutralization_preserves_json(value):
    scan_id = scan_with_evidence(value)
    rows = list(csv.DictReader(io.StringIO(export.render_findings_csv(scan_id))))
    assert rows[0]["evidence"] == "'" + value
    assert rows[0]["remediation"] == "'" + value
    assert json.loads(export.render_json(scan_id))["findings"][0]["evidence"] == value


def test_csv_non_formula_text_is_unchanged():
    scan_id = scan_with_evidence(" observations")
    assert next(csv.DictReader(io.StringIO(export.render_findings_csv(scan_id))))["evidence"] == " observations"


def test_read_snapshot_resists_concurrent_writer(monkeypatch):
    scan_id = scan_with_evidence("before")
    original = db.hosts_with_ports

    def write_after_first_read(selected_id):
        def update():
            with db.connect() as conn:
                conn.execute("UPDATE scans SET risk_score=99 WHERE id=?", (scan_id,))
                conn.execute("UPDATE findings SET title='new', evidence='after' WHERE scan_id=?", (scan_id,))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(update).result(timeout=5)
        return original(selected_id)

    monkeypatch.setattr(db, "hosts_with_ports", write_after_first_read)
    payload = export.scan_payload(scan_id)
    assert payload["scan"]["risk_score"] == 7
    assert payload["findings"][0]["title"] == "old"
    assert payload["findings"][0]["evidence"] == "before"
    assert db.get_scan(scan_id)["risk_score"] == 99
    assert db.get_findings(scan_id)[0]["title"] == "new"


def test_bundle_snapshot_is_reused_and_hashes_match(monkeypatch):
    scan_id = scan_with_evidence("=danger")
    original = export.scan_payload
    calls = []

    def snapshot(selected_id):
        calls.append(selected_id)
        return original(selected_id)

    monkeypatch.setattr(export, "scan_payload", snapshot)
    db.set_nmap_args(scan_id, "nmap fixture", "raw-fixture.xml")
    with zipfile.ZipFile(io.BytesIO(export.render_bundle(scan_id))) as archive:
        prefix = f"scopescan-{scan_id:05d}"
        manifest = json.loads(archive.read(prefix + "/manifest.json"))
        assert calls == [scan_id]
        assert manifest["scan"]["nmap_args"] == "nmap fixture"
        for artifact in manifest["artifacts"]:
            content = archive.read(artifact["path"])
            assert artifact["sha256"] == hashlib.sha256(content).hexdigest()
            assert artifact["bytes"] == len(content)
        assert json.loads(archive.read(prefix + "/scan.json"))["findings"][0]["evidence"] == "=danger"
        assert "'=danger" in archive.read(prefix + "/findings.csv").decode()


def test_spooled_bundle_failure_cleans_temp(monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("fixture failure")
    monkeypatch.setattr(export, "_write_bundle", fail)
    with pytest.raises(ValueError):
        export.spool_bundle(999)
    assert not list((export.raw_dir() / "exports").glob("*.zip"))


def test_report_unknown_booleans_are_not_negative():
    scan_id = scan_with_evidence("normal")
    db.save_host_inventory(scan_id, "10.0.0.1", {
        "platform": "windows", "os_name": "Windows", "os_version": "10", "os_build": "1",
        "ubr": None, "updates": [], "software": [],
        "firewall_profiles": [{"name": "domain", "active": None, "enabled": None}],
        "defender": {"realtime_enabled": None, "signature_age_days": None},
        "guest_account": {"enabled": None},
    }, "fixture")
    html = report.render_report(scan_id)
    assert "domain sin dato/sin dato" in html
    assert "tiempo real sin dato" in html
    assert "Guest sin dato" in html
