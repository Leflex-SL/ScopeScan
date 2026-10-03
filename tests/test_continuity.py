from __future__ import annotations

import sqlite3

import pytest

from scopescan import db
from scopescan.models import Assessment, Finding, Host, NmapRun, Port, Service, Severity


def report(*, namespace="office", day=1, findings=True, port_state="open", ports=(23,),
           version="1", rules_version="v1", status="done", coverage_status="complete",
           verification_of=(), source="rule:telnet", assessment=Assessment.EXPOSURE):
    scan = db.create_scan(name="fixture", targets="10.0.0.1", profile="rapido",
                          execution_context={"namespace": namespace,
                                             "observed_at": f"2026-10-{day:02}T00:00:00+00:00",
                                             "verification_of": list(verification_of)})
    host = Host("10.0.0.1", state="up", ports=[Port(p, state=port_state, service=Service("telnet", version=version)) for p in ports])
    items = [Finding("Title " + version, Severity.HIGH, source, host.address, port=23,
                     assessment=assessment)] if findings else []
    run = NmapRun(exit_status="success", hosts=[host], coverage={
        "status": coverage_status, "engine": "nmap", "engine_version": "7.95",
        "rules_version": rules_version, "rules": [source], "protocols": {"tcp": list(ports)}})
    db.save_results(scan, run, items, 0)
    db.set_status(scan, status)
    return scan


def current():
    return db.list_current_findings()[0][0]


def test_scoped_identity_title_version_history_and_namespace():
    report()
    fid = current()["id"]
    report(day=2, version="2")
    assert current()["id"] == fid
    assert db.current_summary()["findings"] == 1
    assert db.get_asset(current()["asset_id"])["observation_count"] == 2
    report(namespace="other-network", day=2)
    assert db.current_summary()["assets"] == 2
    assert db.current_summary()["findings"] == 2


def test_lifecycle_recheck_fix_and_evidence_closure_atomic_history():
    report()
    fid = current()["id"]
    db.update_remediation(fid, actor="operator", owner="ops", status="in_progress")
    report(day=2)
    scan = report(day=3, findings=False, port_state="closed", verification_of=[fid])
    assert current()["lifecycle"] == "resolved"
    assert db.scan_delta(scan)["findings"][0]["change"] == "resolved"
    with pytest.raises(ValueError):
        db.update_remediation(fid, actor="ops", status="closed", verification_scan_id=scan, evidence="fixed")
    assert len(db.remediation_history(fid)) == 1
    db.update_remediation(fid, actor="ops", status="closed", verification_scan_id=scan,
                          evidence="Telnet endpoint explicitly closed in approved verification")
    assert db.current_summary()["findings"] == 0
    with db.connect() as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE remediation_actions SET actor='changed'")
    report(day=4)
    assert current()["status"] == "open"


@pytest.mark.parametrize("changes", [{"ports": (80,)}, {"rules_version": "v2"},
                                     {"coverage_status": "unknown"}, {"status": "cancelled"},
                                     {"port_state": "filtered"}])
def test_unmatched_partial_coverage_does_not_resolve(changes):
    report()
    report(day=2, findings=False, **changes)
    assert current()["lifecycle"] != "resolved"
    assert db.current_summary()["findings"] == 1


def test_terminal_status_controls_negative_evidence():
    report()
    scan = report(day=2, findings=False, port_state="closed", status="running")
    assert current()["lifecycle"] != "resolved"
    db.set_status(scan, "cancelled")
    assert current()["lifecycle"] != "resolved"


def test_stale_import_cannot_replace_newer_positive_or_close():
    report(day=3, version="new")
    report(day=1, findings=False, port_state="closed")
    assert current()["lifecycle"] == "observed"
    assert current()["title"] == "Title new"


def test_missing_version_does_not_prove_version_candidate_fixed():
    source = "rule:openssh-antiguo"
    report(source=source, assessment=Assessment.CANDIDATE)
    report(day=2, findings=False, source=source, version="")
    assert current()["lifecycle"] == "not_assessed"
    report(day=3, findings=False, source=source, port_state="closed")
    assert current()["lifecycle"] == "not_assessed"


def test_atomic_asset_metadata_and_explicit_alias_identity():
    report()
    aid = current()["asset_id"]
    db.update_asset_metadata(aid, 4, alias="10.0.0.2", actor="ops")
    assert db.list_assets(search="10.0.0.2")[1] == 1
    with pytest.raises(ValueError):
        db.update_asset_metadata(aid, 5, alias="invalid", actor="ops")
    assert db.get_asset(aid)["criticality"] == 4


def test_risk_factors_candidates_feed_unknown_and_criticality():
    report(assessment=Assessment.CANDIDATE)
    aid = current()["asset_id"]
    initial = db.get_asset(aid)["risk"]
    assert initial["candidate_count"] == 1
    assert initial["factors"][0]["known_exploited"] is None
    assert initial["factors"][0]["evidence_weight"] == 0.35
    db.set_asset_criticality(aid, 5, actor="ops")
    assert db.get_asset(aid)["risk"]["score"] > initial["score"]


def test_legacy_backfill_unknown_isolated_and_idempotent():
    first = report(namespace="scan:1")
    with db.connect() as conn:
        conn.execute("DELETE FROM scan_deltas")
        conn.execute("DELETE FROM finding_observations")
        conn.execute("DELETE FROM current_findings")
        conn.execute("DELETE FROM asset_observations")
        conn.execute("DELETE FROM asset_aliases")
        conn.execute("DELETE FROM assets")
        conn.execute("UPDATE scans SET execution_context='{}',coverage='{}',continuity_pending=NULL")
    db.init_db()
    assert db.scan_delta(first)["coverage"]["status"] == "unknown"
    db.init_db()
    assert db.current_summary()["findings"] == 1


def test_targeted_scan_retains_unassessed_current_endpoints():
    report(ports=(23, 80))
    report(day=2, ports=(23,))
    asset = db.get_asset(current()["asset_id"])
    endpoints = {p["portid"]: p for p in asset["current_state"]["ports"]}
    assert endpoints[80]["state"] == "open"
    assert endpoints[80]["current_assessment"] == "not_assessed"


def test_auth_inventory_observations_have_source_specific_positive_baseline():
    scan = report(findings=False)
    auth = Finding("ASLR disabled", Severity.MEDIUM, "auth:linux:aslr", "10.0.0.1",
                   protocol="host", assessment=Assessment.CONFIRMED, confirmed=True)
    db.save_host_inventory(scan, "10.0.0.1", {"platform": "linux", "aslr": 0}, "ssh", findings=[auth])
    assert current()["source"] == auth.source
    with db.connect() as conn:
        baseline = conn.execute("SELECT baseline_coverage FROM current_findings").fetchone()[0]
    assert '"engine": "authenticated"' in baseline
    # No data cannot turn an authenticated finding into a pass.
    db.save_host_inventory(scan, "10.0.0.1", {"platform": "linux"}, "ssh", findings=[])
    assert current()["lifecycle"] == "not_assessed"


def test_deleted_report_clears_current_evidence_but_retains_declared_audit():
    scan = report()
    fid = current()["id"]
    db.update_remediation(fid, actor="ops", owner="team")
    db.delete_scan(scan)
    assert db.current_summary()["findings"] == 0
    assert db.get_finding(fid)["lifecycle"] == "evidence_unavailable"
    assert db.get_finding(fid)["evidence"] == ""
    assert len(db.remediation_history(fid)) == 1


def test_invalid_candidate_risk_inputs_rejected_atomically():
    scan = report()
    with pytest.raises(ValueError):
        db.replace_cve_candidates(scan, [{"cvss": float("nan")}])
    assert db.get_cve_candidates(scan) == []


def test_keV_unknown_and_successful_absence_remain_distinct():
    from scopescan.risk import asset_risk

    finding = {"id": "fixture", "severity": 3, "assessment": "candidate", "host": "10.0.0.1",
               "port": 23, "protocol": "tcp", "cve_ids": ["CVE-2026-1234"]}
    match = {"host": "10.0.0.1", "port": 23, "protocol": "tcp", "cve_id": "CVE-2026-1234",
             "known_exploited": False, "kev_assessed": False}
    unavailable = asset_risk([finding], address=finding["host"], criticality=1, candidates=[match])
    assert unavailable["factors"][0]["known_exploited"] is None
    match["kev_assessed"] = True
    assessed = asset_risk([finding], address=finding["host"], criticality=1, candidates=[match])
    assert assessed["factors"][0]["known_exploited"] is False


def test_unrecognized_nse_output_cannot_prove_resolution():
    report(source="nse:ssl-heartbleed", assessment=Assessment.CONFIRMED)
    report(day=2, findings=False, source="nse:ssl-heartbleed")
    assert current()["lifecycle"] == "not_assessed"


def test_negative_at_other_address_alias_does_not_resolve():
    report()
    fid, aid = current()["id"], current()["asset_id"]
    db.add_asset_alias(aid, "10.0.0.2", actor="ops")
    scan = db.create_scan(name="alias", targets="10.0.0.2", profile="rapido",
                          execution_context={"namespace": "office", "observed_at": "2026-10-02T00:00:00+00:00"})
    run = NmapRun(exit_status="success", hosts=[Host("10.0.0.2", state="up", ports=[Port(23, state="closed")])],
                  coverage={"status": "complete", "engine": "nmap", "engine_version": "7.95",
                            "rules_version": "v1", "rules": ["rule:telnet"], "protocols": {"tcp": [23]}})
    db.save_results(scan, run, [], 0)
    db.set_status(scan, "done")
    assert db.get_finding(fid)["lifecycle"] == "not_assessed"
    endpoints = db.get_asset(aid)["current_state"]["ports"]
    assert len(endpoints) == 2


def test_external_positive_does_not_downgrade_local_evidence():
    report(source="nse:ssl-heartbleed", assessment=Assessment.CONFIRMED)
    fid = current()["id"]
    scan = db.create_scan(name="external", targets="10.0.0.1", profile="external",
                          execution_context={"namespace": "office", "observed_at": "2026-10-02T00:00:00+00:00"})
    finding = Finding("external candidate", Severity.HIGH, "nse:ssl-heartbleed", "10.0.0.1", port=23,
                      assessment=Assessment.CANDIDATE)
    run = NmapRun(exit_status="success", hosts=[Host("10.0.0.1", state="up", ports=[Port(23, state="open")])],
                  provenance={"imported": True, "source": "external"},
                  coverage={"status": "complete", "engine": "nmap", "engine_version": "7.95",
                            "rules_version": "v1", "rules": [finding.source], "protocols": {"tcp": [23]}})
    db.save_results(scan, run, [finding], 0)
    db.set_status(scan, "done")
    assert db.get_finding(fid)["assessment"] == "confirmed"
    with db.connect() as conn:
        baseline = conn.execute("SELECT baseline_coverage FROM current_findings WHERE id=?", (fid,)).fetchone()[0]
    assert "imported:" not in baseline
