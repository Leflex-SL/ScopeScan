"""Review reproductions using real imports and bounded asset API responses."""

import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from scopescan import analysis, db, importers, nmap_parser, verification
from scopescan.models import Finding, Host, NmapRun, Port, Severity
from scopescan.risk import asset_risk
from scopescan.web.app import app


def xml(*, day=1, address="10.0.0.1", state="open"):
    stamp = int(datetime(2026, 10, day, tzinfo=UTC).timestamp())
    return f'''<nmaprun scanner="nmap" version="7.95" start="{stamp}">
    <scaninfo type="connect" protocol="tcp" services="23" numservices="1"/>
    <host><status state="up"/><address addr="{address}" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="23"><state state="{state}"/>
    <service name="telnet" method="probed" conf="10"/></port></ports></host>
    <runstats><finished exit="success"/><hosts up="1" total="1"/></runstats></nmaprun>'''


def local_run(*, day=1, state="open", verification_of=()):
    run = nmap_parser.parse_string(xml(day=day, state=state))
    verification.enrich_coverage(run)
    scan = db.create_scan(name="local", targets="10.0.0.1", profile="rapido",
                          execution_context={"namespace": "office", "verification_of": list(verification_of)})
    db.save_results(scan, run, analysis.analyze(run), 0)
    db.set_status(scan, "done")
    return scan


def imported_run(tmp_path, **kwargs):
    path = tmp_path / "import.xml"
    path.write_text(xml(**kwargs), encoding="utf-8")
    return importers.import_nmap(path, namespace="office")


def test_external_closed_snapshot_and_absent_host_do_not_replace_local(tmp_path):
    local = local_run()
    finding = db.list_current_findings()[0][0]
    before = db.get_finding(finding["id"])
    asset_id = finding["asset_id"]
    imported_run(tmp_path, day=3, state="closed")
    asset = db.get_asset(asset_id)
    assert asset["latest_scan_id"] == local
    assert asset["latest_at"].startswith("2026-10-01")
    assert asset["current_state"]["ports"][0]["state"] == "open"
    imported_run(tmp_path, day=3, address="10.0.0.2")
    unchanged = db.get_finding(finding["id"])
    assert unchanged["lifecycle"] == "observed"
    assert unchanged["evaluated_at"] == before["evaluated_at"]
    local_run(day=2, state="closed", verification_of=[finding["id"]])
    assert db.get_finding(finding["id"])["lifecycle"] == "resolved"


def test_owned_imported_service_candidate_can_be_verified_by_local_closed(tmp_path):
    imported_run(tmp_path)
    finding = db.list_current_findings()[0][0]
    assert finding["assessment"] == "candidate"
    assert finding["source"] == "rule:telnet-claro"
    local_run(day=2, state="closed", verification_of=[finding["id"]])
    assert db.get_finding(finding["id"])["lifecycle"] == "resolved"


def test_deleted_positive_restores_exact_surviving_engine_baseline():
    def save(day, rules_version, positive=True):
        run = NmapRun(start=int(datetime(2026, 10, day, tzinfo=UTC).timestamp()), exit_status="success",
                      hosts=[Host("10.0.0.1", state="up", ports=[Port(23, state="open" if positive else "closed")])],
                      coverage={"engine": "nmap", "engine_version": "7.95", "rules_version": rules_version,
                                "status": "complete", "rules": ["rule:telnet-claro"], "protocols": {"tcp": [23]}})
        scan = db.create_scan(name="local", targets="10.0.0.1", profile="rapido", execution_context={"namespace": "office"})
        findings = [Finding("Telnet", Severity.HIGH, "rule:telnet-claro", "10.0.0.1", port=23)] if positive else []
        db.save_results(scan, run, findings, 0)
        db.set_status(scan, "done")
        return scan
    first = save(1, "v1")
    second = save(2, "v2")
    fid = db.list_current_findings()[0][0]["id"]
    db.delete_scan(second)
    with db.connect() as conn:
        row = conn.execute("SELECT scan_id,baseline_coverage FROM current_findings WHERE id=?", (fid,)).fetchone()
    assert row["scan_id"] == first
    assert json.loads(row["baseline_coverage"])["rules_version"] == "v1"
    save(3, "v2", positive=False)
    assert db.get_finding(fid)["lifecycle"] == "not_assessed"


@pytest.mark.parametrize(("status", "coverage_status", "latest_version"), [
    ("failed", "complete", "v2"), ("cancelled", "complete", "v2"),
    ("done", "partial", "v2"), ("failed", "complete", "v1"),
])
def test_latest_accepted_partial_positive_has_exact_baseline(status, coverage_status, latest_version):
    def save(day, version, terminal, coverage_state, positive):
        scan = db.create_scan(name="fixture", targets="10.0.0.1", profile="rapido",
                              execution_context={"namespace": "office"})
        run = NmapRun(start=int(datetime(2026, 10, day, tzinfo=UTC).timestamp()), exit_status="success",
                      hosts=[Host("10.0.0.1", state="up", ports=[Port(23, state="open" if positive else "closed")])],
                      coverage={"engine": "nmap", "engine_version": "7.95", "rules_version": version,
                                "status": coverage_state, "rules": ["rule:telnet-claro"], "protocols": {"tcp": [23]}})
        findings = [Finding("Observed " + version, Severity.HIGH, "rule:telnet-claro", "10.0.0.1", port=23)] if positive else []
        db.save_results(scan, run, findings, 0)
        db.set_status(scan, terminal)
        return scan
    save(1, "v1", "done", "complete", True)
    latest = save(2, latest_version, status, coverage_status, True)
    finding = db.list_current_findings()[0][0]
    assert finding["scan_id"] == latest
    assert finding["title"] == "Observed " + latest_version
    with db.connect() as conn:
        current = conn.execute("SELECT baseline_coverage FROM current_findings WHERE id=?", (finding["id"],)).fetchone()[0]
        observation = conn.execute("SELECT coverage FROM finding_observations WHERE finding_id=? AND scan_id=?", (finding["id"], latest)).fetchone()[0]
    assert json.loads(current) == json.loads(observation)
    assert json.loads(current)["rules_version"] == latest_version
    assert json.loads(current)["status"] == "partial"
    save(3, "v1", "done", "complete", False)
    assert db.get_finding(finding["id"])["lifecycle"] == "not_assessed"
    assert db.get_finding(finding["id"])["verification_scan_id"] is None


def test_deleted_latest_replays_surviving_mixed_protocol_alias_endpoints(tmp_path):
    def save(day, address, port, protocol):
        run = NmapRun(start=int(datetime(2026, 10, day, tzinfo=UTC).timestamp()), exit_status="success",
                      hosts=[Host(address, state="up", ports=[Port(port, protocol=protocol, state="open")])],
                      coverage={"engine": "nmap", "engine_version": "7.95", "rules_version": "v1",
                                "status": "complete", "rules": [], "protocols": {protocol: [port]}})
        scan = db.create_scan(name="local", targets=address, profile="rapido", execution_context={"namespace": "office"})
        db.save_results(scan, run, [], 0)
        db.set_status(scan, "done")
        return scan
    first = save(1, "10.0.0.1", 22, "tcp")
    aid = db.list_assets()[0][0]["id"]
    db.add_asset_alias(aid, "10.0.0.2", actor="ops")
    second = save(2, "10.0.0.2", 80, "udp")
    third = save(3, "10.0.0.1", 443, "tcp")
    # A newer external claim remains historical and cannot replace either endpoint.
    imported_run(tmp_path, day=3, state="closed")
    db.delete_scan(third)
    asset = db.get_asset(aid)
    endpoints = {(p["address"], p["protocol"], p["portid"]): p for p in asset["current_state"]["ports"]}
    assert set(endpoints) == {("10.0.0.1", "tcp", 22), ("10.0.0.2", "udp", 80)}
    assert endpoints[("10.0.0.1", "tcp", 22)]["network_scan_id"] == first
    assert endpoints[("10.0.0.1", "tcp", 22)]["current_assessment"] == "not_assessed"
    assert endpoints[("10.0.0.2", "udp", 80)]["network_scan_id"] == second
    assert asset["latest_scan_id"] == second
    db.delete_scan(first)
    assert [(p["address"], p["protocol"], p["portid"]) for p in db.get_asset(aid)["current_state"]["ports"]] == [("10.0.0.2", "udp", 80)]


def test_risk_uses_each_endpoint_address_independently_of_asset_alias():
    findings = [{"id": "private", "host": "10.0.0.1", "severity": 3, "assessment": "confirmed"},
                {"id": "public", "host": "8.8.8.8", "severity": 3, "assessment": "confirmed"}]
    risk = asset_risk(findings, address="10.0.0.1", criticality=1)
    other_alias = asset_risk(findings, address="8.8.8.8", criticality=1)
    assert risk["score"] == other_alias["score"]
    assert risk["endpoint_exposure"] == {"public": 1, "non_public": 1, "unknown": 0}
    assert [f["exposure_weight"] for f in risk["factors"]] == [1, 1.25]


def test_current_search_and_risk_survive_different_canonical_alias():
    local_run()
    finding = db.list_current_findings()[0][0]
    aid = finding["asset_id"]
    previous_risk = db.get_asset(aid)["risk"]["score"]
    db.add_asset_alias(aid, "8.8.8.8", actor="ops")
    run = NmapRun(start=int(datetime(2026, 10, 2, tzinfo=UTC).timestamp()), exit_status="success",
                  hosts=[Host("8.8.8.8", state="up", ports=[Port(80, state="open")])],
                  coverage={"engine": "nmap", "engine_version": "7.95", "rules_version": "v1",
                            "status": "complete", "rules": [], "protocols": {"tcp": [80]}})
    scan = db.create_scan(name="alias", targets="8.8.8.8", profile="rapido", execution_context={"namespace": "office"})
    db.save_results(scan, run, [], 0)
    db.set_status(scan, "done")
    assert db.get_asset(aid)["address"] == "8.8.8.8"
    assert db.list_current_findings(search="10.0.0.1")[1] == 1
    assert db.get_asset(aid)["risk"]["score"] == previous_risk


def test_large_asset_api_is_bounded_without_implicit_raw_history(tmp_path):
    document = {"schema": "scopescan.external.v1", "engine": "fixture", "engine_version": "1",
                "rules_version": "1", "observed_at": "2026-10-01T00:00:00Z",
                "coverage": {"status": "complete", "protocols": {"tcp": [23]}},
                "hosts": [{"address": "10.0.0.1", "state": "up", "ports": [{"port": 23, "protocol": "tcp", "state": "open"}]}],
                "findings": [{"host": "10.0.0.1", "port": 23, "protocol": "tcp", "rule_id": f"control-{number}",
                              "title": "fixture", "severity": "high", "evidence": "E" * 16000} for number in range(200)]}
    path = tmp_path / "big.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    importers.import_external_json(path, namespace="office")
    aid = db.list_assets()[0][0]["id"]
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50001)) as client:
        listing = client.get("/api/assets?limit=1")
        assert listing.status_code == 200
        assert len(listing.content) < 10000
        summary = listing.json()["items"][0]
        assert summary["finding_count"] == 200
        assert "findings" not in summary and "current_state" not in summary
        detail = client.get(f"/api/assets/{aid}")
        assert len(detail.content) < 100000
        assert "observations" not in detail.json() and "findings" not in detail.json()
        assert detail.json()["risk"]["factor_total"] == 200
        factors = client.get(f"/api/assets/{aid}/risk-factors?offset=100&limit=10").json()
        assert len(factors["items"]) == 10 and factors["total"] == 200
        assert detail.json()["risk"]["score"] == db.get_asset(aid)["risk"]["score"]
