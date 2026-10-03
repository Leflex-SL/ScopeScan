"""Rendered continuous workflows and CLI contracts, without network scans."""

from __future__ import annotations

import json
import re
from html import unescape

import pytest
from fastapi.testclient import TestClient

from scopescan import cli, db, export, importers, nmap_runner, report, scopes, service
from scopescan.web import app as web


@pytest.fixture
def browser(monkeypatch):
    submitted = []
    monkeypatch.setattr(web.QUEUE, "submit", lambda scan_id: submitted.append(scan_id))
    monkeypatch.setattr(web.QUEUE, "shutdown", lambda **kwargs: None)
    with TestClient(web.app, base_url="http://localhost", client=("127.0.0.1", 51000)) as client:
        client.get("/assets")
        client.headers["X-CSRF-Token"] = client.cookies["scopescan_csrf"]
        yield client, submitted


def external_doc(*, stamp="2026-10-03T10:00:00Z", findings=True, complete=True):
    return {"schema": "scopescan.external.v1", "engine": "fixture", "engine_version": "1",
            "rules_version": "1", "observed_at": stamp,
            "coverage": {"status": "complete" if complete else "partial",
                         "protocols": {"tcp": [23]}, "rules": ["telnet"] if complete else []},
            "hosts": [{"address": "192.0.2.10", "state": "up", "ports": [
                {"port": 23, "protocol": "tcp", "state": "open",
                 "service": {"name": "telnet"}}]}],
            "findings": [{"host": "192.0.2.10", "port": 23, "protocol": "tcp",
                          "rule_id": "telnet", "title": "<script>alert(7)</script>",
                          "severity": "high", "evidence": "Untrusted external evidence"}]
            if findings else []}


def upload(client, **overrides):
    response = client.post("/api/imports/external?namespace=fixture-team&name=observation",
                           content=json.dumps(external_doc(**overrides)),
                           headers={"Content-Type": "application/octet-stream"})
    assert response.status_code == 200, response.text
    return response.json()["scan_id"]


def test_rendered_import_asset_remediation_and_partial_coverage(browser):
    client, _ = browser
    scan_id = upload(client)
    listing = client.get("/assets?q=192.0.2.10&scope_id=")
    assert listing.status_code == 200 and "Activos vigentes" in listing.text
    asset = db.list_assets()[0][0]
    findings, total = db.list_current_findings()
    assert total == 1
    finding = findings[0]
    asset_page = client.get(f"/assets/{asset['id']}")
    assert asset_page.status_code == 200
    assert "Riesgo explicable" in asset_page.text and "Observaciones historicas" in asset_page.text
    assert "<script>alert(7)</script>" not in asset_page.text
    assert "&lt;script&gt;alert(7)&lt;/script&gt;" in asset_page.text
    assert "Endpoints vigentes" in asset_page.text
    observed = client.get(f"/api/assets/{asset['id']}/observations")
    assert observed.status_code == 200 and len(observed.json()["items"]) == 1
    updated = client.post(f"/assets/{asset['id']}/metadata",
                          data={"criticality": "5", "alias": "192.0.2.11", "actor": "operator"})
    assert updated.status_code == 200
    assert db.get_asset(asset["id"])["criticality"] == 5
    assert asset["id"] in client.get("/assets?q=192.0.2.11").text
    invalid = client.post(f"/assets/{asset['id']}/metadata", data={
        "criticality": 2, "alias": "invalid-host", "actor": "operator"})
    assert invalid.status_code == 400
    assert db.get_asset(asset["id"])["criticality"] == 5
    response = client.post(f"/remediation/{finding['id']}", data={
        "owner": "<img src=x onerror=alert(1)>", "status": "in_progress", "actor": "operator",
        "due_at": "2026-10-20T12:00:00+00:00"})
    assert response.status_code == 200 and "Historial de acciones" in response.text
    assert "<img src=x" not in response.text
    response = client.post(f"/remediation/{finding['id']}", data={
        "status": "closed", "actor": "operator", "evidence": "Supposed repair complete",
        "verification_scan_id": scan_id})
    assert response.status_code == 400 and "Closure requires" in response.text
    assert db.get_current_finding(finding["id"])["status"] == "in_progress"
    partial_id = upload(client, stamp="2026-10-03T11:00:00Z", findings=False, complete=False)
    assert db.get_current_finding(finding["id"])["lifecycle"] == "not_assessed"
    delta = client.get(f"/scans/{partial_id}/delta")
    assert delta.status_code == 200 and "not_assessed" in delta.text
    assert client.get(f"/scans/{scan_id}").status_code == 200
    assert "external_unverified" in client.get(f"/scans/{scan_id}").text
    filtered = client.get("/current-findings?status=in_progress&scope_id=&q=script")
    assert filtered.status_code == 200 and finding["id"] in filtered.text
    assert client.get("/api/current-findings?q=script").json()["total"] == 1
    assert client.get("/api/current-findings?min_severity=4").json()["total"] == 0
    assert client.get("/api/current-findings?assessment=candidate&lifecycle=not_assessed").json()["total"] == 1


def test_import_csrf_limits_and_errors(browser, monkeypatch):
    client, _ = browser
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/imports/external", content=b"{}").status_code == 403
    client.headers["X-CSRF-Token"] = client.cookies["scopescan_csrf"]
    from scopescan.web import continuity
    monkeypatch.setattr(continuity, "MAX_IMPORT_BYTES", 16)
    assert client.post("/api/imports/nmap", content=b"x" * 17).status_code == 413
    assert client.post("/api/imports/invalid", content=b"{}").status_code == 400
    assert client.post("/api/imports/external", content=b"{}").status_code == 400
    assert client.post("/assets/invalid/metadata", data={"criticality": 1}).status_code == 404
    assert client.post("/remediation/invalid", data={"status": "closed"}).status_code == 404
    assert client.get("/scopes/999").status_code == 404
    assert client.post("/scopes/999/preview").status_code == 404


def test_saved_scope_form_preview_update_queue(browser):
    client, submitted = browser
    created = client.post("/scopes", data={"name": "Lab", "targets": "192.0.2.1 192.0.2.2",
        "exclusions": "192.0.2.2", "profile": "rapido", "authorized_by": "operator"})
    assert created.status_code == 200
    items, total = scopes.list_scopes()
    assert total == 1
    scope_id = items[0]["id"]
    preview = client.post(f"/scopes/{scope_id}/preview")
    assert preview.status_code == 200 and "192.0.2.1" in preview.text
    assert "Previsualizar IP guardadas" in preview.text
    old_token = re.search(r'name="preview_token" value="([^"]+)"', preview.text)[1]
    updated = client.post("/scopes", data={"scope_id": scope_id, "name": "Lab revised",
        "targets": "192.0.2.3", "profile": "rapido", "authorized_by": "operator"})
    assert updated.status_code == 200 and "Lab revised" in updated.text
    assert client.post(f"/scopes/{scope_id}/queue", data={"preview_token": old_token}).status_code == 400
    preview = client.post(f"/scopes/{scope_id}/preview")
    token = re.search(r'name="preview_token" value="([^"]+)"', preview.text)[1]
    client.post(f"/scopes/{scope_id}/queue", data={"preview_token": token})
    assert len(submitted) == 1
    row = db.get_scan(submitted[0])
    assert row["targets"] == "192.0.2.3" and row["scope_id"] == scope_id
    assert client.get("/scopes").status_code == 200


@pytest.mark.parametrize("token", ["", "é" * 75, "1" * 10000, "1234567890.." + "a" * 64,
                                   "1234567890." + "Ａ" * 64, "1234567890/" + "a" * 64])
def test_scope_preview_tokens_reject_malformed_input(browser, token):
    client, submitted = browser
    scope_id = scopes.create_scope(name="Lab", targets="192.0.2.1", authorized_by="operator")
    response = client.post(f"/scopes/{scope_id}/queue", data={"preview_token": token})
    assert response.status_code == 400 and not submitted


def test_verification_queue_failure_reports_actual_status(browser, xml_file, monkeypatch):
    client, _ = browser
    importers.import_nmap(xml_file, namespace="lab")
    finding = next(row for row in db.list_current_findings()[0] if row["source"] == "rule:telnet-claro")
    def fail(scan_id):
        raise RuntimeError("Worker unavailable")
    monkeypatch.setattr(web.QUEUE, "submit", fail)
    response = client.post("/verification", data={"finding_ids": finding["id"],
                                                "authorized_by": "operator", "action": "queue"})
    assert response.status_code == 400 and "Worker unavailable" in response.text
    scan_id = db.list_scans()[0]["id"]
    assert db.get_scan(scan_id)["status"] == "failed"
    assert f'href="/scans/{scan_id}"' in response.text


def test_verification_preview_and_queue_use_real_owned_controls(browser, xml_file):
    client, submitted = browser
    importers.import_nmap(xml_file, namespace="lab")
    finding = next(row for row in db.list_current_findings()[0] if row["source"] == "rule:telnet-claro")
    form = client.get(f"/verification?finding_id={finding['id']}")
    assert form.status_code == 200 and finding["id"] in form.text
    result = client.post("/verification", data={"finding_ids": finding["id"],
                                               "authorized_by": "operator", "action": "preview"})
    assert result.status_code == 200 and "Escaneos dirigidos" in result.text
    assert not submitted
    result = client.post("/verification", data={"finding_ids": finding["id"],
                                               "authorized_by": "operator", "action": "queue"})
    assert result.status_code == 200 and len(submitted) == 1
    context = json.loads(db.get_scan(submitted[0])["execution_context"])
    assert context["verification"]["ports"] == [23]
    assert context["verification_of"] == [finding["id"]]
    asset_id = finding["asset_id"]
    asset_response = client.get(f"/assets/{asset_id}")
    assert len(asset_response.content) < 120_000
    assert "JSON completo de esta observacion" in asset_response.text
    assert "65535" not in asset_response.text  # Huge port coverage stays in the explicit observation API.
    evidence = client.get(f"/api/assets/{asset_id}/observations")
    assert len(evidence.json()["items"][0]["coverage"]["protocols"]["tcp"]) == 65535


def test_rendered_verified_correction_exception_and_closure(browser, xml_file, tmp_path):
    client, submitted = browser
    initial_id = service.queue_scan(service.ScanRequest(targets="192.168.1.10", profile="rapido"))
    db.set_scan_context(initial_id, execution_context={"namespace": "lab"})
    db.set_status(initial_id, "running")
    service._store(initial_id, nmap_runner.NmapExecution(argv=["nmap"], returncode=0,
                   xml_path=xml_file, stdout="", stderr=""), target_private=True)
    finding = next(row for row in db.list_current_findings()[0]
                   if row["source"] == "rule:telnet-claro")
    response = client.post(f"/remediation/{finding['id']}", data={"status": "exception",
        "actor": "operator", "owner": "Operations", "exception_until": "2099-01-01T00:00:00Z",
        "evidence": "Temporary exception approved for migration window"})
    assert response.status_code == 200
    client.post("/verification", data={"finding_ids": finding["id"],
                                        "authorized_by": "operator", "action": "queue"})
    scan_id = submitted[-1]
    corrected = tmp_path / "verified.xml"
    corrected.write_text('''<nmaprun scanner="nmap" version="7.95" start="1758200300">
<scaninfo type="connect" protocol="tcp" numservices="1" services="23"/>
<host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>
<ports><port portid="23" protocol="tcp"><state state="closed"/></port></ports></host>
<runstats><finished exit="success" elapsed="1"/><hosts up="1" total="1"/></runstats></nmaprun>''',
                         encoding="utf-8")
    db.set_status(scan_id, "running")
    execution = nmap_runner.NmapExecution(argv=["nmap"], returncode=0, xml_path=corrected,
                                          stdout="", stderr="")
    service._store(scan_id, execution, target_private=True)
    assert db.get_current_finding(finding["id"])["lifecycle"] == "resolved"
    response = client.post(f"/remediation/{finding['id']}", data={"status": "closed",
        "actor": "operator", "owner": "Operations", "verification_scan_id": scan_id,
        "evidence": "Telnet disabled; directed observation confirms the endpoint is closed"})
    assert response.status_code == 200, response.text
    assert "Cerrado" in response.text
    assert db.get_current_finding(finding["id"])["status"] == "closed"
    assert len(db.remediation_history(finding["id"])) == 2


def test_cli_assets_import_remediation_delta_and_scope(tmp_path, capsys):
    document = tmp_path / "external.json"
    document.write_text(json.dumps(external_doc()), encoding="utf-8")
    assert cli.main(["import", "external", str(document), "--namespace", "cli-lab"]) == 0
    result = json.loads(capsys.readouterr().out)
    scan_id = result["scan_id"]
    assert cli.main(["assets", "--search", "192.0.2.10"]) == 0
    asset = json.loads(capsys.readouterr().out)["items"][0]
    assert cli.main(["asset", asset["id"], "--criticality", "4", "--alias", "192.0.2.12"]) == 0
    assert json.loads(capsys.readouterr().out)["criticality"] == 4
    assert cli.main(["current-findings", "--asset-id", asset["id"]]) == 0
    finding = json.loads(capsys.readouterr().out)["items"][0]
    assert cli.main(["remediate", finding["id"], "--status", "in_progress", "--owner", "Ada"]) == 0
    assert json.loads(capsys.readouterr().out)["owner"] == "Ada"
    assert cli.main(["remediate", finding["id"], "--history"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["actor"] == "cli"
    assert cli.main(["delta", str(scan_id)]) == 0
    assert "coverage" in json.loads(capsys.readouterr().out)
    assert cli.main(["scope", "create", "--name", "lab", "--targets", "192.0.2.1",
                     "--authorized-by", "Ada", "--profile", "rapido"]) == 0
    scope_id = json.loads(capsys.readouterr().out)["id"]
    assert cli.main(["scope", "preview", str(scope_id)]) == 0
    assert json.loads(capsys.readouterr().out)["hosts"] == 1
    assert cli.main(["verify", finding["id"], "--authorized-by", "Ada"]) == 0
    assert json.loads(capsys.readouterr().out)["missing_controls"]
    assert cli.main(["remediate", finding["id"], "--status", "closed", "--evidence",
                     "Invalid premature closure"]) == 2
    assert "Closure requires" in capsys.readouterr().err
    assert cli.main(["asset-history", asset["id"], "--limit", "25"]) == 0
    assert json.loads(capsys.readouterr().out)["total"] == 1
    assert cli.main(["historical-findings", "--search", "script"]) == 0
    assert len(json.loads(capsys.readouterr().out)["items"]) == 1
    payload = export.scan_payload(scan_id)
    assert payload["observation"]["provenance"]["engine"] == "fixture"
    assert "Procedencia y cobertura" in report.render_report(scan_id, payload=payload)


def test_current_lists_and_history_follow_rendered_pagination(browser):
    client, _ = browser
    document = external_doc()
    template_host, template_finding = document["hosts"][0], document["findings"][0]
    document["hosts"] = [{**template_host, "address": f"192.0.2.{number}"}
                         for number in range(1, 54)]
    document["findings"] = [{**template_finding, "host": f"192.0.2.{number}"}
                            for number in range(1, 54)]
    response = client.post("/api/imports/external?namespace=pages", content=json.dumps(document))
    assert response.status_code == 200
    for path in ("/assets?q=192.0.2", "/current-findings?q=script&assessment=candidate"):
        first = client.get(path)
        next_link = re.search(r'href="([^"]+)">Siguiente</a>', first.text)[1]
        second = client.get(path.split("?")[0] + unescape(next_link))
        assert second.status_code == 200 and "pagina 2" in second.text
        assert "Siguiente</a>" not in second.text
        assert len(re.findall(r'href="/remediation/', second.text)) == (3 if "findings" in path else 0)
    asset = db.list_assets(search="192.0.2.10")[0][0]
    # Persist 101 historical observations to exercise the page beyond get_asset's 100 cap.
    scan_ids = [db.create_scan(name=f"historical-{number}", targets="192.0.2.10", profile="imported")
                for number in range(101)]
    with db.connect() as conn:
        original = conn.execute("SELECT * FROM asset_observations WHERE asset_id=?", (asset["id"],)).fetchone()
        for scan_id in scan_ids:
            conn.execute("INSERT INTO asset_observations VALUES(?,?,?,?,?)", (
                asset["id"], scan_id, original["observed_at"], original["snapshot"], original["coverage"]))
    detail = client.get(f"/assets/{asset['id']}?history_page=5")
    assert detail.status_code == 200 and "102 observaciones" in detail.text
    assert "pagina 5" in detail.text and "Siguiente</a>" not in detail.text
