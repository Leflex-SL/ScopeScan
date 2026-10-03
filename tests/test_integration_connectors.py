"""Wire-level connector contracts and conservative imported evidence."""
from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from scopescan import (
    db,
    defectdojo,
    destinations,
    durable_jobs,
    faraday,
    greenbone,
    integrations_service,
    integrations_store,
    scopes,
)
from scopescan._integration_http import Cancelled, ConnectorError, request_json, session
from scopescan.models import Assessment, Finding, Host, NmapRun, Severity

DATE = "2025-01-02T03:04:05+00:00"
REPORT_ID = "f0fdf522-276d-4893-9274-fb8699dc2270"
GMP = f'''<get_reports_response status="200"><report id="{REPORT_ID}"><report id="{REPORT_ID}"><gmp><version>22.5</version></gmp>
<scan_run_status>Done</scan_run_status><scan_start>2025-01-01T00:00:00Z</scan_start><scan_end>2025-01-02T03:04:05Z</scan_end>
<results><result id="result-1"><name>TLS issue</name><host>192.0.2.1<asset asset_id="host-1"/></host><port>443/tcp</port><severity>8.2</severity><threat>High</threat>
<description>Repository https://user:fake-secret@example.test/repo</description><qod><value>98</value><type>remote_banner</type></qod>
<nvt oid="1.3.6.1.4.1.25623.1.0.123"><name>TLS issue</name><refs><ref type="cve" id="CVE-2025-1234"/></refs><solution>Update TLS</solution></nvt></result></results>
<result_count><filtered>1</filtered></result_count></report></report></get_reports_response>'''.encode()


@pytest.fixture(autouse=True)
def connector_schema():
    with db.connect() as conn:
        integrations_store.migrate(conn)
        durable_jobs.migrate(conn)


@pytest.fixture
def scope_id():
    return scopes.create_scope(name="Lab", targets="192.0.2.1", authorized_by="operator")


@pytest.fixture
def scan_id(scope_id):
    identity = db.create_scan(name="Evidence", targets="192.0.2.1", profile="imported", authorized_by="operator", scope_id=scope_id,
        execution_context={"namespace": f"scope:{scope_id}", "observed_at": DATE})
    finding = Finding("TLS issue", Severity.HIGH, "rule:tls", "192.0.2.1", port=443, evidence="tested", confirmed=True, assessment=Assessment.CONFIRMED, rule_id="tls")
    db.save_results(identity, NmapRun(hosts=[Host("192.0.2.1", state="up")], hosts_total=1, hosts_up=1), [finding], 10)
    db.set_status(identity, "done")
    db.replace_cve_candidates(identity, [{"host":"192.0.2.1", "port":443, "protocol":"tcp", "detected_cpe":"cpe:x", "queried_cpe":"cpe:x", "cve_id":"CVE-2025-5678", "summary":"candidate", "cvss":9.8}])
    return identity


@pytest.fixture
def server():
    state = {"requests": [], "mode": "async", "polls": 0}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def send_json(self, value, status=200, headers=None):
            raw = json.dumps(value).encode()
            self.send_response(status)
            for name, header_value in (headers or {}).items():
                self.send_header(name, header_value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            state["requests"].append(("POST", self.path, dict(self.headers), body))
            if self.path == "/_api/login":
                self.send_json({"response": {"user": {"id": 1}}}, headers={"Set-Cookie": "session=fake-session-secret; Path=/; HttpOnly"})
            elif state["mode"] == "redirect":
                self.send_json({}, 302, {"Location": "https://other.example/api/v2/import-scan/"})
            elif state["mode"] == "badjson":
                self.send_json({"message": "accepted but omitted reference"})
            elif state["mode"] == "sync":
                self.send_json({"test": 42, "statistics": {"after": {"active": 2}}})
            else:
                self.send_json({"background_import": True, "test_id": 42, "status": "Processing", "findings_parsed": 2})
        def do_GET(self):
            state["requests"].append(("GET", self.path, dict(self.headers), b""))
            if "/api/v2/tests/" in self.path:
                state["polls"] += 1
                status = "Failed" if state["mode"] == "failed" else ("Post Processing - Deduplication" if state["polls"] == 1 else "Processed")
                self.send_json({"status": status, "processing": status != "Processed"})
            elif "/hosts/" in self.path:
                self.send_json({"rows": [{"id": 1, "key": 1, "value": {"_id": 1, "ip": "192.0.2.1"}}], "count": 1})
            elif "/services/" in self.path:
                self.send_json({"services": [{"id": 10, "key": 10, "value": {"_id": 10, "parent": 1, "port": 443, "protocol": "tcp", "name": "https"}}], "count": 1})
            elif "/vulns/" in self.path:
                self.send_json({"vulnerabilities": [{"id": 20, "key": 20, "value": {"_id": 20, "parent": 10, "parent_type": "Service", "name": "Remote claim", "severity": "high", "status": "opened", "confirmed": True, "desc": "Test fake-faraday-password", "cve": ["CVE-2025-1234"]}}], "count": 1})
            else:
                self.send_json({}, 404)
    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{instance.server_port}", state
    instance.shutdown()
    instance.server_close()
    thread.join(timeout=2)


def destination(url, kind="defectdojo"):
    options = {"allow_http_loopback": True, "timeout": 10}
    options.update({"token_env": "SCOPESCAN_DOJO_TOKEN"} if kind == "defectdojo" else {"username_env": "SCOPESCAN_FARADAY_USER", "password_env": "SCOPESCAN_FARADAY_PASSWORD", "workspace": "lab"})
    return integrations_store.get_destination(integrations_store.create_destination("Lab", kind, url, options))


@pytest.mark.parametrize("url", ["https://user:password@example.test", "https://user%40example.test", "http://example.test", "https://example.test?token=x", "https://example.test#secret", "https://example.test:invalid"])
def test_destination_rejects_credential_and_insecure_urls(url):
    with pytest.raises(ValueError):
        destinations.validate("defectdojo", url, {"token_env": "SCOPESCAN_DOJO_TOKEN"})


def test_destination_settings_never_accept_plaintext_credentials():
    with pytest.raises(ValueError):
        integrations_store.create_destination("X", "defectdojo", "https://example.test", {"token": "secret"})
    with pytest.raises(ValueError):
        destinations.validate("faraday", "https://example.test", {"username_env": "USER", "password_env": "secret value", "workspace": "lab"})


def test_generic_export_fields_dates_and_candidate_proof(scan_id):
    report = json.loads(defectdojo.generic_findings(scan_id))
    assert report["findings"][0]["date"] == DATE
    assert {item["severity"] for item in report["findings"]} == {"High", "Critical"}
    assert len({item["unique_id_from_tool"] for item in report["findings"]}) == 2
    assert report["findings"][0]["verified"] is True
    assert report["findings"][0]["unique_id_from_tool"] == db.get_findings(scan_id)[0]["stable_id"]
    candidate = next(item for item in report["findings"] if "CVE-2025-5678" in item.get("vulnerability_ids", []))
    assert candidate["verified"] is False
    assert candidate["endpoints"] == [{"host": "192.0.2.1", "port": 443, "protocol": "tcp"}]
    assert "type" not in report


def test_defectdojo_real_http_async_sync_and_idempotence(server, scan_id, monkeypatch):
    url, state = server
    monkeypatch.setenv("SCOPESCAN_DOJO_TOKEN", "fake-dojo-token")
    dest = destination(url)
    operation = integrations_service.enqueue_delivery(dest["id"], scan_id, engagement_id=7)
    assert operation == integrations_service.enqueue_delivery(dest["id"], scan_id, engagement_id=7)
    from scopescan import worker
    result = worker.run_once(job_id=operation["job_id"])
    assert result["status"] == "done", result
    delivery = integrations_store.get_delivery(operation["delivery_id"])
    assert delivery["remote_test_id"] == 42 and delivery["state"] == "done"
    posts = [row for row in state["requests"] if row[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == "/api/v2/import-scan/"
    assert b'name="close_old_findings"\r\n\r\nfalse' in posts[0][3]
    assert b'name="verified"' not in posts[0][3]
    defectdojo.deliver(operation["delivery_id"])
    assert len([row for row in state["requests"] if row[0] == "POST"]) == 1
    assert "fake-dojo-token" not in json.dumps(delivery)
    history, total = integrations_store.delivery_history(delivery["id"], limit=2)
    assert total >= 3 and len(history) == 2
    assert history[0]["state"] == "posting"
    state["mode"] = "sync"
    second = integrations_service.enqueue_delivery(dest["id"], scan_id, test_id=42)
    row = worker.run_once(job_id=second["job_id"])
    assert row["status"] == "done", row
    assert state["requests"][-1][1] == "/api/v2/reimport-scan/"


@pytest.mark.parametrize("mode", ["redirect", "badjson"])
def test_ambiguous_post_cannot_repeat_and_can_reconcile(server, scan_id, monkeypatch, mode):
    url, state = server
    state["mode"] = mode
    monkeypatch.setenv("SCOPESCAN_DOJO_TOKEN", "fake-dojo-token")
    value = integrations_service.enqueue_delivery(destination(url)["id"], scan_id, engagement_id=7)
    with pytest.raises(ConnectorError):
        defectdojo.deliver(value["delivery_id"])
    assert integrations_store.get_delivery(value["delivery_id"])["state"] == "action_required"
    with pytest.raises(ConnectorError, match="automatic POST retry refused"):
        defectdojo.deliver(value["delivery_id"])
    assert len(state["requests"]) == 1
    state["mode"] = "async"
    job = integrations_service.enqueue_poll(value["delivery_id"], remote_test_id=42)
    from scopescan import worker
    assert worker.run_once(job_id=job["job_id"])["status"] == "done"
    assert len([row for row in state["requests"] if row[0] == "POST"]) == 1


def test_remote_failure_preserves_reference_and_errors(server, scan_id, monkeypatch):
    url, state = server
    state["mode"] = "failed"
    monkeypatch.setenv("SCOPESCAN_DOJO_TOKEN", "fake-dojo-token")
    value = integrations_service.enqueue_delivery(destination(url)["id"], scan_id, engagement_id=7)
    from scopescan import worker
    result = worker.run_once(job_id=value["job_id"])
    delivery = integrations_store.get_delivery(value["delivery_id"])
    assert result["status"] == "failed"
    assert delivery["state"] == "failed" and delivery["remote_test_id"] == 42
    assert "fake-dojo-token" not in result["error"]


def test_missing_worker_secret_does_not_mark_posting(server, scan_id):
    url, state = server
    value = integrations_service.enqueue_delivery(destination(url)["id"], scan_id, engagement_id=7)
    with pytest.raises(ValueError, match="Worker credential"):
        defectdojo.deliver(value["delivery_id"])
    assert integrations_store.get_delivery(value["delivery_id"])["state"] == "prepared"
    assert not state["requests"]


def test_transport_no_ambient_proxy_cancel_and_size(server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://wrong.invalid:1")
    client = session()
    assert client.trust_env is False and client.verify is True
    event = threading.Event()
    event.set()
    with pytest.raises(Cancelled):
        request_json(client, "GET", server[0] + "/api/v2/tests/42/", cancel=event, deadline=time.monotonic() + 5)
    assert not server[1]["requests"]
    with pytest.raises(ConnectorError, match="byte limit"):
        request_json(client, "GET", server[0] + "/api/v2/tests/42/", deadline=time.monotonic() + 5, max_bytes=1)
    client.close()


def test_faraday_wire_cookie_parent_and_imported_proof(server, scope_id, monkeypatch):
    url, state = server
    monkeypatch.setenv("SCOPESCAN_FARADAY_USER", "operator")
    monkeypatch.setenv("SCOPESCAN_FARADAY_PASSWORD", "fake-faraday-password")
    queued = integrations_service.enqueue_pull(destination(url, "faraday")["id"], scope_id)
    from scopescan import worker
    row = worker.run_once(job_id=queued["job_id"])
    assert row["status"] == "done", row
    calls = state["requests"]
    assert json.loads(calls[0][3]) == {"email": "operator", "password": "fake-faraday-password"}
    assert all("session=fake-session-secret" in call[2].get("Cookie", "") for call in calls[1:])
    assert all("page_size=100" in call[1] for call in calls[1:])
    result = json.loads(row["result"])
    findings = db.get_findings(result["scan_id"])
    assert findings[0]["port"] == 443 and findings[0]["protocol"] == "tcp"
    assert not findings[0]["confirmed"] and findings[0]["assessment"] == "candidate"
    imported = integrations_store.get_import(result["import_id"], include_raw=True)
    assert "fake-faraday-password" not in json.dumps(imported)
    assert "fake-session-secret" not in json.dumps(imported)


def test_gmp_socket_framing_and_credentials_are_not_evidence(scope_id, monkeypatch):
    monkeypatch.setenv("GMP_USER", "reader")
    monkeypatch.setenv("GMP_PASSWORD", "fake-gmp-password")
    config = {"id": 1, "kind": "greenbone", "url": "tls://example.test:9390", "settings": {"username_env": "GMP_USER", "password_env": "GMP_PASSWORD", "timeout": 5}}
    left, right = socket.socketpair()
    commands = []
    def server():
        for response in (b'<authenticate_response status="200"/>', GMP):
            commands.append(greenbone.parse_xml(right.recv(16384)))
            for index in range(0, len(response), 19):
                right.sendall(response[index:index+19])
        right.close()
    thread = threading.Thread(target=server)
    thread.start()
    payload = greenbone.pull(config, REPORT_ID, stream=left)
    left.close()
    thread.join(timeout=2)
    assert commands[0].findtext("./credentials/password") == "fake-gmp-password"
    assert commands[1].attrib == {"report_id": REPORT_ID, "details": "1", "filter": "first=1 rows=-1"}
    result = integrations_service.import_evidence("greenbone", payload, scope_id=scope_id)
    imported = integrations_store.get_import(result["import_id"], include_raw=True)
    assert imported["observed_at"] == DATE
    assert imported["received_sha256"] == hashlib.sha256(GMP).hexdigest()
    assert imported["normalized"]["results"][0]["qod"] == 98
    assert "fake-secret" not in imported["raw"] and "fake-gmp-password" not in imported["raw"]
    assert not db.get_findings(result["scan_id"])[0]["confirmed"]


@pytest.mark.parametrize("payload", [b'<!DOCTYPE x [<!ENTITY secret "boom">]><x>&secret;</x>', b'<report>' + b'<x>' * 70 + b'</x>' * 70 + b'</report>', b'x' * 8_000_001], ids=["entities", "depth", "bytes"])
def test_gmp_unsafe_or_excessive_xml_rejected(payload):
    with pytest.raises(ValueError):
        greenbone.normalize(payload)


def test_import_future_or_scope_mismatch_atomic(scope_id):
    for payload in (GMP.replace(b'192.0.2.1', b'192.0.2.99'), GMP.replace(b'2025-01-02T03:04:05Z', b'2099-01-02T03:04:05Z')):
        with pytest.raises(ValueError):
            integrations_service.import_evidence("greenbone", payload, scope_id=scope_id)
    assert db.list_scans() == []
    assert integrations_store.page("integration_imports")[1] == 0


def test_gmp_partial_metadata(scope_id):
    value = integrations_service.import_evidence("greenbone", GMP.replace(b'<scan_run_status>Done', b'<scan_run_status>Running').replace(b'<filtered>1', b'<filtered>2'), scope_id=scope_id)
    assert value["status"] == "partial"
    assert len(integrations_store.get_import(value["import_id"])["normalized"]["errors"]) == 2


def test_panel_routes_are_queue_only(scope_id, scan_id, monkeypatch):
    from scopescan.web.integrations import router
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app, base_url="http://127.0.0.1")
    monkeypatch.setattr(defectdojo, "deliver", lambda *args, **kwargs: pytest.fail("web made remote call"))
    destination_id = integrations_store.create_destination("Dojo", "defectdojo", "https://dojo.example", {"token_env": "SCOPESCAN_DOJO_TOKEN"})
    response = client.get("/integrations")
    assert response.status_code == 200 and "Configurar destino" in response.text
    response = client.post("/integrations/deliver", data={"destination_id": destination_id, "scan_id": scan_id, "engagement_id": 7}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"].startswith("/jobs/")
    assert durable_jobs.list_jobs()[0]["status"] == "queued"
    imported = client.post(f"/api/integrations/import/greenbone?scope_id={scope_id}", content=GMP)
    assert imported.status_code == 200
    identity = imported.json()["import_id"]
    assert client.get(f"/integrations/imports/{identity}").status_code == 200
    assert client.get(f"/api/integrations/imports/{identity}/raw").status_code == 200
    assert client.get("/api/integrations/imports?limit=1&offset=0").json()["total"] == 1
    assert client.get(f"/integrations/export/defectdojo/{scan_id}").status_code == 200


def test_faraday_pagination_beyond_first_hundred_and_bad_counts(monkeypatch):
    config = {"url": "https://faraday.example", "settings": {"workspace": "lab"}}
    pages = []
    def response(client, method, url, **kwargs):
        page = kwargs["params"]["page"]
        pages.append(page)
        numbers = range(1, 101) if page == 1 else [101]
        return {"rows": [{"id": n, "value": {"_id": n, "ip": "192.0.2.1"}} for n in numbers], "count": 101}
    monkeypatch.setattr(faraday, "request_json", response)
    items = faraday.collection(object(), config, "hosts", cancel=None, deadline=time.monotonic() + 5)
    assert len(items) == 101 and pages == [1, 2]
    monkeypatch.setattr(faraday, "request_json", lambda *args, **kwargs: {"rows": [], "count": 1})
    with pytest.raises(ConnectorError, match="before the declared count"):
        faraday.collection(object(), config, "hosts", cancel=None, deadline=time.monotonic() + 5)
    monkeypatch.setattr(faraday, "request_json", lambda *args, **kwargs: {"rows": []})
    with pytest.raises(ConnectorError, match="count"):
        faraday.collection(object(), config, "hosts", cancel=None, deadline=time.monotonic() + 5)


def test_faraday_malformed_and_nonfinite_imports_atomic(scope_id):
    for payload in (b'{"hosts":[1],"services":[],"vulns":[],"observed_at":"2025-01-01T00:00:00Z"}',
                    b'{"hosts":[],"services":[],"vulns":[],"observed_at":"2025-01-01T00:00:00Z","extra":NaN}'):
        with pytest.raises(ValueError):
            integrations_service.import_evidence("faraday", payload, scope_id=scope_id)
    assert db.list_scans() == []


def test_scope_authorization_changed_before_worker_refuses_network(server, scope_id, monkeypatch):
    url, state = server
    config = destination(url, "faraday")
    value = integrations_service.enqueue_pull(config["id"], scope_id)
    with db.connect() as conn:
        specification = json.loads(conn.execute("SELECT specification FROM saved_scopes WHERE id=?", (scope_id,)).fetchone()[0])
        specification["authorized_by"] = "changed"
        conn.execute("UPDATE saved_scopes SET specification=? WHERE id=?", (json.dumps(specification), scope_id))
    from scopescan import worker
    result = worker.run_once(job_id=value["job_id"])
    assert result["status"] == "failed" and not state["requests"]


def test_cli_import_original_file_intact_and_export(scan_id, scope_id, tmp_path, capsys):
    from scopescan import cli
    path = tmp_path / "gmp.xml"
    path.write_bytes(GMP)
    assert cli.main(["integration", "import", "greenbone", str(path), "--scope-id", str(scope_id)]) == 0
    value = json.loads(capsys.readouterr().out)
    assert path.read_bytes() == GMP
    assert cli.main(["integration", "raw", str(value["import_id"])]) == 0
    assert "fake-secret" not in capsys.readouterr().out
    assert cli.main(["integration", "export", str(scan_id)]) == 0
    assert json.loads(capsys.readouterr().out)["findings"]


def test_gmp_silent_socket_cancels_without_waiting_deadline(monkeypatch):
    monkeypatch.setenv("GMP_USER", "reader")
    monkeypatch.setenv("GMP_PASSWORD", "fake-password")
    left, right = socket.socketpair()
    event = threading.Event()
    timer = threading.Timer(.1, event.set)
    timer.start()
    config = {"url": "tls://example.test:9390", "settings": {"username_env": "GMP_USER", "password_env": "GMP_PASSWORD", "timeout": 5}}
    start = time.monotonic()
    try:
        with pytest.raises(Cancelled):
            greenbone.pull(config, REPORT_ID, stream=left, cancel=event)
        assert time.monotonic() - start < 2
    finally:
        left.close()
        right.close()
        timer.cancel()


def test_gmp_unfinished_token_bound_prevents_quadratic_parsing():
    left, right = socket.socketpair()
    def server():
        right.recv(4096)
        try:
            right.sendall(b'<authenticate_response status="' + b'a' * 80_000)
        except OSError:
            pass
        finally:
            right.close()
    thread = threading.Thread(target=server)
    thread.start()
    from xml.etree import ElementTree
    try:
        with pytest.raises(ConnectorError, match="token exceeds"):
            greenbone._exchange(left, ElementTree.Element("authenticate"), cancel=None, deadline=time.monotonic() + 5)
    finally:
        left.close()
        thread.join(timeout=2)


def test_real_app_browser_csrf_and_delivery_history(scan_id):
    from scopescan.web.app import app
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 40000))
    page = client.get("/integrations")
    assert page.status_code == 200
    csrf = client.cookies["scopescan_csrf"]
    response = client.post("/integrations/destinations", headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": csrf},
        data={"name": "Dojo", "kind": "defectdojo", "url": "https://dojo.example", "options": '{"token_env":"SCOPESCAN_DOJO_TOKEN"}'}, follow_redirects=False)
    assert response.status_code == 303
    destination_id = integrations_store.page("integration_destinations")[0][0]["id"]
    response = client.post("/integrations/deliver", headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": csrf},
        data={"destination_id": destination_id, "scan_id": scan_id, "engagement_id": 7}, follow_redirects=False)
    assert response.status_code == 303
    identity = integrations_store.page("integration_deliveries")[0][0]["id"]
    assert client.get(f"/integrations/deliveries/{identity}").status_code == 200
    assert client.get(f"/api/integrations/deliveries/{identity}/raw").status_code == 200
    assert client.get(f"/api/integrations/deliveries/{identity}/history").json()["total"] == 0
    imported = client.post("/integrations/import", headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": csrf},
        data={"kind": "greenbone", "scope_id": db.get_scan(scan_id)["scope_id"]},
        files={"file": ("gmp.xml", GMP, "application/xml")}, follow_redirects=False)
    assert imported.status_code == 303
    assert client.get(imported.headers["location"]).status_code == 200
    denied = client.post("/integrations/poll", data={"delivery_id": identity, "remote_test_id": 42})
    assert denied.status_code == 403
