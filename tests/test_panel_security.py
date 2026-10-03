"""Panel security regressions; no engine or network is launched."""
from __future__ import annotations

import base64
import re
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from scopescan import db
from scopescan.web import app as web_app


def local_client(**kwargs):
    return TestClient(web_app.app, base_url="http://localhost", client=("127.0.0.1", 50000),
                      **kwargs)


@pytest.mark.parametrize("host", ["evil.example", "localhost.evil.example", "user@localhost",
                                 "localhost:invalid", "localhost:0", "localhost:65536"])
def test_untrusted_host_blocks_read_and_matching_origin(host):
    client = local_client()
    assert client.get("/openapi.json", headers={"Host": host}).status_code == 403
    assert client.post("/api/preview", data={"targets": "10.0.0.1"},
                       headers={"Host": host, "Origin": "http://" + host}).status_code == 403


@pytest.mark.parametrize("origin", ["http://localhost:invalid", "http://[::1", "null",
                                   "http://localhost:0", "http://localhost:65536",
                                   "http://user@localhost", "https://evil.example"])
def test_invalid_origin_is_rejected_without_500(origin):
    assert local_client().post("/api/preview", data={"targets": "10.0.0.1"},
                               headers={"Origin": origin}).status_code == 403


def test_basic_auth_applies_to_loopback_and_proxy(monkeypatch):
    monkeypatch.setenv("SCOPESCAN_PANEL_USER", "audit")
    monkeypatch.setenv("SCOPESCAN_PANEL_PASSWORD", "secret")
    client = local_client()
    assert client.get("/openapi.json").status_code == 401
    token = base64.b64encode(b"audit:secret").decode()
    headers = {"Authorization": "Basic " + token, "X-Forwarded-For": "203.0.113.8"}
    assert client.get("/openapi.json", headers=headers).status_code == 200
    # A loopback upstream connection still cannot bypass configured authentication.
    assert client.get("/openapi.json", headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 401


def test_proxy_headers_do_not_grant_local_access():
    remote = TestClient(web_app.app, base_url="http://localhost", client=("203.0.113.8", 9000))
    assert remote.get("/openapi.json", headers={"X-Forwarded-For": "127.0.0.1",
                                              "X-Forwarded-Host": "localhost"}).status_code == 403


def test_explicit_lab_host_and_canonical_origin(monkeypatch):
    monkeypatch.setenv("SCOPESCAN_PANEL_HOSTS", "panel.lab")
    monkeypatch.setenv("SCOPESCAN_PANEL_ORIGINS", "http://panel.lab:80")
    client = TestClient(web_app.app, base_url="http://panel.lab", client=("127.0.0.1", 50000))
    page = client.get("/scans/new")
    assert page.status_code == 200
    token = client.cookies.get("scopescan_csrf")
    response = client.post("/api/preview", data={"targets": "10.0.0.1"},
                           headers={"Origin": "http://PANEL.LAB", "X-CSRF-Token": token})
    assert response.status_code == 200
    # Configuring a Host does not automatically trust that Host as a browser origin.
    monkeypatch.setenv("SCOPESCAN_PANEL_ORIGINS", "http://localhost")
    assert client.post("/api/preview", data={"targets": "10.0.0.1"},
                       headers={"Origin": "http://panel.lab", "X-CSRF-Token": token}).status_code == 403


def test_real_browser_form_and_fetch_csrf():
    client = local_client()
    page = client.get("/scans/new")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    assert client.post("/api/preview", data={"targets": "10.0.0.1"},
                       headers={"Origin": "http://localhost"}).status_code == 403
    form = client.post("/api/preview", data={"targets": "10.0.0.1", "csrf_token": token},
                       headers={"Origin": "http://localhost"})
    assert form.status_code == 200 and form.json()["ok"]
    assert client.post("/api/preview", data={"targets": "10.0.0.1"},
                       headers={"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": token}).status_code == 200
    assert client.post("/api/preview", data={"targets": "10.0.0.1"},
                       headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": token}).status_code == 403
    client.cookies.set("scopescan_csrf", "tampered")
    assert client.post("/api/preview", data={"targets": "10.0.0.1"},
                       headers={"X-CSRF-Token": "tampered"}).status_code == 403


def test_headerless_cli_client_stays_supported():
    client = local_client()
    assert client.post("/api/preview", data={"targets": "10.0.0.1"}).status_code == 200
    assert not client.cookies


def test_claim_enrichment_is_atomic():
    scan_id = db.create_scan(name="race", targets="10.0.0.1", profile="rapido")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: db.claim_enrichment_job(scan_id, "nvd"), range(16)))
    assert sum(results) == 1
    db.set_enrichment_status(scan_id, "nvd", "done")
    assert db.claim_enrichment_job(scan_id, "nvd")


def test_inventory_is_loaded_on_demand_and_paginated():
    scan_id = db.create_scan(name="inventory", targets="10.0.0.1", profile="rapido")
    from scopescan.models import Host, NmapRun
    run = NmapRun(hosts=[Host(address="10.0.0.1", state="up")])
    db.save_results(scan_id, run, [], 0)
    db.save_host_inventory(scan_id, "10.0.0.1", {
        "platform": "linux", "os_name": "Linux", "os_version": "test", "kernel": "1",
        "packages": [{"name": f"package-{n:04}", "version": "1"} for n in range(205)],
        "firewall": {}, "aslr": None,
    }, "fixture")
    client = local_client()
    detail = client.get(f"/scans/{scan_id}").text
    assert "205 paquetes" in detail
    assert "package-0000" not in detail
    first = client.get(f"/scans/{scan_id}/inventory/10.0.0.1/packages").text
    assert "package-0000" in first and "package-0100" not in first
    last = client.get(f"/scans/{scan_id}/inventory/10.0.0.1/packages?page=3").text
    assert "package-0200" in last and "package-0199" not in last
    searched = client.get(f"/scans/{scan_id}/inventory/10.0.0.1/packages?q=0204").text
    assert "package-0204" in searched and "package-0203" not in searched
    assert client.get(f"/scans/{scan_id}/inventory/10.0.0.2/packages").status_code == 404


def test_scan_pagination_and_search():
    for n in range(30):
        db.create_scan(name=f"scan-{n:02}", targets="10.0.0.1", profile="rapido")
    client = local_client()
    first = client.get("/").text
    assert "scan-29" in first and "scan-00" not in first and "Siguiente" in first
    second = client.get("/?page=2").text
    assert "scan-00" in second and "scan-29" not in second
    filtered = client.get("/?q=scan-01").text
    assert "scan-01" in filtered and "scan-02" not in filtered


def test_delete_refuses_active_enrichment():
    scan_id = db.create_scan(name="active", targets="10.0.0.1", profile="rapido")
    assert db.claim_enrichment_job(scan_id, "nvd")
    response = local_client().post(f"/scans/{scan_id}/delete", follow_redirects=False)
    assert response.status_code == 409
    assert db.get_scan(scan_id) is not None


def test_enrichment_route_cannot_launch_duplicate(monkeypatch):
    scan_id = db.create_scan(name="active", targets="10.0.0.1", profile="rapido")
    db.set_status(scan_id, "done")
    assert db.claim_enrichment_job(scan_id, "nvd")
    calls = []
    monkeypatch.setattr(web_app, "_submit_enrichment", lambda *args: calls.append(args))
    response = local_client().post(f"/scans/{scan_id}/enrich/nvd", follow_redirects=False)
    assert response.status_code == 303 and calls == []


def test_explicit_refresh_calls_probe_and_requires_browser_token(monkeypatch):
    client = local_client()
    # Use existing form to obtain a valid session, then replace the refresh probe.
    client.get("/scans/new")
    calls = []
    monkeypatch.setattr(web_app, "probe_environment", lambda **kwargs: calls.append(kwargs))
    denied = client.post("/api/environment/refresh", follow_redirects=False)
    assert denied.status_code == 403 and not calls
    allowed = client.post("/api/environment/refresh", headers={
        "X-CSRF-Token": client.cookies.get("scopescan_csrf")}, follow_redirects=False)
    assert allowed.status_code == 303 and calls == [{"refresh": True}]


def test_secure_cookie_opt_in_for_tls_proxy(monkeypatch):
    monkeypatch.setenv("SCOPESCAN_PANEL_COOKIE_SECURE", "1")
    response = local_client().get("/scans/new")
    assert "; Secure" in response.headers["set-cookie"]


def test_zip_download_does_not_use_bytes_api_and_cleans_temp(monkeypatch):
    from scopescan import export
    scan_id = db.create_scan(name="zip", targets="10.0.0.1", profile="rapido")
    def forbidden(*args, **kwargs):
        raise AssertionError("legacy bytes API must not serve ZIP downloads")
    monkeypatch.setattr(export, "render_bundle", forbidden)
    response = local_client().get(f"/scans/{scan_id}/bundle.zip")
    assert response.status_code == 200 and response.content.startswith(b"PK")
    assert not list((export.raw_dir() / "exports").glob("*.zip"))
