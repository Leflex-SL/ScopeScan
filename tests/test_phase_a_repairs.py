"""Verified review blockers: local fixtures, SQLite races and mocked motors only."""
from __future__ import annotations

import base64
import os
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scopescan import db, jobs, linux_inventory, msf, msf_modules, nmap_parser, report
from scopescan.compliance import linux_controls
from scopescan.web import app as web


def client():
    return TestClient(web.app, base_url="http://localhost", client=("127.0.0.1", 50000))


def scan(nmap_xml=None):
    sid = db.create_scan(name="review", targets="192.168.1.10", profile="rapido",
                         authorized_by="fixture")
    if nmap_xml:
        db.save_results(sid, nmap_parser.parse_string(nmap_xml), [], 0)
    db.set_status(sid, "done")
    return sid


@pytest.mark.parametrize("credentials", ["audit:wrong", "intrusö:wrong", "audit:secrét",
                                        "not-separated", "\u2603:wrong"])
def test_basic_invalid_ascii_and_unicode_has_401_challenge(monkeypatch, credentials):
    monkeypatch.setenv("SCOPESCAN_PANEL_USER", "audit")
    monkeypatch.setenv("SCOPESCAN_PANEL_PASSWORD", "secret")
    token = base64.b64encode(credentials.encode()).decode()
    response = client().get("/openapi.json", headers={"Authorization": "Basic " + token})
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith('Basic realm="ScopeScan"')


def test_configured_unicode_basic_credentials_work(monkeypatch):
    monkeypatch.setenv("SCOPESCAN_PANEL_USER", "auditoría")
    monkeypatch.setenv("SCOPESCAN_PANEL_PASSWORD", "contraseña\u2603")
    token = base64.b64encode("auditoría:contraseña\u2603".encode()).decode()
    assert client().get("/openapi.json", headers={"Authorization": "Basic " + token}).status_code == 200


def test_non_ascii_csrf_cookie_and_header_are_controlled_403():
    browser = client()
    browser.get("/scans/new")
    token = browser.cookies.get("scopescan_csrf")
    assert not web._valid_csrf("n.é")
    assert not web._valid_csrf("a" * 10000)
    response = browser.post("/api/preview", data={"targets": "10.0.0.1"},
                            headers=[(b"x-csrf-token", (token + "é").encode())])
    assert response.status_code == 403
    browser.cookies.clear()
    response = browser.post("/api/preview", data={"targets": "10.0.0.1"},
                            headers=[(b"cookie", b"scopescan_csrf=n.\xc3\xa9"),
                                     (b"x-csrf-token", token.encode())])
    assert response.status_code == 403


@pytest.mark.parametrize("metadata, expected", [
    ({"packages_checked": True, "package_total": 5001, "packages_truncated": True,
      "packages_unparsed": 1, "packages_complete": False},
     ["total declarado 5001", "Lectura comprobada", "recorte si",
      "registros sin interpretar 1", "cobertura incompleta"]),
    ({}, ["total declarado sin dato", "Lectura sin dato", "recorte sin dato",
          "registros sin interpretar sin dato", "inventario antiguo o sin metadatos"]),
    ({"packages_checked": True, "package_total": 1, "packages_truncated": False,
      "packages_unparsed": 0, "packages_complete": True},
     ["total declarado 1", "recorte no", "registros sin interpretar 0", "cobertura completa"]),
])
def test_package_coverage_detail_report_and_demand_page(nmap_xml, metadata, expected):
    sid = scan(nmap_xml)
    inv = {"platform": "linux", "os_name": "Linux", "kernel": "test", "firewall": {},
           "packages": [{"name": "example", "version": "1"}], **metadata}
    db.save_host_inventory(sid, "192.168.1.10", inv, "fixture")
    pages = [client().get(f"/scans/{sid}").text, report.render_report(sid),
             client().get(f"/scans/{sid}/inventory/192.168.1.10/packages").text]
    for page in pages:
        normalized = " ".join(page.split())
        assert "Reinicio pendiente sin dato" in normalized
        for fragment in expected:
            assert fragment in normalized


@pytest.mark.parametrize("distro, notifier, marker, expected", [
    ("alpine", False, False, ""), ("rhel", False, False, ""),
    ("debian", False, False, ""), ("ubuntu", False, False, ""),
    ("ubuntu", True, False, "no"), ("ubuntu", True, True, "yes"),
    ("debian", False, True, "yes"),
])
def test_actual_reboot_collector_branch(distro, notifier, marker, expected, tmp_path):
    bash = shutil.which("bash") if os.name != "nt" else None
    if os.name == "nt":
        candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
        bash = str(candidate) if candidate.exists() else None
    if bash is None:
        pytest.skip("POSIX shell unavailable")
    marker_path, notifier_path = tmp_path / "reboot-required", tmp_path / "notify.sh"
    if marker:
        marker_path.touch()
    if notifier:
        notifier_path.write_text("#!/bin/sh\nexit 0\n")
        notifier_path.chmod(0o755)
    assert linux_inventory.SCRIPT.endswith(linux_inventory.REBOOT_CHECK)
    branch = linux_inventory.REBOOT_CHECK.replace("/var/run/reboot-required", marker_path.as_posix())
    branch = branch.replace("/usr/share/update-notifier/notify-reboot-required", notifier_path.as_posix())
    # Execute the exact collector branch with isolated fixture paths; no package commands.
    script = (f"os_release={shlex.quote('ID=' + distro)}\n" +
              "emit() { printf '%s\\t%s\\n' \"$1\" \"$2\"; }\n"
              + branch)
    result = subprocess.run([bash, "--noprofile", "--norc"], input=script.encode(),
                            capture_output=True, check=True, timeout=5)
    records = dict(line.split("\t", 1) for line in result.stdout.decode().splitlines())
    assert records["REBOOT_REQUIRED"] == expected, (result.stderr.decode(), script)
    if not expected:
        controls = linux_controls({"reboot_required": None}, set())
        reboot = next(item for item in controls if item["control_id"] == "LINUX-REBOOT")
        assert reboot["status"] == "unknown"


def test_collector_sends_lf_bytes_even_from_windows(monkeypatch):

    records = {"OS_RELEASE": "ID=alpine", "KERNEL": "test-kernel"}
    encoded = "\n".join(key + "\t" + base64.b64encode(value.encode()).decode()
                        for key, value in records.items()).encode()

    def run(argv, **kwargs):
        import shlex

        from scopescan.process_runner import ProcessResult
        shell, option, script = shlex.split(argv[-1])
        assert (shell, option) == ("sh", "-c")
        assert script == linux_inventory.SCRIPT and "\r\n" not in script
        assert kwargs["timeout"] == 180 and kwargs["max_output_chars"] == 8_000_000
        return ProcessResult(0, encoded.decode(), "")

    from scopescan import process_runner
    monkeypatch.setattr(linux_inventory.shutil, "which", lambda _name: "fixture-ssh")
    monkeypatch.setattr(process_runner, "run_process", run)
    assert linux_inventory.collect("192.168.1.10")["reboot_required"] is None


def test_http_delete_rechecks_interleaved_claim_atomically(monkeypatch):
    sid = scan()
    queue = jobs.ScanQueue(1)
    original = queue.request_delete

    def interleave(scan_id):
        assert db.claim_enrichment_job(scan_id, "nvd")
        return original(scan_id)

    monkeypatch.setattr(queue, "request_delete", interleave)
    monkeypatch.setattr(web, "QUEUE", queue)
    try:
        response = client().post(f"/scans/{sid}/delete", follow_redirects=False)
        assert response.status_code == 409
        assert db.get_scan(sid) is not None
        assert db.enrichment_claim_active(sid, "nvd")
    finally:
        queue.shutdown(wait=True)


def test_true_concurrent_claim_delete_race_has_only_serializable_outcomes():
    for _ in range(12):
        sid = scan()
        barrier = threading.Barrier(2)

        def claim(sid=sid, barrier=barrier):
            barrier.wait(timeout=5)
            try:
                return db.claim_enrichment_job(sid, "nvd")
            except db.ScanUnavailable:
                return "unavailable"

        def delete(sid=sid, barrier=barrier):
            barrier.wait(timeout=5)
            try:
                db.delete_scan(sid)
                return "deleted"
            except db.ScanUnavailable:
                return "busy"

        with ThreadPoolExecutor(2) as pool:
            claimed, deleted = pool.submit(claim), pool.submit(delete)
            results = claimed.result(5), deleted.result(5)
        assert results in [(True, "busy"), ("unavailable", "deleted")]
        assert (db.get_scan(sid) is not None) == (results[0] is True)


def test_pending_delete_blocks_claim_before_worker_last_write(monkeypatch):
    sid = scan()
    db.set_status(sid, "queued")
    started, release = threading.Event(), threading.Event()
    writes = []

    def execute(scan_id, cancel):
        assert db.claim_scan_execution(scan_id)
        started.set()
        assert release.wait(5)
        assert cancel.is_set()
        assert db.get_scan(scan_id) is not None
        db.set_status(scan_id, "cancelled")
        writes.append("finished")

    monkeypatch.setattr(jobs.service, "execute", execute)
    queue = jobs.ScanQueue(1)
    try:
        queue.submit(sid)
        assert started.wait(5)
        assert queue.request_delete(sid)
        assert db.get_scan(sid)["deletion_pending"]
        with pytest.raises(db.ScanUnavailable):
            db.claim_enrichment_job(sid, "nvd")
        release.set()
        queue.shutdown(wait=True)
        assert writes == ["finished"]
        assert db.get_scan(sid) is None
    finally:
        release.set()
        queue.shutdown(wait=True)


def test_deleted_scan_cannot_launch_late_background_motor(monkeypatch):
    sid = scan()
    assert db.claim_enrichment_job(sid, "nvd")
    db.set_enrichment_status(sid, "nvd", "done")
    db.delete_scan(sid)
    calls = []
    web._submit_enrichment(sid, "nvd", lambda: calls.append("motor"))
    assert calls == []
    db.set_enrichment_status(sid, "nvd", "failed", "late callback")
    assert db.get_enrichment_statuses(sid) == {}
    with pytest.raises(db.ScanUnavailable):
        db.claim_enrichment_job(sid, "nvd")


MODULE = "exploit/windows/smb/ms17_010_eternalblue"


def mock_msf(sid, monkeypatch, tmp_path, *, returncode=0, **flags):
    db.save_msf_results(sid, [{"host": "192.168.1.10", "port": 445, "protocol": "tcp",
        "module": MODULE, "module_kind": "exploit", "action": "check",
        "result": msf_modules.VULNERABLE, "detail": "fixture"}])
    monkeypatch.setattr(msf, "msf_lhost", lambda: "192.168.1.50")
    monkeypatch.setattr(msf, "msf_lport", lambda: 4444)
    monkeypatch.setattr(msf, "raw_dir", lambda: tmp_path)
    monkeypatch.setattr(msf.msf_runner, "build_argv", lambda *args, **kw: ["fixture"])
    execution = msf.msf_runner.MsfExecution(
        argv=[], rc_path=tmp_path / "fixture.rc", returncode=returncode,
        stdout="[+] 192.168.1.10:445 - Meterpreter session 1 opened", stderr="", **flags)
    monkeypatch.setattr(msf.msf_runner, "run", lambda *args, **kw: execution)
    return execution


@pytest.mark.parametrize("flags,status,reason", [
    ({"timed_out": True}, "failed", "Tiempo maximo"),
    ({"output_truncated": True}, "failed", "Salida truncada"),
    ({"cancelled": True}, "cancelled", "Cancelado"),
    ({"returncode": 1}, "failed", "codigo 1"),
])
def test_exploit_incomplete_positive_output_never_becomes_success(nmap_xml, monkeypatch,
                                                                tmp_path, flags, status, reason):
    sid = scan(nmap_xml)
    execution = mock_msf(sid, monkeypatch, tmp_path, **flags)
    web._run_msf_exploit(sid, "192.168.1.10", 445, MODULE)
    run = db.get_exploit_runs(sid)[0]
    assert run["result"] == msf_modules.ERROR
    assert run["status"] == status
    assert reason in run["detail"]
    job = db.get_enrichment_statuses(sid)["metasploit-exploit"]
    assert job["status"] == status
    assert reason in job["error"]
    assert Path(run["log_path"]).read_text() == execution.output


def test_verify_all_incomplete_is_failed(nmap_xml, monkeypatch, tmp_path):
    sid = scan(nmap_xml)
    mock_msf(sid, monkeypatch, tmp_path, timed_out=True)
    with db.connect() as connection:
        connection.execute("DELETE FROM msf_results WHERE scan_id=?", (sid,))
    msf.verify_scan(sid)
    job = db.get_enrichment_statuses(sid)[msf.ENRICH_KIND]
    assert job["status"] == "failed"
    assert "Tiempo maximo" in job["error"]
    assert all(row["result"] == msf_modules.ERROR for row in db.get_msf_results(sid))


def test_verify_mixed_complete_incomplete_is_partial(nmap_xml, monkeypatch, tmp_path):
    sid = scan(nmap_xml)
    mock_msf(sid, monkeypatch, tmp_path)
    sequence = iter([
        msf.msf_runner.MsfExecution([], tmp_path / "ok.rc", 0, "[*] check complete", ""),
        msf.msf_runner.MsfExecution([], tmp_path / "bad.rc", 1, "[*] startup", "",
                                    timed_out=True),
    ])
    first = msf_modules.module_by_path("auxiliary/scanner/ssh/ssh_version")
    second = msf_modules.module_by_path("auxiliary/scanner/smb/smb_version")
    monkeypatch.setattr(msf, "plan_scan", lambda _sid: [
        ("192.168.1.10", 22, "ssh", first), ("192.168.1.10", 445, "smb", second)])
    monkeypatch.setattr(msf.msf_runner, "run", lambda *args, **kwargs: next(sequence))
    msf.verify_scan(sid)
    assert db.get_enrichment_statuses(sid)[msf.ENRICH_KIND]["status"] == "partial"


class NavigationParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title_markup = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
        elif self.in_title:
            self.title_markup.append(tag)
        if tag == "a":
            self.links.append(dict(attrs).get("href", ""))

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False


@pytest.mark.parametrize("route", ["/", "/findings?min_severity=0"])
def test_pagination_has_real_links_outside_html_title(nmap_xml, route):
    sid = scan(nmap_xml)
    if route == "/":
        for n in range(29):
            db.create_scan(name=f"page-test-{n}", targets="192.168.1.10", profile="rapido")
    else:
        from scopescan.models import Finding, Severity
        findings = [Finding(host="192.168.1.10", title=f"review-{n}", severity=Severity.LOW,
                            source="fixture") for n in range(305)]
        db.save_results(sid, nmap_parser.parse_string(nmap_xml), findings, 0)
    browser = client()
    page = browser.get(route)
    parser = NavigationParser()
    parser.feed(page.text)
    assert parser.title_markup == []
    next_link = next(link for link in parser.links if "page=2" in link)
    next_response = browser.get(page.url.join(next_link))
    assert next_response.status_code == 200
    assert "Pagina 2" in next_response.text
