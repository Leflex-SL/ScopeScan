"""Native versions, shared feed budgets and honest stale/coverage provenance."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError

import pytest

from scopescan import db, linux_advisories, linux_inventory, msrc, nvd
from scopescan.feed_budget import FeedInterrupted, SharedFeedBudget, claim_refresh, release_refresh
from scopescan.package_versions import compare_versions, debian_compare, rpm_compare

CPE = "cpe:2.3:a:test:service:1.0:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    "a,b",
    [
        ("1.0~rc1", "1.0"),
        ("1.0-1", "1.0-2"),
        ("1.0-1+deb12u1", "1.0-1+deb12u2"),
        ("1.0", "1:0.1"),
        ("1.0a", "1.0+"),
        ("1.09", "1.10"),
        ("1.0~~", "1.0~"),
    ],
)
def test_debian_native_order(a, b):
    assert debian_compare(a, b) == -1
    assert debian_compare(b, a) == 1


@pytest.mark.parametrize(
    "a,b",
    [
        ("1.0~rc1-1", "1.0-1"),
        ("1.0-1", "1.0-2"),
        ("1.0-99", "1:0.1-1"),
        ("1.0", "1.0^git1"),
        ("1.0^git1", "1.0.1"),
        ("1.0a", "1.0.1"),
        ("1.009-1", "1.10-1"),
    ],
)
def test_rpm_native_order(a, b):
    assert rpm_compare(a, b) == -1
    assert rpm_compare(b, a) == 1


def test_zero_segments_and_unsupported():
    assert debian_compare("1.01-0", "1.1") == 0
    assert rpm_compare("1+0", "1.0") == 0
    assert compare_versions("1.0-r1", "1.0-r2", "apk") is None
    assert compare_versions("bad version", "1.0", "dpkg") is None


def test_rpm_inventory_complete_evr_arch_vendor():
    row = linux_inventory._packages("openssl\t1:3.0.7-28.el9_4\tx86_64\tRed Hat, Inc.", "rpm")[0]
    assert row["version"] == "1:3.0.7-28.el9_4"
    assert row["arch"] == "x86_64"
    assert row["repository_class"] == "unknown"
    assert "%{EPOCHNUM}" in linux_inventory.SCRIPT and "%{ARCH}" in linux_inventory.SCRIPT


def feed():
    return linux_advisories.parse_advisories(
        json.dumps(
            {
                "schema": linux_advisories.SCHEMA,
                "provider": "Debian",
                "distro": "debian",
                "release": "12",
                "feed_version": "2026-10-03",
                "observed_at": "2026-10-03T00:00:00Z",
                "advisories": [
                    {
                        "id": "DSA-example",
                        "package": "openssl",
                        "fixed_version": "3.0.11-1+deb12u2",
                        "repository": "bookworm-security",
                        "cves": ["CVE-2024-12345"],
                        "arch": "amd64",
                    }
                ],
            }
        ).encode()
    )


def test_backport_fixed_requires_proven_repository():
    inv = {
        "os_id": "debian",
        "os_version": "12",
        "package_manager": "dpkg",
        "packages": [{"name": "openssl", "version": "3.0.11-1+deb12u2", "arch": "amd64"}],
    }
    assert linux_advisories.assess_inventory(inv, feed())["results"][0]["state"] == "not_assessed"
    inv["packages"][0].update(repository_class="distribution", repository="bookworm-security")
    assert linux_advisories.assess_inventory(inv, feed())["results"][0]["state"] == "fixed"
    inv["packages"][0]["version"] = "3.0.11-1+deb12u1"
    assert linux_advisories.assess_inventory(inv, feed())["results"][0]["state"] == "candidate"
    inv["os_version"] = "11"
    assert linux_advisories.assess_inventory(inv, feed())["results"][0]["state"] == "not_assessed"


def test_budget_two_clients_share_reservations():
    clock = lambda: 1000.0
    first, second = SharedFeedBudget(clock=clock), SharedFeedBudget(clock=clock)
    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(lambda i: (first if i % 2 else second).reserve(), range(5)))
    with pytest.raises(FeedInterrupted):
        second.reserve(deadline=time.monotonic() + 0.02)
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM feed_requests").fetchone()[0] == 5


def test_cancel_budget_wait_immediate():
    budget = SharedFeedBudget()
    budget.defer(120)
    with pytest.raises(FeedInterrupted, match="cancelada"):
        budget.reserve(cancel=lambda: True)


def test_refresh_claim_owner_cannot_release_another():
    owner = claim_refresh("a")
    assert claim_refresh("a") is None
    release_refresh("a", "other")
    assert claim_refresh("a") is None
    release_refresh("a", owner)
    assert claim_refresh("a")


def test_nvd_cvss_version_primary_and_all_providers():
    item = {
        "cve": {
            "id": "CVE-2024-12345",
            "affected": [{}],
            "metrics": {
                "cvssMetricV40": [
                    {"source": "secondary", "type": "Secondary", "cvssData": {"baseScore": 9.5}},
                    {"source": "CNA", "type": "Primary", "cvssData": {"baseScore": 7.3}},
                ],
                "cvssMetricV31": [
                    {"source": "NVD", "type": "Primary", "cvssData": {"baseScore": 8.0}}
                ],
            },
        }
    }
    result = nvd._extract(item, CPE)
    assert (result["cvss"], result["cvss_source"], result["cvss_version"]) == (7.3, "CNA", "4.0")
    assert len(result["cvss_metrics"]) == 3
    assert result["match_type"] == "unresolved"


@pytest.mark.parametrize("score", [True, float("nan"), float("inf"), -1, 11, "9.8"])
def test_nonfinite_cvss_not_selected(score):
    result = nvd._extract(
        {
            "cve": {
                "id": "CVE-2024-12345",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
            }
        },
        CPE,
    )
    assert result["cvss"] is None


def test_two_nvd_clients_dedupe_inflight_refresh(monkeypatch):
    clients = [nvd.NvdClient(), nvd.NvdClient()]
    calls = []

    def page(cpe, start):
        calls.append(start)
        time.sleep(0.1)
        return {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024-12345"}}]}

    for client in clients:
        monkeypatch.setattr(client, "_page", page)
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(lambda c: c.candidates(CPE), clients))
    assert calls == [0]
    assert all(x[0]["feed_stale"] is False for x in result)


def test_stale_failure_preserves_date_and_marks_error(monkeypatch):
    old = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    db.put_nvd_cache(CPE, [{"cve_id": "CVE-2024-12345", "match_type": "exact"}])
    with db.connect() as conn:
        conn.execute("UPDATE nvd_cache SET fetched_at=?", (old,))
    client = nvd.NvdClient()

    def fail(*args):
        raise nvd.NvdError("HTTP 503")

    monkeypatch.setattr(client, "_page", fail)
    result = client.candidates(CPE)[0]
    assert result["feed_stale"] and result["feed_error"] == "HTTP 503"
    assert result["feed_fetched_at"] == old
    assert db.get_nvd_cache(CPE)["fetched_at"] == old


def test_nvd_cancel_never_returns_stale(monkeypatch):
    client = nvd.NvdClient(cancel=lambda: True)
    with pytest.raises(nvd.NvdError, match="cancelada"):
        client.candidates(CPE)


def test_nvd_retry_after_shared_backoff():
    calls = []

    class Budget:
        def reserve(self, **kw):
            pass

        def defer(self, seconds):
            calls.append(seconds)

    def transport(*args, **kw):
        raise HTTPError(nvd.API_URL, 429, "rate limit", {"Retry-After": "11"}, None)

    with pytest.raises(nvd.NvdError, match="HTTP 429"):
        nvd.NvdClient(budget=Budget(), transport=transport).candidates(CPE)
    assert calls == [11.0, 11.0, 11.0]


def test_final_retry_after_updates_shared_backoff_even_when_job_fails():
    calls=[]
    delays=iter(('0','0','3600'))
    class Budget:
        def reserve(self,**kwargs):
            pass
        def defer(self,seconds):
            calls.append(seconds)
    def transport(*args,**kwargs):
        raise HTTPError(nvd.API_URL,429,'rate limit',{'Retry-After':next(delays)},None)
    with pytest.raises(nvd.NvdError,match='HTTP 429'):
        nvd.NvdClient(budget=Budget(),transport=transport).candidates(CPE)
    assert calls==[0,0,3600]


@pytest.mark.parametrize('total',[None,True,'0',[],{},-1,10001])
def test_malformed_total_never_clears_or_refreshes_stale_cache(monkeypatch,total):
    old=(datetime.now(UTC)-timedelta(days=8)).isoformat()
    db.put_nvd_cache(CPE,[{'cve_id':'CVE-2024-12345','match_type':'exact'}])
    with db.connect() as conn:
        conn.execute('UPDATE nvd_cache SET fetched_at=?',(old,))
    client=nvd.NvdClient()
    monkeypatch.setattr(client,'_page',lambda *args:{'totalResults':total,'vulnerabilities':[]})
    values=client.candidates(CPE)
    assert values[0]['feed_stale'] and values[0]['feed_error']
    assert db.get_nvd_cache(CPE)['fetched_at']==old
    assert json.loads(db.get_nvd_cache(CPE)['candidates'])[0]['cve_id']=='CVE-2024-12345'


def test_missing_total_never_creates_a_fresh_empty_cache(monkeypatch):
    client=nvd.NvdClient()
    monkeypatch.setattr(client,'_page',lambda *args:{'vulnerabilities':[]})
    with pytest.raises(nvd.NvdError,match='total'):
        client.candidates(CPE)
    assert db.get_nvd_cache(CPE) is None


@pytest.mark.parametrize('field,value',[('startIndex',True),('startIndex',1),('resultsPerPage',True),('resultsPerPage',-1),('resultsPerPage',2001)])
def test_malformed_page_metadata_never_creates_fresh_cache(monkeypatch,field,value):
    client=nvd.NvdClient()
    monkeypatch.setattr(client,'_page',lambda *args:{'totalResults':0,'vulnerabilities':[],field:value})
    with pytest.raises(nvd.NvdError):
        client.candidates(CPE)
    assert db.get_nvd_cache(CPE) is None


def test_msrc_invalid_scores_ignored():
    assert not msrc._valid_score(float("nan"))
    assert not msrc._valid_score(True)
    assert not msrc._valid_score("garbage")


def test_retry_after_long_pause_preserved_but_job_deadline_bounds_wait():
    budget = SharedFeedBudget()
    before = time.time()
    budget.defer(3600)
    with db.connect() as conn:
        assert conn.execute("SELECT until FROM feed_backoff").fetchone()[0] >= before + 3600
    started = time.monotonic()
    with pytest.raises(FeedInterrupted):
        budget.reserve(deadline=started + 0.02)
    assert time.monotonic() - started < 1.0


def test_nvd_failed_refresh_deduplication_does_not_extend_cooldown(monkeypatch):
    from scopescan.feed_budget import last_refresh

    calls = []

    def fail(*args):
        calls.append(1)
        raise nvd.NvdError("HTTP 503")

    clients = [nvd.NvdClient(), nvd.NvdClient()]
    for client in clients:
        monkeypatch.setattr(client, "_page", fail)
        with pytest.raises(nvd.NvdError):
            client.candidates(CPE)
        if client is clients[0]:
            attempted = last_refresh("nvd:" + CPE)["attempted_at"]
    assert calls == [1]
    assert last_refresh("nvd:" + CPE)["attempted_at"] == attempted


@pytest.mark.parametrize(
    "value",
    [
        {"metrics": []},
        {"descriptions": [None]},
        {"configurations": [{"cpeMatch": [{"criteria": [], "vulnerable": True}]}]},
    ],
)
def test_malformed_nvd_fields_fail_without_typeerror(value):
    with pytest.raises(nvd.NvdError):
        nvd._extract({"cve": {"id": "CVE-2024-12345", **value}}, CPE)


def test_stale_enrichment_status_partial_and_cpe_dedup(monkeypatch, nmap_xml):
    from scopescan.nmap_parser import parse_string

    run = parse_string(nmap_xml)
    scan_id = db.create_scan(name="feed", targets="192.168.1.10", profile="rapido")
    db.save_results(scan_id, run, [], 0)
    calls = []

    class Client:
        def __init__(self):
            self.last_status = {CPE: {"feed_stale": True, "feed_error": "HTTP 503"}}

        def candidates(self, cpe):
            calls.append(cpe)
            return []

    monkeypatch.setattr(nvd, "normalize_cpe", lambda _: CPE)
    original_replace = db.replace_cve_candidates

    def assert_partial_before_replace(scan_id, rows):
        assert db.get_enrichment_statuses(scan_id)["nvd"]["status"] == "partial"
        return original_replace(scan_id, rows)

    monkeypatch.setattr(db, "replace_cve_candidates", assert_partial_before_replace)
    nvd.enrich_scan(scan_id, client=Client(), intel_enricher=lambda rows: (rows, []))
    assert calls == [CPE]
    assert db.get_enrichment_statuses(scan_id)["nvd"]["status"] == "partial"


def test_nvd_per_cpe_failure_keeps_success_and_cancel_aborts(nmap_xml, monkeypatch):
    from scopescan.nmap_parser import parse_string

    run = parse_string(nmap_xml)
    scan_id = db.create_scan(name="partial", targets="192.168.1.10", profile="rapido")
    port = run.hosts[0].ports[0]
    port.service.cpes = ["cpe:/a:test:service:1.0", "cpe:/a:test:other:1.0"]
    db.save_results(scan_id, run, [], 0)

    class Client:
        def candidates(self, cpe):
            if ":other:" in cpe:
                raise nvd.NvdError("HTTP 503")
            return [
                {
                    "cve_id": "CVE-2024-12345",
                    "cvss": 7.5,
                    "summary": "fixture",
                    "match_type": "exact",
                }
            ]

    assert nvd.enrich_scan(scan_id, client=Client(), intel_enricher=lambda rows: (rows, [])) == 1
    assert db.get_cve_candidates(scan_id)[0]["cve_id"] == "CVE-2024-12345"
    assert db.get_enrichment_statuses(scan_id)["nvd"]["status"] == "partial"

    class Cancelled:
        def candidates(self, cpe):
            raise nvd.NvdCancelled("cancelada")

    monkeypatch.setattr(
        db, "replace_cve_candidates", lambda *args: pytest.fail("Cancelled result persisted")
    )
    with pytest.raises(nvd.NvdCancelled):
        nvd.enrich_scan(scan_id, client=Cancelled(), intel_enricher=lambda rows: (rows, []))
