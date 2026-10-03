"""Documented Vuls fixtures and distribution backport evidence integrate C01."""

import hashlib
import json
import threading
from datetime import UTC, datetime

import pytest

from scopescan import engine_store, linux_advisories, vuls_import
from scopescan.engine_contracts import Endpoint, ScanScope


def scope():
    return ScanScope("scope:linux", "operator", (Endpoint("192.0.2.4", None, "host"),))


def report():
    return {
        "jsonVersion": 4,
        "family": "debian",
        "release": "12",
        "scannedAt": datetime.now(UTC).isoformat(),
        "scannedVersion": "0.41.0",
        "ipv4Addrs": ["192.0.2.4"],
        "serverName": "not-a-dns-query.example",
        "config": {"scan": {"password": "DO_NOT_PERSIST", "token": "secret-token"}},
        "errors": [],
        "warnings": [],
        "packages": {
            "openssl": {
                "name": "openssl",
                "version": "3.0.11-1+deb12u1",
                "release": "",
                "arch": "amd64",
                "repository": "bookworm-security",
                "repositoryClass": "official",
            }
        },
        "scannedCves": {
            "CVE-2024-12345": {
                "cveID": "CVE-2024-12345",
                "affectedPackages": [
                    {
                        "name": "openssl",
                        "fixedIn": "3.0.11-1+deb12u2",
                        "notFixedYet": False,
                        "fixState": "affected",
                    }
                ],
                "cveContents": {"debian": []},
            }
        },
    }


def test_vuls_actual_model_candidate_and_redaction():
    payload = json.dumps(report()).encode()
    adapter = vuls_import.VulsImportAdapter(payload, host="192.0.2.4")
    plan = adapter.plan(scope())
    result = adapter.execute(plan)
    engine_store.validate(plan, result)
    assert result.provenance.engine_version == "0.41.0"
    assert result.provenance.imported
    assert result.observations[0].finding.confirmed is False
    assert "3.0.11-1+deb12u1" in result.observations[0].evidence
    assert b"DO_NOT_PERSIST" not in result.raw and b"secret-token" not in result.raw
    assert json.loads(result.raw)["source_sha256"] == hashlib.sha256(payload).hexdigest()


def test_vuls_absent_cves_never_negative():
    data = report()
    data["scannedCves"] = {}
    result = vuls_import.parse_vuls(json.dumps(data).encode(), host="192.0.2.4", scope=scope())
    assert not result.observations


def test_vuls_foreign_ip_no_dns_binding():
    data = report()
    data["ipv4Addrs"] = ["192.0.2.9"]
    with pytest.raises(ValueError, match="direcciones"):
        vuls_import.parse_vuls(json.dumps(data).encode(), host="192.0.2.4", scope=scope())


def test_vuls_errors_partial_and_secret_error_text_omitted():
    data = report()
    data["errors"] = ["authentication: SECRET_PASSWORD"]
    result = vuls_import.parse_vuls(json.dumps(data).encode(), host="192.0.2.4", scope=scope())
    assert result.status == "partial" and b"SECRET_PASSWORD" not in result.raw


@pytest.mark.parametrize(
    "key,value",
    [
        ("packages", []),
        ("scannedCves", []),
        ("jsonVersion", True),
        ("container", []),
        ("errors", {}),
        ("scannedAt", "2100-01-01T00:00:00Z"),
    ],
)
def test_vuls_malformed_contract_rejected(key, value):
    data = report()
    data[key] = value
    with pytest.raises(ValueError):
        vuls_import.parse_vuls(json.dumps(data).encode(), host="192.0.2.4", scope=scope())


def test_vuls_cancelled_never_evidence():
    adapter = vuls_import.VulsImportAdapter(json.dumps(report()).encode(), host="192.0.2.4")
    plan = adapter.plan(scope())
    cancel = threading.Event()
    cancel.set()
    assert adapter.execute(plan, cancel=cancel).status == "cancelled"


def test_linux_adapter_native_backport_and_observation_time():
    timestamp = datetime.now(UTC).isoformat()
    feed = {
        "schema": linux_advisories.SCHEMA,
        "provider": "Debian",
        "distro": "debian",
        "release": "12",
        "feed_version": "fixture-2026",
        "observed_at": timestamp,
        "advisories": [
            {
                "id": "DSA-fixture",
                "package": "openssl",
                "fixed_version": "3.0.11-1+deb12u2",
                "repository": "bookworm-security",
                "cves": ["CVE-2024-12345"],
            }
        ],
    }
    inventory = {
        "observed_at": timestamp,
        "os_id": "debian",
        "os_version": "12",
        "package_manager": "dpkg",
        "packages": [
            {
                "name": "openssl",
                "version": "3.0.11-1+deb12u2",
                "repository": "bookworm-security",
                "repository_class": "distribution",
            }
        ],
    }
    adapter = linux_advisories.LinuxAdvisoryAdapter(
        inventory, json.dumps(feed).encode(), host="192.0.2.4"
    )
    plan = adapter.plan(scope())
    result = adapter.execute(plan)
    engine_store.validate(plan, result)
    assert result.observations[0].outcome == "negative"
    assert result.observations[0].observed_at == timestamp
    assert result.provenance.feeds == (("Debian", "fixture-2026"),)


def test_linux_source_version_is_not_binary_version():
    from test_precision_feeds import feed

    inventory = {
        "os_id": "debian",
        "os_version": "12",
        "package_manager": "dpkg",
        "packages": [
            {
                "name": "libssl3",
                "source_name": "openssl",
                "version": "9.0-binary-only",
                "source_version": "3.0.11-1+deb12u1",
                "arch": "amd64",
            }
        ],
    }
    row = linux_advisories.assess_inventory(inventory, feed())["results"][0]
    assert row["installed_version"] == "3.0.11-1+deb12u1" and row["state"] == "candidate"
