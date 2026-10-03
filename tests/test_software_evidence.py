import hashlib
import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from scopescan import cli, db, sbom, software_service, software_store
from scopescan.grype_adapter import parse as parse_grype
from scopescan.scap_import import parse as parse_scap
from scopescan.web import app as web


def cdx(name="openssl", version="3.0", ref="openssl", purl=None):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "serialNumber": "urn:uuid:aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
            "metadata": {"timestamp": "2025-01-01T00:00:00Z", "tools": {"components": [{"type": "application", "name": "syft", "version": "1.54.0"}]}},
            "components": [{"type": "library", "bom-ref": ref, "name": name, "version": version,
                            "purl": purl or f"pkg:deb/debian/{name}@{version}?arch=amd64&distro=debian-12",
                            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                            "properties": [{"name": "distribution", "value": "debian-12"}]}]}


def spdx():
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "inventory",
            "documentNamespace": "https://example.org/sbom", "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: fixture"]},
            "packages": [{"SPDXID": "SPDXRef-openssl", "name": "openssl", "versionInfo": "3.0", "filesAnalyzed": False,
                          "downloadLocation": "NOASSERTION", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:deb/debian/openssl@3.0?arch=amd64&distro=debian-12"}],
                          "checksums": [{"algorithm": "SHA256", "checksumValue": "a" * 64}]}]}


def encode(value):
    return json.dumps(value).encode()


def store(value, name="image@sha256:123"):
    return software_service.import_evidence("sbom", encode(value), namespace="fixture", resource_kind="image", resource_name=name)


@pytest.mark.parametrize("factory", [cdx, spdx])
def test_sbom_roundtrip_producers_hashes_namespace_original_date(factory):
    payload = encode(factory())
    document_id = store(factory())
    row = software_store.get(document_id, raw=True)
    assert row["observed_at"] == "2025-01-01T00:00:00+00:00"
    assert row["received_sha256"] == hashlib.sha256(payload).hexdigest()
    assert row["provenance"]["imported"] and not row["provenance"]["confirmed"]
    assert row["normalized"]["components"][0]["hashes"]
    assert row["normalized"]["producers"] and row["normalized"]["document_namespace"]
    for target in ("cyclonedx", "spdx"):
        exported = software_service.export_document(document_id, target)
        again = sbom.parse(exported)
        assert again["observed_at"] == row["normalized"]["observed_at"]
        assert again["components"][0]["purl"] == row["normalized"]["components"][0]["purl"]
        assert "debian-12" in exported.decode() and "2025-01-01" in exported.decode()
    assert not db.list_scans() and not db.list_assets()[0]


def test_component_identity_stays_across_versions_source_refs_and_order():
    first = store(cdx(version="3.0", ref="producer-one"))
    second = store(cdx(version="3.1", ref="producer-two"))
    one, _ = software_store.page("components", document_id=first)
    two, _ = software_store.page("components", document_id=second)
    assert one[0]["id"] == two[0]["id"] and one[0]["version"] != two[0]["version"]
    arm = store(cdx(purl="pkg:deb/debian/openssl@3.0?arch=arm64&distro=debian-12"))
    three, _ = software_store.page("components", document_id=arm)
    assert one[0]["id"] != three[0]["id"]
    assert software_store.page("documents", resource_id=software_store.get(first)["resource_id"])[1] == 3


def test_duplicate_package_occurrences_keep_refs_and_common_stable_identity():
    value = cdx()
    value["components"].append(dict(value["components"][0], **{"bom-ref": "second-occurrence"}))
    document_id = store(value)
    rows, total = software_store.page("components", document_id=document_id)
    assert total == 2 and rows[0]["id"] == rows[1]["id"] and rows[0]["ref"] != rows[1]["ref"]


@pytest.mark.parametrize("versions", [("1.0","1.1"),("1.0","1.0")], ids=["two-versions","two-locations"])
def test_grype_occurrences_preserve_every_component_match(versions):
    matches = []
    for index,version in enumerate(versions):
        matches.append({"artifact":{"id":str(index),"name":"openssl","version":version,"type":"deb",
            "purl":f"pkg:deb/debian/openssl@{version}?arch=amd64", "locations":[{"path":f"/root-{index}/var/lib/dpkg/status"}]},
            "vulnerability":{"id":"CVE-2020-0001","namespace":"debian:12","severity":"High","fix":{"state":"fixed","versions":["2.0"]}},
            "matchDetails":[{"type":"exact-direct-match"}]})
    payload = {"matches":matches,"source":{"type":"image","target":{"userInput":"fixture"}},
        "distro":{"name":"debian","version":"12"},"descriptor":{"name":"grype","version":"0.119.0","db":{"built":datetime.now(UTC).isoformat(),"schemaVersion":"6","valid":True}}}
    document_id = software_service.import_evidence("grype",encode(payload),namespace="fixture",resource_kind="image",resource_name="occurrences")
    components, total_components = software_store.page("components",document_id=document_id)
    observations, total_observations = software_store.page("observations",document_id=document_id)
    normalized = software_store.get(document_id)["normalized"]
    assert total_components == total_observations == 2
    assert len(normalized["observations"]) == len(normalized["components"]) == 2
    assert components[0]["id"] == components[1]["id"]  # stable logical component
    assert observations[0]["id"] != observations[1]["id"]
    assert {row["component_ref"] for row in observations} == {row["ref"] for row in components}
    assert {row["version"] for row in components} == set(versions)


def test_store_preserves_identical_observation_occurrences_without_collision():
    normalized = sbom.parse(encode(cdx()))
    observation = {"component_ref":"openssl","rule_id":"CVE-2020-0001","outcome":"candidate","severity":"high"}
    normalized["observations"] = [dict(observation),dict(observation)]
    document_id = software_store.persist(normalized,namespace="fixture",resource_kind="image",resource_name="duplicate-producer-match")
    rows,total = software_store.page("observations",document_id=document_id)
    assert total == 2 and rows[0]["id"] != rows[1]["id"]


@pytest.mark.parametrize("payload", [b"[]", b'{"bomFormat":"CycloneDX","bomFormat":"SPDX"}', b'{"x":NaN}', b"{" + b" " * 8_000_001, b'{"bomFormat":"CycloneDX","specVersion":"1.5"}', b'{"spdxVersion":"SPDX-3.0"}'], ids=["array", "duplicate-key", "nonfinite", "oversize", "old-cdx", "new-spdx"])
def test_invalid_sbom_is_rejected_before_db_mutation(payload):
    with pytest.raises(ValueError):
        software_service.import_evidence("sbom", payload, namespace="fixture", resource_kind="software", resource_name="app")
    assert software_store.page("documents")[1] == 0


def test_uri_redaction_applies_raw_normalized_exports_and_original_hash():
    value = cdx()
    value["components"][0]["externalReferences"] = [{"type": "distribution", "url": "https://alice:supersecret@registry.example/path"}]
    payload = encode(value)
    document_id = store(value)
    row = software_store.get(document_id, raw=True)
    assert row["received_sha256"] == hashlib.sha256(payload).hexdigest()
    assert row["normalized"]["redactions"]
    for output in (row["raw"], encode(row["normalized"]), software_service.export_document(document_id, "spdx")):
        assert b"supersecret" not in output and b"alice:" not in output


def xccdf(state="fail"):
    return f'''<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="baseline"><version>2025.01</version><Rule id="rule-ssh" severity="medium"><title>SSH policy</title><description>Expected approved option</description><reference href="https://example.org/policy">Policy</reference><check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"><check-content-ref href="oval.xml" name="oval:fixture:def:1"/></check></Rule><TestResult id="result" end-time="2025-01-01T00:00:00Z"><profile idref="profile-cis"/><target>host.example</target><rule-result idref="rule-ssh" time="2025-01-01T00:00:00Z"><result>{state}</result><message severity="info">Reported evidence</message></rule-result></TestResult></Benchmark>'''.encode()


@pytest.mark.parametrize("state", ["pass", "fail", "error", "unknown", "notapplicable", "notchecked", "informational", "fixed"])
def test_scap_preserves_status_controls_criteria_without_certification(state):
    value = parse_scap(xccdf(state))
    assert value["observations"][0]["outcome"] == state
    assert value["observations"][0]["criteria"][0]["references"][0]["name"] == "oval:fixture:def:1"
    assert value["benchmark_id"] == "baseline" and value["benchmark_version"] == "2025.01"
    assert value["profile"] == "profile-cis" and value["observed_at"].startswith("2025-01-01")
    assert value["coverage"] == "reported_rules_only" and not value["certification"]
    document_id = software_service.import_evidence("scap", xccdf(state), namespace="fixture", resource_kind="host-compliance", resource_name="host.example")
    assert software_store.page("observations", document_id=document_id)[1] == 1
    assert not db.list_current_findings()[0]


def test_arf_report_and_xml_safety_ambiguity():
    arf = b'<asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"><reports><report><content>' + xccdf() + b"</content></report></reports></asset-report-collection>"
    assert parse_scap(arf)["benchmark_id"] == "baseline"
    for payload in (b'<!DOCTYPE a [<!ENTITY x "boom">]><TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">&x;</TestResult>', xccdf().replace(b"<target>host.example</target>", b"<target>one</target><target>two</target>"), arf.replace(b"</content>", xccdf() + b"</content>")):
        with pytest.raises(ValueError):
            parse_scap(payload)


def grype():
    return {"matches": [{"artifact": {"id": "artifact-one", "name": "openssl", "version": "3.0", "purl": "pkg:deb/debian/openssl@3.0?arch=amd64&distro=debian-12"},
                         "vulnerability": {"id": "CVE-2025-0001", "namespace": "debian:12", "severity": "High", "fix": {"versions": ["3.1"], "state": "fixed"}}, "matchDetails": [{"type": "exact-direct-match", "matcher": "dpkg-matcher"}], "relatedVulnerabilities": []}],
            "distro": {"name": "debian", "version": "12"}, "source": {"type": "sbom"},
            "descriptor": {"name": "grype", "version": "0.119.0", "db": {"built": datetime.now(UTC).isoformat(), "schemaVersion": "6", "checksum": "xxh64:123", "valid": True}}}


def test_grype_candidates_database_context_and_duplicate_matches():
    value = grype()
    value["matches"].append(value["matches"][0])
    parsed = parse_grype(encode(value))
    assert len(parsed["observations"]) == 1
    assert parsed["observations"][0]["outcome"] == "candidate" and not parsed["observations"][0]["confirmed"]
    assert len(parsed["observations"][0]["match_details"]) == 2
    assert parsed["distro"]["name"] == "debian" and not parsed["database_stale"]
    assert parsed["observed_at"] is None
    value["descriptor"]["db"]["built"] = "2025-01-01T00:00:00Z"
    assert parse_grype(encode(value))["status"] == "partial"
    value["descriptor"]["db"] = {}
    with pytest.raises(ValueError, match="empty"):
        parse_grype(encode(value))


def test_worker_queue_payload_authorization_and_resource_binding():
    from scopescan import durable_jobs
    document_id = store(cdx())
    row = software_store.get(document_id)
    payload = {"namespace": row["namespace"], "resource_name": row["name"], "resource_kind": row["resource_kind"], "document_id": document_id}
    job_id = software_service.enqueue("software.grype", payload, authorized_by="operator")
    assert durable_jobs.get(job_id)["status"] == "queued"
    with pytest.raises(ValueError, match="match"):
        software_service.enqueue("software.grype", dict(payload, resource_name="different-image"), authorized_by="operator")
    with pytest.raises(ValueError, match="network"):
        software_service.enqueue("software.syft", dict(payload, source="registry:example.org/image:1"), authorized_by="operator")


def test_durable_worker_dispatch_persists_result_once_with_fenced_owner(monkeypatch):
    from scopescan import durable_jobs, worker
    from scopescan.syft_adapter import SyftAdapter
    value = sbom.parse(encode(cdx()))
    value["engine_version"] = "1.54.0"
    monkeypatch.setattr(SyftAdapter, "execute", lambda *_, **__: value)
    payload = {"namespace": "fixture", "resource_name": "image", "resource_kind": "image", "source": "registry:example.org/image:1", "allow_registry": True}
    job_id = software_service.enqueue("software.syft", payload, authorized_by="operator")
    worker.run_once(job_id=job_id)
    row = durable_jobs.get(job_id)
    assert row["status"] == "done" and json.loads(row["result"])["document_id"] > 0
    assert software_store.page("documents")[1] == 1
    assert worker.run_once(job_id=job_id) is None
    assert software_store.page("documents")[1] == 1


def test_imported_scap_pass_preserves_existing_network_finding():
    from scopescan.models import Finding, Host, NmapRun, Port, Service, Severity
    scan_id = db.create_scan(name="prior local", targets="192.0.2.1", profile="tcp")
    db.set_status(scan_id, "running")
    run = NmapRun(hosts=[Host("192.0.2.1", state="up", ports=[Port(22, state="open", service=Service("ssh"))])], exit_status="success")
    finding = Finding("Local proof", Severity.HIGH, "nse:fixture", "192.0.2.1", port=22, protocol="tcp", confirmed=True, rule_id="fixture")
    db.save_results(scan_id, run, [finding], 50)
    db.set_status(scan_id, "done")
    before, _ = db.list_current_findings()
    assert before
    software_service.import_evidence("scap", xccdf("pass"), namespace="fixture", resource_kind="host-compliance", resource_name="192.0.2.1")
    after, _ = db.list_current_findings()
    assert [(row["id"], row["lifecycle"]) for row in after] == [(row["id"], row["lifecycle"]) for row in before]


def test_unknown_date_remains_unknown_after_cross_format_export():
    value = cdx()
    value.pop("metadata")
    normalized = sbom.parse(encode(value))
    for target in ("spdx", "cyclonedx"):
        assert sbom.parse(sbom.export(normalized, target))["observed_at"] is None


def test_read_snapshot_and_literal_search():
    document_id = store(cdx(name="openssl%"), name="literal%image")
    with db.read_snapshot():
        assert software_store.get(document_id)["id"] == document_id
        assert software_store.page("documents", search="%image")[1] == 1
    assert software_store.page("documents", search="%notwildcard")[1] == 0


def test_cli_import_list_detail_and_preview(tmp_path, capsys):
    path = tmp_path / "sbom.json"
    path.write_bytes(encode(cdx()))
    assert cli.main(["software", "import", "sbom", str(path), "--namespace", "fixture", "--resource", "image", "--resource-kind", "image"]) == 0
    document_id = json.loads(capsys.readouterr().out)["document_id"]
    assert cli.main(["software", "list"]) == 0
    assert json.loads(capsys.readouterr().out)["total"] == 1
    assert cli.main(["software", "preview", "grype", "--document-id", str(document_id), "--namespace", "fixture", "--resource", "image", "--resource-kind", "image", "--authorized-by", "operator"]) == 0
    assert json.loads(capsys.readouterr().out)["execution"] == "separate-worker"


def test_web_upload_csrf_escape_download_history_and_durable_queue(monkeypatch):
    monkeypatch.setattr(web.QUEUE, "shutdown", lambda **_: None)
    with TestClient(web.app, base_url="http://localhost", client=("127.0.0.1", 51000)) as client:
        assert client.get("/software").status_code == 200
        uri = "/api/software/import/sbom?namespace=fixture&resource=image&resource_kind=image"
        assert client.post(uri, content=encode(cdx())).status_code == 403
        client.headers["X-CSRF-Token"] = client.cookies["scopescan_csrf"]
        response = client.post(uri, content=encode(cdx(name="<script>x</script>")))
        assert response.status_code == 200, response.text
        document_id = response.json()["document_id"]
        detail = client.get(f"/software/{document_id}")
        assert detail.status_code == 200 and "<script>x</script>" not in detail.text and "&lt;script&gt;" in detail.text
        assert client.get(f"/api/software/{document_id}/raw").status_code == 200
        assert client.get(f"/api/software/{document_id}/export/spdx").json()["spdxVersion"] == "SPDX-2.3"
        resource_id = software_store.get(document_id)["resource_id"]
        store(cdx(), name="other")
        assert client.get("/api/software/documents", params={"resource_id": resource_id}).json()["total"] == 1
        assert "1 documentos" in client.get("/software", params={"resource_id": resource_id}).text
        queued = client.post("/software/queue", data={"engine": "grype", "namespace": "fixture", "resource": "image", "resource_kind": "image", "document_id": document_id, "authorized_by": "operator", "reviewed": "true"}, follow_redirects=False)
        assert queued.status_code == 303 and queued.headers["location"].startswith("/jobs/")
