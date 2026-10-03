"""Las coincidencias CPE y el inventario se prueban sin consultar la red."""

from __future__ import annotations

import base64
import sqlite3

import pytest

from medscan import (
    compliance,
    db,
    exploitdb,
    linux_inventory,
    msrc,
    nvd,
    threat_intel,
    windows_inventory,
)
from medscan.authenticated_checks import linux_findings, windows_findings
from medscan.models import Assessment, Port, Service, Severity
from medscan.nmap_parser import parse_string
from medscan.rules import evaluate_port


def test_cpe_simple_se_normaliza_sin_adivinar_version():
    assert nvd.normalize_cpe("cpe:/a:openbsd:openssh:6.6.1p1") == (
        "cpe:2.3:a:openbsd:openssh:6.6.1p1:*:*:*:*:*:*:*"
    )
    assert nvd.normalize_cpe("cpe:/o:microsoft:windows") is None
    assert nvd.normalize_cpe("cpe:/a:openbsd:openssh:*bad") is None


def test_nvd_cache_reutiliza_consulta(monkeypatch):
    client = nvd.NvdClient()
    calls = []

    def page(cpe, start):
        calls.append((cpe, start))
        return {
            "totalResults": 1,
            "vulnerabilities": [{"cve": {
                "id": "CVE-2024-12345", "descriptions": [{"lang": "en", "value": "Example"}],
                "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                    "vulnerable": True, "criteria": "cpe:2.3:a:test:service:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "2.0",
                }]}]}],
                "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "nvd@test",
                    "cvssData": {"baseScore": 7.5,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                }}]},
            }}],
        }

    monkeypatch.setattr(client, "_page", page)
    cpe = "cpe:2.3:a:test:service:1.0:*:*:*:*:*:*:*"
    assert client.candidates(cpe)[0]["cve_id"] == "CVE-2024-12345"
    assert client.candidates(cpe)[0]["cvss"] == 7.5
    assert client.candidates(cpe)[0]["match_type"] == "range"
    assert client.candidates(cpe)[0]["cvss_source"] == "nvd@test"
    assert calls == [(cpe, 0)]


def test_aplicabilidad_nvd_distingue_todas_versiones_y_dependencias():
    query = "cpe:2.3:a:vendor:product:1.5:*:*:*:*:*:*:*"
    simple = {"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
    }]}]}]}
    assert nvd._applicability(simple, query) == (
        "all_versions", False, "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
    )
    conditional = {"configurations": [{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.0", "versionEndExcluding": "2.0",
        }]},
        {"operator": "OR", "cpeMatch": [{
            "vulnerable": False, "criteria": "cpe:2.3:o:vendor:system:*:*:*:*:*:*:*:*",
        }]},
    ]}]}
    assert nvd._applicability(conditional, query)[0:2] == ("range", True)


def test_aplicabilidad_descarta_version_fuera_de_rango():
    query = "cpe:2.3:a:vendor:product:2.1:*:*:*:*:*:*:*"
    cve = {"configurations": [{"nodes": [{"cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "2.0",
    }]}]}]}
    assert nvd._applicability(cve, query) == ("not_applicable", False, "")


def test_priorizacion_cisa_kev_y_epss_usa_cache():
    calls = []

    def fetch(url, **_kwargs):
        calls.append(url)
        if "cisa.gov" in url:
            return {"vulnerabilities": [{
                "cveID": "CVE-2024-12345", "dueDate": "2026-01-01",
                "requiredAction": "Apply mitigations",
            }]}
        return {"data": [{
            "cve": "CVE-2024-12345", "epss": "0.42", "percentile": "0.97",
            "date": "2026-09-21",
        }]}

    kev = threat_intel.kev_catalog(fetch_json=fetch)
    scores = threat_intel.epss_scores({"CVE-2024-12345"}, fetch_json=fetch)
    assert kev["CVE-2024-12345"]["due_date"] == "2026-01-01"
    assert scores["CVE-2024-12345"]["epss"] == 0.42
    assert len(calls) == 2
    threat_intel.kev_catalog(fetch_json=fetch)
    threat_intel.epss_scores({"CVE-2024-12345"}, fetch_json=fetch)
    assert len(calls) == 2


def test_exploitdb_cruza_cve_con_searchsploit(nmap_xml, tmp_path):
    path = tmp_path / "scan.xml"
    path.write_text(nmap_xml, encoding="utf-8")
    from medscan import analysis, nmap_parser

    run = nmap_parser.parse_file(path)
    scan_id = db.create_scan(
        name="ms17", targets="192.168.1.10", profile="vulnerabilidades"
    )
    db.save_results(scan_id, run, analysis.analyze(run, target_is_private=True), 80)

    def fake_searchsploit(cve_id: str) -> dict:
        assert cve_id == "CVE-2017-0143"
        return {
            "RESULTS_EXPLOIT": [
                {
                    "Title": "Microsoft Windows SMB MS17-010 Remote Code Execution",
                    "EDB-ID": "42315",
                    "Date": "2017-05-01",
                    "Type": "remote",
                    "Platform": "windows",
                    "Path": "/usr/share/exploitdb/exploits/windows/remote/42315.py",
                }
            ]
        }

    assert exploitdb.enrich_scan(scan_id, runner=fake_searchsploit) == 1
    rows = db.get_exploitdb_results(scan_id)
    assert rows[0]["cve_id"] == "CVE-2017-0143"
    assert rows[0]["edb_id"] == "42315"
    assert rows[0]["url"] == "https://www.exploit-db.com/exploits/42315"
    assert rows[0]["context_score"] >= 45
    assert "192.168.1.10:445" in rows[0]["matched_context"]
    assert db.get_enrichment_statuses(scan_id)["exploitdb"]["status"] == "done"


def test_msrc_compara_producto_y_build_acumulativo_con_cache():
    calls = []
    document = {
        "ProductTree": {"Branch": [{"Items": [{
            "ProductID": "20438", "Value": "Windows 11 Version 25H2 for x64-based Systems",
        }]}]},
        "Vulnerability": [{
            "CVE": "CVE-2026-12345", "Title": {"Value": "Windows demo"},
            "ProductStatuses": [{"Type": 3, "ProductID": ["20438"]}],
            "CVSSScoreSets": [{"ProductID": ["20438"], "BaseScore": 8.8,
                               "Vector": "CVSS:3.1/AV:N"}],
            "Remediations": [{"Type": 2, "ProductID": ["20438"],
                              "Description": {"Value": "5124008"},
                              "FixedBuild": "10.0.26200.9445", "URL": "https://example.test/kb"}],
        }],
    }

    def fetch(url, **_kwargs):
        calls.append(url)
        return document

    inventory = {"os_name": "Windows 10 Pro", "display_version": "25H2",
                 "os_build": "26200", "ubr": 9400, "os_architecture": "AMD64"}
    status, missing = msrc.assess_inventory(
        inventory, release_id="2026-Sep", fetch_json=fetch
    )
    assert status["product_id"] == "20438"
    assert status["status"] == "outdated"
    assert missing[0]["cve_id"] == "CVE-2026-12345"
    scan_id = db.create_scan(name="patch", targets="host", profile="rapido")
    db.replace_windows_patch_assessment(scan_id, "host", status, missing)
    patch_finding = next(row for row in db.get_findings(scan_id)
                         if row["source"].startswith("auth:windows:msrc:"))
    assert patch_finding["assessment"] == "confirmed"
    assert patch_finding["severity"] == int(Severity.HIGH)
    assert db.get_scan(scan_id)["risk_score"] > 0

    inventory["ubr"] = 9457
    status, missing = msrc.assess_inventory(
        inventory, release_id="2026-Sep", fetch_json=fetch
    )
    assert status["status"] == "current"
    assert missing == []
    assert len(calls) == 1

    db.replace_windows_patch_assessment(scan_id, "host", status, missing)
    assert db.get_windows_patch_statuses(scan_id)[0]["required_build"] == "10.0.26200.9445"
    patch_control = next(row for row in db.get_control_results(scan_id)
                         if row["control_id"] == "WIN-OS-PATCHLEVEL")
    assert patch_control["status"] == "pass"
    assert not any(row["source"].startswith("auth:windows:msrc:")
                   for row in db.get_findings(scan_id))


def test_amt_solo_se_correlaciona_con_firmware_autenticado(nmap_xml):
    xml = nmap_xml.replace(
        "</ports>",
        '<port protocol="tcp" portid="16992"><state state="open"/>'
        '<service name="http" product="Intel Active Management Technology httpd" '
        'version="16.1.42.2872" method="probed" conf="10">'
        '<cpe>cpe:/h:intel:active_management_technology:16.1.42.2872</cpe>'
        '</service></port></ports>',
        1,
    )
    run = parse_string(xml)
    scan_id = db.create_scan(name="amt", targets="192.168.1.10", profile="rapido")
    db.save_results(scan_id, run, [], 0)

    class FakeClient:
        def __init__(self):
            self.queried = []

        def candidates(self, cpe):
            self.queried.append(cpe)
            return [{"cve_id": "CVE-2025-12345", "cvss": 7.5, "summary": "Demo"}]

    client = FakeClient()
    no_intel = lambda rows: (rows, [])
    nvd.enrich_scan(scan_id, client=client, intel_enricher=no_intel)
    assert not any("active_management" in cpe for cpe in client.queried)
    assert not any(row["port"] == 16992 for row in db.get_cve_candidates(scan_id))

    db.save_host_inventory(scan_id, "192.168.1.10", {"intel_me_firmware": "16.1.42.2872"}, "test")
    nvd.enrich_scan(scan_id, client=client, intel_enricher=no_intel)
    assert not any("active_management" in cpe for cpe in client.queried)
    nvd.enrich_scan(
        scan_id, client=client, include_firmware=True, intel_enricher=no_intel
    )
    assert any(":o:intel:active_management_technology_firmware:16.1.42.2872:" in cpe
               for cpe in client.queried)
    row = next(row for row in db.get_cve_candidates(scan_id) if row["port"] == 16992)
    assert row["cve_id"] == "CVE-2025-12345"
    assert row["detected_cpe"].startswith("WMI")


def test_amt_exposicion_no_es_cve_confirmada():
    port = Port(
        portid=16992, state="open",
        service=Service(name="http", product="Intel Active Management Technology httpd",
                        version="16.1.42.2872", method="probed", confidence=10),
    )
    findings = evaluate_port("10.0.0.1", port, target_is_private=True)
    assert len(findings) == 1
    assert findings[0].source == "rule:amt-expuesto"
    assert findings[0].assessment == Assessment.EXPOSURE
    assert findings[0].cve_ids == []
    assert findings[0].severity == Severity.MEDIUM


def test_servicio_por_tabla_se_etiqueta_como_inferido():
    port = Port(
        portid=445, state="open",
        service=Service(name="microsoft-ds", method="table", confidence=3),
    )
    finding = evaluate_port("127.0.0.1", port, target_is_private=True)[0]
    assert finding.title == "SMB accesible (servicio inferido)"
    assert "nmap no obtuvo un fingerprint fiable" in finding.description
    assert finding.assessment == Assessment.EXPOSURE


def test_windows_inventory_solo_host_escaneado(monkeypatch, nmap_xml):
    run = parse_string(nmap_xml)
    scan_id = db.create_scan(name="win", targets="192.168.1.10", profile="rapido")
    db.save_results(scan_id, run, [], 0)
    calls = []

    def fake_collect(host, *, local=False):
        calls.append((host, local))
        return {"os_build": "22631", "updates": [{"kb": "KB123"}],
                "software": [], "intel_me_firmware": None}

    monkeypatch.setattr(windows_inventory, "collect", fake_collect)
    with pytest.raises(ValueError, match="no pertenece"):
        windows_inventory.inventory_scan(scan_id, host="10.0.0.99")
    with pytest.raises(ValueError, match="loopback"):
        windows_inventory.inventory_scan(scan_id, host="192.168.1.10", local=True)
    assert windows_inventory.inventory_scan(scan_id, host="192.168.1.10") == 1
    assert calls == [("192.168.1.10", False)]
    assert db.get_host_inventories(scan_id)["192.168.1.10"]["updates"][0]["kb"] == "KB123"


def test_inventario_autenticado_actualiza_hallazgos_y_riesgo(monkeypatch, nmap_xml):
    scan_id = db.create_scan(name="smb", targets="192.168.1.10", profile="rapido")
    db.save_results(scan_id, parse_string(nmap_xml), [], 0)
    config = {"smb1_enabled": True, "signing_required": False}

    def fake_collect(_host, *, local=False):
        return {"os_build": "22631", "smb_server": config.copy(),
                "updates": [], "software": []}

    monkeypatch.setattr(windows_inventory, "collect", fake_collect)
    windows_inventory.inventory_scan(scan_id, host="192.168.1.10")
    findings = db.get_findings(scan_id)
    assert {f["source"] for f in findings} == {
        "auth:windows:smb1", "auth:windows:smb-signing",
    }
    assert all(f["assessment"] == "confirmed" for f in findings)
    assert db.get_scan(scan_id)["risk_score"] > 0

    config.update(smb1_enabled=False, signing_required=True)
    windows_inventory.inventory_scan(scan_id, host="192.168.1.10")
    assert db.get_findings(scan_id) == []
    assert db.get_scan(scan_id)["risk_score"] == 0


def test_nla_solo_genera_hallazgo_si_rdp_esta_accesible():
    data = {"rdp": {"nla_required": False, "nla_source": "policy"}}
    assert windows_findings("10.0.0.1", data, {445}) == []
    finding = windows_findings("10.0.0.1", data, {3389})[0]
    assert finding.source == "auth:windows:rdp-nla"
    assert finding.assessment == Assessment.CONFIRMED


def test_controles_windows_autenticados_generan_hallazgos_confirmados():
    data = {
        "firewall_profiles": [{"name": "Public", "active": True, "enabled": False}],
        "defender": {"antivirus_enabled": True, "realtime_enabled": False,
                     "signature_age_days": 9},
        "uac_enabled": False,
        "bitlocker": {"mount_point": "C:", "protection_status": "Off",
                      "volume_status": "FullyDecrypted"},
    }
    findings = windows_findings("10.0.0.1", data, set())
    assert {finding.source for finding in findings} == {
        "auth:windows:firewall:public", "auth:windows:defender-realtime",
        "auth:windows:defender-signatures", "auth:windows:uac",
        "auth:windows:bitlocker",
    }
    assert all(finding.assessment == Assessment.CONFIRMED for finding in findings)


def test_controles_windows_de_red_autenticados():
    data = {
        "llmnr_enabled": True, "llmnr_source": "Windows default (policy absent)",
        "winrm": {"allow_unencrypted": True, "basic_auth": True},
        "remote_registry": {"running": True},
    }
    findings = windows_findings("10.0.0.1", data, {5985})
    assert {finding.source for finding in findings} == {
        "auth:windows:llmnr", "auth:windows:winrm-unencrypted",
        "auth:windows:winrm-basic", "auth:windows:remote-registry",
    }
    controls = {item["control_id"]: item for item in compliance.windows_controls(data, {5985})}
    assert controls["WIN-LLMNR"]["status"] == "fail"
    assert controls["WIN-WINRM-UNENCRYPTED"]["status"] == "fail"


def test_resultados_de_control_distinguen_cumple_falla_y_sin_datos():
    data = {
        "smb_server": {"smb1_enabled": False, "signing_required": False},
        "rdp": {"nla_required": True},
        "firewall_profiles": [{"name": "Public", "active": True, "enabled": True}],
        "defender": {"antivirus_enabled": True, "realtime_enabled": True,
                     "signature_age_days": 2},
        "uac_enabled": None,
        "bitlocker": None,
    }
    rows = {item["control_id"]: item for item in compliance.windows_controls(data, {445, 3389})}
    assert rows["WIN-SMB1"]["status"] == "pass"
    assert rows["WIN-SMB-SIGN"]["status"] == "fail"
    assert rows["WIN-RDP-NLA"]["status"] == "pass"
    assert rows["WIN-UAC"]["status"] == "unknown"
    assert "CIS Controls v8.1 4.4" in rows["WIN-FIREWALL"]["references"]


def test_perfiles_firewall_inactivos_no_generan_hallazgo():
    data = {"firewall_profiles": [{"name": "Public", "active": False, "enabled": False}]}
    assert windows_findings("10.0.0.1", data, set()) == []


def _linux_records(**values):
    return "\n".join(
        f"{key}\t{base64.b64encode(str(value).encode()).decode()}"
        for key, value in values.items()
    )


def test_parsea_inventario_linux_y_controles_confirmados():
    output = _linux_records(
        HOSTNAME="srv-01", KERNEL="6.8.0-1", OS_RELEASE='ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"',
        PACKAGE_MANAGER="dpkg", PACKAGES="openssh-server\t1:9.6p1\nlinux-image\t6.8.0",
        SECURITY_UPDATES_CHECKED="yes",
        SECURITY_UPDATES="Inst openssl [3.0.1] (3.0.2 Ubuntu:24.04/noble-security [amd64])",
        SSHD_EFFECTIVE="permitrootlogin yes\npasswordauthentication yes",
        FIREWALL_OBSERVED="yes", FIREWALL_ACTIVE="no", FIREWALL_DETAIL="ufw: inactive",
        ASLR="0", SELINUX="", APPARMOR="Y", REBOOT_REQUIRED="yes",
    )
    inventory = linux_inventory.parse_inventory(output)
    assert inventory["os_id"] == "ubuntu"
    assert inventory["kernel"] == "6.8.0-1"
    assert inventory["packages"][0] == {"name": "openssh-server", "version": "1:9.6p1"}
    findings = linux_findings("10.0.0.2", inventory, {22})
    assert {finding.source for finding in findings} == {
        "auth:linux:ssh-root", "auth:linux:ssh-password", "auth:linux:firewall",
        "auth:linux:aslr", "auth:linux:reboot", "auth:linux:security-updates",
    }
    assert all(finding.assessment == Assessment.CONFIRMED for finding in findings)
    assert inventory["security_updates"][0]["name"] == "openssl"
    controls = {item["control_id"]: item for item in compliance.linux_controls(inventory, {22})}
    assert controls["LINUX-SECURITY-UPDATES"]["status"] == "fail"


def test_sshd_con_contrasenas_vacias_y_muchos_intentos():
    data = {"ssh_port": 22, "sshd": {
        "permit_root_login": "no", "password_authentication": "no",
        "permit_empty_passwords": "yes", "max_auth_tries": "10",
    }}
    findings = linux_findings("10.0.0.2", data, {22})
    assert {finding.source for finding in findings} == {
        "auth:linux:ssh-empty-passwords", "auth:linux:ssh-max-auth-tries",
    }
    controls = {item["control_id"]: item for item in compliance.linux_controls(data, {22})}
    assert controls["LINUX-SSH-EMPTY"]["status"] == "fail"
    assert controls["LINUX-SSH-MAXAUTH"]["status"] == "fail"


def test_inventario_linux_solo_host_escaneado(monkeypatch, nmap_xml):
    scan_id = db.create_scan(name="linux", targets="192.168.1.10", profile="rapido")
    db.save_results(scan_id, parse_string(nmap_xml), [], 0)
    calls = []

    def fake_collect(host, *, user=None, port=22, local=False):
        calls.append((host, user, port, local))
        return {"platform": "linux", "os_id": "debian", "kernel": "6.1",
                "packages": [], "ssh_port": port}

    monkeypatch.setattr(linux_inventory, "collect", fake_collect)
    with pytest.raises(ValueError, match="no pertenece"):
        linux_inventory.inventory_scan(scan_id, host="10.0.0.99")
    assert linux_inventory.inventory_scan(
        scan_id, host="192.168.1.10", user="audit", port=22
    ) == 1
    assert calls == [("192.168.1.10", "audit", 22, False)]
    assert db.get_host_inventories(scan_id)["192.168.1.10"]["platform"] == "linux"
    assert db.get_control_results(scan_id)


def test_migracion_de_assessment_en_bd_antigua(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.execute("""CREATE TABLE findings (
            id INTEGER PRIMARY KEY, scan_id INTEGER, severity INTEGER,
            source TEXT, cves TEXT, confirmed INTEGER
        )""")
        conn.execute("INSERT INTO findings (source, cves, confirmed) VALUES (?, ?, ?)",
                     ("nse:test", '["CVE-2024-12345"]', 0))
    db.init_db(path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT assessment FROM findings").fetchone()[0] == "candidate"
