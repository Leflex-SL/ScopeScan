from __future__ import annotations

from medscan import analysis, attack_paths, db, nmap_parser
from medscan.msf_modules import VULNERABLE


def test_attack_path_encadena_cve_poc_y_msf(nmap_xml):
    run = nmap_parser.parse_string(nmap_xml)
    sid = db.create_scan(
        name="path", targets="192.168.1.10", profile="vulnerabilidades", target_private=True
    )
    db.save_results(sid, run, analysis.analyze(run, target_is_private=True), 0)
    db.replace_exploitdb_results(sid, [{
        "cve_id": "CVE-2017-0143",
        "edb_id": "42315",
        "title": "MS17-010 public PoC",
        "type": "remote",
        "platform": "windows",
        "context_score": 80,
        "matched_context": "192.168.1.10:445/tcp microsoft-ds Samba smbd 3.0.20",
    }])
    db.save_msf_results(sid, [{
        "host": "192.168.1.10",
        "port": 445,
        "protocol": "tcp",
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "module_kind": "exploit",
        "action": "check",
        "result": VULNERABLE,
        "detail": "Host is vulnerable",
    }])

    paths = attack_paths.build(sid)
    smb = next(item for item in paths if item["host"] == "192.168.1.10" and item["port"] == 445)

    assert smb["state"] == "Verificada"
    assert "CVE-2017-0143" in smb["cves"]
    assert len(smb["exploitdb"]) == 1
    assert smb["best_poc"]["context_score"] == 80
    assert smb["exploitable_modules"]
    assert smb["best_msf"]["result"] == VULNERABLE
    assert smb["score"] >= 80


def test_attack_path_sube_exposicion_publica(nmap_xml):
    run = nmap_parser.parse_string(nmap_xml)
    sid = db.create_scan(
        name="public", targets="203.0.113.10", profile="vulnerabilidades", target_private=False
    )
    db.save_results(sid, run, analysis.analyze(run, target_is_private=False), 0)

    smb = next(
        item for item in attack_paths.build(sid)
        if item["host"] == "192.168.1.10" and item["port"] == 445
    )

    assert smb["public_scope"] is True
    assert "exposicion publica" in smb["recommendation"].lower()
