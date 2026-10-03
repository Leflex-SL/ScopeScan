"""Pruebas de la integracion con Metasploit.

El catalogo y el parser son funciones puras: se prueban sin msfconsole. El plan
de verificacion se prueba montando un escaneo real en la BD desde el XML de
nmap de conftest, para comprobar que los servicios y CVE se traducen a modulos.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from medscan import analysis, cli, db, msf, msf_modules, nmap_parser
from medscan.msf_modules import EXPLOITED, LIKELY, SAFE, UNKNOWN, VULNERABLE

# --- catalogo ----------------------------------------------------------------


def test_servicio_smb_mapea_a_scanner():
    mods = msf_modules.candidates_for(service_name="microsoft-ds", product="Samba smbd")
    paths = {m.path for m in mods}
    assert "auxiliary/scanner/smb/smb_version" in paths
    assert all(m.kind == "scanner" for m in mods)


def test_cve_ms17_010_activa_modulo_de_check():
    mods = msf_modules.candidates_for(
        service_name="microsoft-ds", product="", cve_ids=["CVE-2017-0144"]
    )
    eternalblue = next(m for m in mods if "ms17_010_eternalblue" in m.path)
    assert eternalblue.kind == "exploit"
    # Un exploit solo se verifica con `check`, nunca se dispara.
    assert eternalblue.action == "check"


def test_servicio_desconocido_sin_cve_no_da_modulos():
    assert msf_modules.candidates_for(service_name="hotline", product="") == []


def test_cve_sin_coincidir_no_mete_modulo():
    mods = msf_modules.candidates_for(service_name="ssh", product="", cve_ids=["CVE-2099-9999"])
    assert all("eternalblue" not in m.path for m in mods)


# --- resource script ---------------------------------------------------------


def test_build_rc_no_contiene_exploit_ni_payload():
    mod = msf_modules.MsfModule("exploit/windows/smb/ms17_010_eternalblue", "exploit", "x")
    rc = msf_modules.build_resource_script(mod, ["10.0.0.1", "10.0.0.2"], rport=445)
    assert "use exploit/windows/smb/ms17_010_eternalblue" in rc
    assert "setg RHOSTS 10.0.0.1 10.0.0.2" in rc
    assert "set RPORT 445" in rc
    assert "\ncheck\n" in rc
    # Nunca debe aparecer el disparo del exploit ni un payload.
    assert "\nexploit" not in rc
    assert "PAYLOAD" not in rc.upper()


def test_build_rc_scanner_usa_run():
    mod = msf_modules.MsfModule("auxiliary/scanner/ssh/ssh_version", "scanner", "x")
    rc = msf_modules.build_resource_script(mod, ["10.0.0.1"])
    assert "\nrun\n" in rc


def test_build_rc_sin_hosts_falla():
    mod = msf_modules.MsfModule("auxiliary/scanner/ssh/ssh_version", "scanner", "x")
    with pytest.raises(ValueError):
        msf_modules.build_resource_script(mod, [])


# --- parser de salida --------------------------------------------------------


def test_parse_vulnerable_gana_a_otras_lineas():
    salida = (
        "[*] 10.0.0.5:445 - Scanning...\n"
        "[+] 10.0.0.5:445 - Host is likely VULNERABLE to MS17-010!\n"
        "[*] 10.0.0.5:445 - Scanned 1 of 1 hosts\n"
    )
    verdicts = msf_modules.parse_output(salida)
    assert verdicts["10.0.0.5"].result == VULNERABLE


def test_parse_not_vulnerable_es_safe():
    salida = "[-] 10.0.0.6:3389 - The target is not exploitable.\n"
    assert msf_modules.parse_output(salida)["10.0.0.6"].result == SAFE


def test_parse_appears_es_likely():
    salida = "[*] 10.0.0.7:445 - The target appears to be vulnerable.\n"
    assert msf_modules.parse_output(salida)["10.0.0.7"].result == LIKELY


def test_parse_host_sin_veredicto_queda_unknown():
    verdicts = msf_modules.parse_output("", default_hosts=["10.0.0.9"])
    assert verdicts["10.0.0.9"].result == UNKNOWN


# --- plan de verificacion sobre un escaneo real ------------------------------


@pytest.fixture
def scan_id(nmap_xml, tmp_path) -> int:
    path = tmp_path / "scan.xml"
    path.write_text(nmap_xml, encoding="utf-8")
    run = nmap_parser.parse_file(path)
    findings = analysis.analyze(run, target_is_private=True)
    sid = db.create_scan(
        name="t", targets="192.168.1.10", profile="vulnerabilidades", target_private=True
    )
    db.save_results(sid, run, findings, analysis.risk_score(findings))
    return sid


def test_plan_incluye_scanner_por_servicio_y_check_por_cve(scan_id):
    plan = msf.plan_scan(scan_id)
    por_puerto = {(port, mod.path) for _addr, port, _svc, mod in plan}
    assert (22, "auxiliary/scanner/ssh/ssh_version") in por_puerto
    assert (445, "auxiliary/scanner/smb/smb_version") in por_puerto
    # El NSE marco MS17-010 (CVE-2017-0143) en el 445 -> modulo de check.
    assert (445, "exploit/windows/smb/ms17_010_eternalblue") in por_puerto


def test_verify_bloquea_objetivo_publico_sin_autorizacion(nmap_xml, tmp_path):
    path = tmp_path / "pub.xml"
    path.write_text(nmap_xml, encoding="utf-8")
    run = nmap_parser.parse_file(path)
    sid = db.create_scan(
        name="pub", targets="8.8.8.8", profile="rapido", target_private=False
    )
    db.save_results(sid, run, analysis.analyze(run, target_is_private=False), 0)
    with pytest.raises(msf.MsfScopeError):
        msf.verify_scan(sid)


def test_exploit_target_guarda_run_sin_pisar_verificacion(scan_id, monkeypatch, tmp_path):
    module = "exploit/windows/smb/ms17_010_eternalblue"
    db.save_msf_results(scan_id, [{
        "host": "192.168.1.10",
        "port": 445,
        "protocol": "tcp",
        "module": module,
        "module_kind": "exploit",
        "action": "check",
        "result": VULNERABLE,
        "detail": "Host is vulnerable",
    }])
    monkeypatch.setattr(msf, "msf_lhost", lambda: "192.168.1.50")
    monkeypatch.setattr(msf, "msf_lport", lambda: 4444)
    monkeypatch.setattr(msf.msf_runner, "build_argv", lambda rc_path, log_path=None: [
        "msfconsole", "-q", "-n", "-r", str(rc_path), "-o", str(log_path)
    ])

    def fake_run(argv, *, cancel=None, progress=None):
        rc_path = tmp_path / "fake.rc"
        return msf.msf_runner.MsfExecution(
            argv=argv,
            rc_path=rc_path,
            returncode=0,
            stdout="[+] 192.168.1.10:445 - Meterpreter session 1 opened\nwhoami\nnt authority\\system",
            stderr="",
        )

    monkeypatch.setattr(msf.msf_runner, "run", fake_run)

    assert msf.exploit_target(scan_id, host="192.168.1.10", port=445, module_path=module) == EXPLOITED

    rows = db.get_msf_results(scan_id)
    assert rows[0]["action"] == "check"
    assert rows[0]["result"] == VULNERABLE

    runs = db.get_exploit_runs(scan_id)
    assert len(runs) == 1
    assert runs[0]["module"] == module
    assert runs[0]["result"] == EXPLOITED
    assert "session 1 opened" in runs[0]["detail"].lower()


def test_prepare_exploit_resource_registra_rc_sin_lanzar_msf(scan_id, monkeypatch, tmp_path):
    module = "exploit/windows/smb/ms17_010_eternalblue"
    db.save_msf_results(scan_id, [{
        "host": "192.168.1.10",
        "port": 445,
        "protocol": "tcp",
        "module": module,
        "module_kind": "exploit",
        "action": "check",
        "result": VULNERABLE,
        "detail": "Host is vulnerable",
    }])
    monkeypatch.setattr(msf, "raw_dir", lambda: tmp_path)
    monkeypatch.setattr(msf, "msf_lhost", lambda: "192.168.1.50")
    monkeypatch.setattr(msf, "msf_lport", lambda: 4444)

    def forbidden_run(*_args, **_kwargs):
        raise AssertionError("preparar el .rc no debe lanzar msfconsole")

    monkeypatch.setattr(msf.msf_runner, "run", forbidden_run)

    rc_path, rc_text = msf.prepare_exploit_resource(
        scan_id, host="192.168.1.10", port=445, module_path=module
    )

    assert rc_path.endswith("-manual.rc")
    assert "use exploit/windows/smb/ms17_010_eternalblue" in rc_text
    assert "setg RHOSTS 192.168.1.10" in rc_text
    assert "exploit -z" in rc_text
    assert (tmp_path / Path(rc_path).name).read_text(encoding="utf-8") == rc_text

    runs = db.get_exploit_runs(scan_id)
    assert len(runs) == 1
    assert runs[0]["action"] == "prepare_rc"
    assert runs[0]["status"] == "prepared"
    assert runs[0]["result"] == msf_modules.PREPARED


def test_cli_msf_rc_prepara_resource_script(scan_id, monkeypatch, tmp_path, capsys):
    module = "exploit/windows/smb/ms17_010_eternalblue"
    db.save_msf_results(scan_id, [{
        "host": "192.168.1.10",
        "port": 445,
        "protocol": "tcp",
        "module": module,
        "module_kind": "exploit",
        "action": "check",
        "result": VULNERABLE,
        "detail": "Host is vulnerable",
    }])
    monkeypatch.setattr(msf, "raw_dir", lambda: tmp_path)
    monkeypatch.setattr(msf, "msf_lhost", lambda: "192.168.1.50")
    monkeypatch.setattr(msf, "msf_lport", lambda: 4444)

    code = cli.main([
        "msf-rc",
        str(scan_id),
        "--host", "192.168.1.10",
        "--port", "445",
        "--module", module,
    ])

    out = capsys.readouterr().out
    assert code == 0
    assert "Resource script preparado:" in out
    assert "msfconsole -q -r" in out
    assert db.get_exploit_runs(scan_id)[0]["status"] == "prepared"


def test_cli_msf_catalog_lista_allowlist(capsys):
    assert cli.main(["msf-catalog"]) == 0
    out = capsys.readouterr().out
    assert "Catalogo Metasploit allowlistado" in out
    assert "exploit/windows/smb/ms17_010_eternalblue" in out
    assert "prerequisitos" in out
