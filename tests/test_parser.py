from __future__ import annotations

import pytest

from scopescan import nmap_parser
from scopescan.nmap_parser import NmapParseError, parse_file, parse_string


def test_parsea_cabecera(nmap_xml):
    run = parse_string(nmap_xml)
    assert run.scanner_version == "7.95"
    assert run.elapsed == pytest.approx(121.45)
    assert run.exit_status == "success"
    assert run.hosts_up == 1
    assert run.hosts_total == 2


def test_hosts_y_estado(nmap_xml):
    run = parse_string(nmap_xml)
    assert len(run.hosts) == 2
    assert len(run.live_hosts) == 1
    host = run.live_hosts[0]
    assert host.address == "192.168.1.10"
    assert host.mac == "00:0C:29:3A:1B:2C"
    assert host.vendor == "VMware"
    assert host.hostnames == ["servidor.local"]


def test_puertos_abiertos_y_servicios(nmap_xml):
    host = parse_string(nmap_xml).live_hosts[0]
    assert [p.portid for p in host.open_ports] == [22, 23, 443, 445]
    ssh = next(p for p in host.ports if p.portid == 22)
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "6.6.1p1"
    assert ssh.service.cpes == ["cpe:/a:openbsd:openssh:6.6.1p1"]
    assert ssh.service.display == "OpenSSH 6.6.1p1 (Ubuntu)"


def test_puerto_cerrado_no_cuenta_como_abierto(nmap_xml):
    host = parse_string(nmap_xml).live_hosts[0]
    cerrado = next(p for p in host.ports if p.portid == 1234)
    assert not cerrado.is_open


def test_extraports(nmap_xml):
    host = parse_string(nmap_xml).live_hosts[0]
    assert host.extraports == {"closed": 65530}


def test_scripts_y_os(nmap_xml):
    host = parse_string(nmap_xml).live_hosts[0]
    smb = next(p for p in host.ports if p.portid == 445)
    assert [s.id for s in smb.scripts] == ["smb-vuln-ms17-010"]
    assert "CVE-2017-0143" in smb.scripts[0].output
    assert host.best_os is not None
    assert host.best_os.name == "Linux 3.2 - 4.9"
    assert host.best_os.accuracy == 95


def test_parse_file(xml_file):
    run = parse_file(xml_file)
    assert run.hosts_up == 1


def test_xml_truncado_se_recupera(tmp_path, nmap_xml):
    """Si se cancela el escaneo, nmap deja el XML sin cerrar: hay que aprovecharlo."""
    truncado = nmap_xml.split("</host>")[0] + "</host>\n<host><status state=\"up\""
    path = tmp_path / "parcial.xml"
    path.write_text(truncado, encoding="utf-8")

    run = parse_file(path)
    assert len(run.hosts) == 1
    assert run.hosts[0].address == "192.168.1.10"


def test_xml_ilegible():
    with pytest.raises(NmapParseError):
        parse_string("esto no es xml")


def test_raiz_equivocada():
    with pytest.raises(NmapParseError, match="nmaprun"):
        parse_string("<otracosa/>")


def test_fichero_inexistente(tmp_path):
    with pytest.raises(NmapParseError):
        nmap_parser.parse_file(tmp_path / "no-existe.xml")
