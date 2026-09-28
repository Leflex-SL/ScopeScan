from __future__ import annotations

import pytest

from medscan.targets import InvalidTarget, parse_target, parse_targets


def test_ip_privada():
    target = parse_target("192.168.1.10")
    assert target.kind == "ip"
    assert target.hosts == 1
    assert target.private


def test_ip_publica_no_es_privada():
    assert not parse_target("8.8.8.8").private


def test_cidr_cuenta_hosts():
    target = parse_target("192.168.1.0/24")
    assert target.kind == "cidr"
    assert target.hosts == 256
    assert target.private


def test_rango_de_octetos():
    target = parse_target("10.0.0.1-50")
    assert target.kind == "range"
    assert target.hosts == 50
    assert target.private


def test_hostname():
    target = parse_target("scanme.nmap.org")
    assert target.kind == "hostname"
    assert not target.private


@pytest.mark.parametrize(
    "entrada",
    [
        "-oX",  # se colaria como opcion de nmap
        "--script=vuln",
        "192.168.1.1; rm -rf /",
        "192.168.1.1 && calc.exe",
        "$(whoami)",
        "192.168.1.1|nc",
        "",
        "999.999.999.999",
    ],
)
def test_objetivos_rechazados(entrada):
    """Ningun objetivo puede empezar por guion ni traer metacaracteres."""
    with pytest.raises(InvalidTarget):
        parse_target(entrada)


def test_varios_objetivos_separados():
    conjunto = parse_targets("192.168.1.10, 192.168.1.20 10.0.0.0/30")
    assert len(conjunto.targets) == 3
    assert conjunto.hosts == 1 + 1 + 4
    assert conjunto.all_private


def test_limite_de_hosts():
    with pytest.raises(InvalidTarget, match="limite"):
        parse_targets("10.0.0.0/16", max_hosts=256)


def test_limite_se_puede_forzar():
    conjunto = parse_targets("10.0.0.0/22", max_hosts=256, force=True)
    assert conjunto.hosts == 1024


def test_aviso_si_el_objetivo_es_publico():
    conjunto = parse_targets("8.8.8.8")
    assert any("autorizacion" in w for w in conjunto.warnings)
    assert not conjunto.all_private


def test_rango_de_octetos_invalido():
    with pytest.raises(InvalidTarget):
        parse_target("10.0.0.50-20")
