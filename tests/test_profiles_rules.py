from __future__ import annotations

import pytest

from scopescan.models import Port, Service, Severity
from scopescan.profiles import DEFAULT_PROFILE, PROFILES, get_profile
from scopescan.rules import evaluate_port


def puerto(portid: int, name: str = "", product: str = "", version: str = "") -> Port:
    return Port(
        portid=portid,
        state="open",
        service=Service(name=name, product=product, version=version),
    )


def test_perfil_por_defecto_escanea_todos_los_puertos():
    args = get_profile(DEFAULT_PROFILE).nmap_args(privileged=True)
    assert "-p-" in args
    assert "-sV" in args
    assert "--script" in args


def test_sin_privilegios_usa_connect_scan():
    profile = get_profile("completo")
    con = profile.nmap_args(privileged=True)
    sin = profile.nmap_args(privileged=False)
    assert "-sS" in con and "-O" in con
    assert "-sT" in sin and "-O" not in sin


def test_descubrimiento_no_escanea_puertos():
    args = get_profile("descubrimiento").nmap_args(privileged=True)
    assert "-sn" in args
    assert "-p-" not in args


def test_perfil_vuln_excluye_dos_y_exploit():
    args = get_profile("vulnerabilidades-profundo").nmap_args(privileged=True)
    selector = args[args.index("--script") + 1]
    assert "not dos" in selector
    assert "not exploit" in selector
    assert "ssl-enum-ciphers" in selector


def test_perfil_safe_solo_usa_scripts_safe():
    selector = get_profile("vulnerabilidades").nmap_args(privileged=True)
    assert "safe" in selector[selector.index("--script") + 1]


def test_avisos_de_perfil():
    avisos = get_profile("vulnerabilidades-profundo").warnings(privileged=False)
    assert any("connect scan" in a for a in avisos)
    assert any("intrusivo" in a.lower() for a in avisos)


def test_perfil_desconocido():
    with pytest.raises(KeyError, match="Disponibles"):
        get_profile("inventado")


def test_todos_los_perfiles_construyen_argumentos():
    for profile in PROFILES.values():
        assert profile.nmap_args(privileged=False)


def test_perfil_tls_enumera_cifrados_de_forma_explicita():
    args = get_profile("auditoria-tls").nmap_args(privileged=True)
    selector = args[args.index("--script") + 1]
    assert selector == "ssl-enum-ciphers or ssl-cert"
    assert get_profile("auditoria-tls").intrusive is True


def test_perfil_udp_comun_usa_udp_y_top_200():
    profile = get_profile("udp-comun")
    args = profile.nmap_args(privileged=True)
    assert "-sU" in args
    assert "-sS" not in args
    assert args[args.index("--top-ports") + 1] == "200"


def test_perfil_udp_avisa_si_faltan_privilegios():
    warnings = get_profile("udp-comun").warnings(privileged=False)
    assert any("privilegios" in warning for warning in warnings)


def test_reglas_tcp_no_se_disparan_por_mismo_numero_udp():
    port = puerto(23, "unknown")
    port.protocol = "udp"
    assert evaluate_port("10.0.0.1", port, target_is_private=True) == []


def test_regla_snmp_es_udp():
    port = puerto(161, "snmp")
    port.protocol = "udp"
    findings = evaluate_port("10.0.0.1", port, target_is_private=True)
    assert any(f.source == "rule:snmp-expuesto" for f in findings)


@pytest.mark.parametrize(
    ("portid", "service", "source"),
    [
        (53, "domain", "rule:dns-udp-expuesto"),
        (123, "ntp", "rule:ntp-udp-expuesto"),
        (1900, "upnp", "rule:ssdp-udp-expuesto"),
        (389, "cldap", "rule:cldap-udp-expuesto"),
        (137, "netbios-ns", "rule:netbios-udp-expuesto"),
    ],
)
def test_reglas_de_exposicion_udp(portid: int, service: str, source: str):
    port = puerto(portid, service)
    port.protocol = "udp"
    findings = evaluate_port("10.0.0.1", port, target_is_private=True)
    assert any(f.source == source for f in findings)


def test_regla_telnet():
    hallazgos = evaluate_port("10.0.0.1", puerto(23, "telnet"), target_is_private=True)
    assert hallazgos[0].severity == Severity.HIGH
    assert "telnet" in hallazgos[0].source


def test_regla_no_aplica_a_puerto_cerrado():
    cerrado = Port(portid=23, state="closed", service=Service(name="telnet"))
    assert evaluate_port("10.0.0.1", cerrado, target_is_private=True) == []


def test_version_antigua_de_openssh():
    hallazgos = evaluate_port(
        "10.0.0.1", puerto(22, "ssh", "OpenSSH", "6.6.1p1"), target_is_private=True
    )
    assert any(f.source == "rule:openssh-antiguo" for f in hallazgos)


def test_version_reciente_no_dispara_la_regla():
    hallazgos = evaluate_port(
        "10.0.0.1", puerto(22, "ssh", "OpenSSH", "9.6p1"), target_is_private=True
    )
    assert not any("openssh" in f.source for f in hallazgos)


def test_banner_vsftpd_no_confirma_backdoor():
    hallazgos = evaluate_port(
        "10.0.0.1", puerto(21, "ftp", "vsftpd", "2.3.4"), target_is_private=True
    )
    assert not any(f.severity == Severity.CRITICAL for f in hallazgos)


def test_redis_expuesto_no_duplica_la_regla_generica():
    hallazgos = evaluate_port("10.0.0.1", puerto(6379, "redis"), target_is_private=True)
    fuentes = [f.source for f in hallazgos]
    assert "rule:db-nosql-expuesta" in fuentes
    assert "rule:db-expuesta" not in fuentes


def test_exposicion_publica_sube_un_nivel():
    privado = evaluate_port("10.0.0.1", puerto(3389, "ms-wbt-server"), target_is_private=True)
    publico = evaluate_port("8.8.8.8", puerto(3389, "ms-wbt-server"), target_is_private=False)
    assert publico[0].severity > privado[0].severity


def test_la_severidad_no_pasa_de_critica():
    publico = evaluate_port("8.8.8.8", puerto(6379, "redis"), target_is_private=False)
    assert publico[0].severity == Severity.CRITICAL
