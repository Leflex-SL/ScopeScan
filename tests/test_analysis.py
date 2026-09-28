from __future__ import annotations

from medscan.analysis import analyze, finding_from_script, risk_score, summarize
from medscan.models import Assessment, ScriptResult, Severity
from medscan.nmap_parser import parse_string


def script(id_: str, output: str) -> ScriptResult:
    return ScriptResult(id=id_, output=output)


def test_risk_factor_manda_sobre_la_tabla():
    resultado = finding_from_script(
        script("smb-vuln-ms17-010", "VULNERABLE:\nMS17-010\n  State: VULNERABLE\n  Risk factor: HIGH"),
        host="10.0.0.1",
        port=445,
    )
    assert resultado is not None
    assert resultado.severity == Severity.HIGH
    assert resultado.confirmed
    assert resultado.title == "MS17-010"


def test_not_vulnerable_no_genera_hallazgo():
    assert finding_from_script(
        script("ssl-heartbleed", "NOT VULNERABLE:\n  State: NOT VULNERABLE"),
        host="10.0.0.1",
        port=443,
    ) is None


def test_cvss_define_severidad():
    resultado = finding_from_script(
        script("http-vuln-generico", "State: VULNERABLE\n  CVSSv3 Score: 9.8"),
        host="10.0.0.1",
        port=80,
    )
    assert resultado is not None
    assert resultado.severity == Severity.CRITICAL
    assert resultado.cvss == 9.8


def test_vulners_toma_la_mayor_puntuacion():
    salida = (
        "cpe:/a:openbsd:openssh:6.6.1p1:\n"
        "\tCVE-2015-5600\t8.5\thttps://vulners.com/cve/CVE-2015-5600\n"
        "\tCVE-2016-0778\t4.6\thttps://vulners.com/cve/CVE-2016-0778\n"
    )
    resultado = finding_from_script(script("vulners", salida), host="10.0.0.1", port=22)
    assert resultado is not None
    assert resultado.cvss == 8.5
    assert resultado.severity == Severity.HIGH
    assert resultado.cve_ids == ["CVE-2015-5600", "CVE-2016-0778"]


def test_likely_vulnerable_baja_de_critica_a_alta():
    resultado = finding_from_script(
        script("smb-vuln-ms08-067", "LIKELY VULNERABLE:\nAlgo\n  State: LIKELY VULNERABLE"),
        host="10.0.0.1",
        port=445,
    )
    assert resultado is not None
    assert resultado.severity == Severity.HIGH


def test_script_descriptivo_no_genera_hallazgo():
    assert finding_from_script(
        script("http-title", "Did not follow redirect"), host="10.0.0.1", port=80
    ) is None


def test_script_sin_senal_no_genera_hallazgo():
    assert finding_from_script(
        script("banner-raro", "algo que no dice nada"), host="10.0.0.1", port=9999
    ) is None


def test_tls_antiguo_y_cifrado_debil_son_evidencia_confirmada():
    resultado = finding_from_script(
        script("ssl-enum-ciphers", "TLSv1.0:\n  ciphers:\nleast strength: C"),
        host="10.0.0.1", port=443, service="https",
    )
    assert resultado is not None
    assert resultado.severity == Severity.MEDIUM
    assert resultado.assessment == Assessment.CONFIRMED


def test_certificado_caducado_genera_hallazgo_confirmado():
    cert = ScriptResult(
        id="ssl-cert", output="Subject: CN=demo",
        elements={"validity.notAfter": "2000-01-01T00:00:00Z"},
    )
    resultado = finding_from_script(cert, host="10.0.0.1", port=443, service="https")
    assert resultado is not None
    assert resultado.title == "Certificado TLS caducado"
    assert resultado.severity == Severity.HIGH
    assert resultado.confirmed is True


def test_certificado_lejano_sigue_siendo_descriptivo():
    cert = ScriptResult(
        id="ssl-cert", output="Subject: CN=demo",
        elements={"validity.notAfter": "2999-01-01T00:00:00Z"},
    )
    assert finding_from_script(cert, host="10.0.0.1", port=443) is None


def test_analisis_completo_del_xml(nmap_xml):
    hallazgos = analyze(parse_string(nmap_xml), target_is_private=True)
    titulos = [f.title for f in hallazgos]

    assert "MS17-010" in " ".join(titulos) or any("ms17" in t.lower() for t in titulos)
    assert any("Telnet" in t for t in titulos)
    assert any("OpenSSH" in t for t in titulos)
    assert any("Samba" in t for t in titulos)
    # ssl-heartbleed dijo NOT VULNERABLE: no debe aparecer.
    assert not any("heartbleed" in t.lower() for t in titulos)
    # Ordenado de mas grave a menos.
    severidades = [int(f.severity) for f in hallazgos]
    assert severidades == sorted(severidades, reverse=True)


def test_objetivo_publico_agrava_la_exposicion(nmap_xml):
    run = parse_string(nmap_xml)
    privado = {f.source: f.severity for f in analyze(run, target_is_private=True)}
    publico = {f.source: f.severity for f in analyze(run, target_is_private=False)}
    assert publico["rule:telnet-claro"] > privado["rule:telnet-claro"]


def test_resumen_y_puntuacion(nmap_xml):
    hallazgos = analyze(parse_string(nmap_xml), target_is_private=True)
    counts = summarize(hallazgos)
    assert set(counts) == {"critical", "high", "medium", "low", "info"}
    assert sum(counts.values()) == len(hallazgos)

    puntuacion = risk_score(hallazgos)
    assert 0 < puntuacion <= 100
    assert risk_score([]) == 0


def test_la_puntuacion_satura():
    """Muchos hallazgos medios no deben empatar con varias criticas ni pasarse de 100."""
    from medscan.models import Finding

    criticos = [
        Finding(title=f"c{i}", severity=Severity.CRITICAL, source="t", host="h")
        for i in range(20)
    ]
    assert risk_score(criticos) <= 100
