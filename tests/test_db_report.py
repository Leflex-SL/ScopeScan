from __future__ import annotations

from pathlib import Path

from medscan import analysis, db, report, service
from medscan.models import Severity
from medscan.nmap_parser import parse_string
from medscan.nmap_runner import NmapExecution, build_argv, explain_failure


def escaneo_guardado(nmap_xml: str, *, private: bool = True) -> int:
    scan_id = db.create_scan(
        name="prueba", targets="192.168.1.10", profile="vulnerabilidades",
        target_private=private, authorized_by="Hugo",
    )
    run = parse_string(nmap_xml)
    hallazgos = analysis.analyze(run, target_is_private=private)
    db.save_results(scan_id, run, hallazgos, analysis.risk_score(hallazgos))
    db.set_status(scan_id, "done")
    return scan_id


def test_ciclo_completo_en_bd(nmap_xml):
    scan_id = escaneo_guardado(nmap_xml)
    scan = db.get_scan(scan_id)
    assert scan is not None
    assert scan["status"] == "done"
    assert scan["hosts_up"] == 1
    assert scan["risk_score"] > 0

    hosts = db.hosts_with_ports(scan_id)
    assert len(hosts) == 2  # uno vivo y uno caido
    vivo = next(h for h, _ in hosts if h["state"] == "up")
    puertos = dict(hosts)[vivo]
    assert [p["portid"] for p in puertos] == [22, 23, 443, 445]


def test_solo_se_guardan_puertos_abiertos_en_la_vista(nmap_xml):
    scan_id = escaneo_guardado(nmap_xml)
    abiertos = db.get_ports(scan_id, only_open=True)
    todos = db.get_ports(scan_id, only_open=False)
    assert sum(len(v) for v in abiertos.values()) == 4
    assert sum(len(v) for v in todos.values()) == 5


def test_filtro_por_severidad(nmap_xml):
    scan_id = escaneo_guardado(nmap_xml)
    todos = db.get_findings(scan_id)
    altos = db.get_findings(scan_id, min_severity=int(Severity.HIGH))
    assert len(altos) < len(todos)
    assert all(f["severity"] >= int(Severity.HIGH) for f in altos)


def test_recuento_por_severidad(nmap_xml):
    scan_id = escaneo_guardado(nmap_xml)
    counts = db.severity_counts(scan_id)
    assert sum(counts.values()) == len(db.get_findings(scan_id))


def test_estadisticas_globales(nmap_xml):
    escaneo_guardado(nmap_xml)
    stats = db.global_stats()
    assert stats["scans"] == 1
    assert stats["hosts"] == 1
    assert stats["open_ports"] == 4


def test_borrado_en_cascada(nmap_xml):
    scan_id = escaneo_guardado(nmap_xml)
    db.delete_scan(scan_id)
    assert db.get_scan(scan_id) is None
    assert db.get_findings(scan_id) == []
    assert db.get_hosts(scan_id) == []


def test_escaneos_colgados_se_cierran(nmap_xml):
    scan_id = db.create_scan(name="colgado", targets="10.0.0.1", profile="rapido")
    db.set_status(scan_id, "running")
    assert db.reset_stale_scans() == 1
    row = db.get_scan(scan_id)
    assert row["status"] == "failed"
    assert "Interrumpido" in row["error"]


def test_repetir_escaneo_conserva_parametros(nmap_xml):
    scan_id = escaneo_guardado(nmap_xml)
    nuevo = service.rerun(scan_id)
    assert nuevo != scan_id
    original, copia = db.get_scan(scan_id), db.get_scan(nuevo)
    assert copia["targets"] == original["targets"]
    assert copia["profile"] == original["profile"]
    assert copia["status"] == "queued"


def test_informe_html(nmap_xml, tmp_path):
    scan_id = escaneo_guardado(nmap_xml)
    html = report.render_report(scan_id)

    assert "<!doctype html>" in html.lower()
    assert "192.168.1.10" in html
    assert "Telnet" in html
    assert "nvd.nist.gov" in html  # enlaza los CVE detectados
    assert "Hugo" in html  # consta quien autorizo
    assert "no demuestra que el sistema sea seguro" in html  # limitaciones declaradas

    destino = report.write_report(scan_id, tmp_path / "informe.html")
    assert Path(destino).read_text(encoding="utf-8") == html


def test_argv_de_nmap_pone_los_objetivos_al_final(tmp_path):
    argv = build_argv(
        targets=["192.168.1.10"],
        profile_args=["-T4", "-sS", "-p-"],
        xml_path=tmp_path / "s.xml",
        nmap_path="nmap",
    )
    assert argv[0] == "nmap"
    assert argv[-1] == "192.168.1.10"
    assert argv[argv.index("-oX") + 1] == str(tmp_path / "s.xml")
    assert "--stats-every" in argv


def test_mensajes_de_error_accionables(tmp_path):
    ejecucion = NmapExecution(
        argv=["nmap"], xml_path=tmp_path / "s.xml", returncode=1,
        stdout="", stderr="You requested a scan type which requires root privileges.",
    )
    assert "administrador" in explain_failure(ejecucion)
