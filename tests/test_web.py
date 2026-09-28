"""Pruebas del panel. La cola se sustituye por un doble: aqui no se lanza nmap."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from medscan import analysis, db
from medscan.nmap_parser import parse_string
from medscan.web import app as web_app


class ColaFalsa:
    def __init__(self) -> None:
        self.enviados: list[int] = []
        self.cancelados: list[int] = []

    def submit(self, scan_id: int) -> None:
        self.enviados.append(scan_id)

    def cancel(self, scan_id: int) -> bool:
        self.cancelados.append(scan_id)
        return True

    def is_active(self, scan_id: int) -> bool:
        return scan_id in self.enviados

    def active_ids(self) -> list[int]:
        return list(self.enviados)

    def shutdown(self, wait: bool = False) -> None:
        pass


@pytest.fixture
def cola(monkeypatch):
    doble = ColaFalsa()
    monkeypatch.setattr(web_app, "QUEUE", doble)
    return doble


@pytest.fixture
def client(cola):
    with TestClient(web_app.app, client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def test_panel_vacio(client):
    respuesta = client.get("/")
    assert respuesta.status_code == 200
    assert "Todavia no hay escaneos" in respuesta.text


def test_panel_rechaza_cliente_remoto():
    remote = TestClient(web_app.app, client=("203.0.113.10", 50000))
    assert remote.get("/").status_code == 403


def test_formulario_de_nuevo_escaneo(client):
    respuesta = client.get("/scans/new")
    assert respuesta.status_code == 200
    assert "vulnerabilidades" in respuesta.text
    assert "autorizacion" in respuesta.text


def test_lanzar_escaneo_encola(client, cola):
    respuesta = client.post(
        "/scans",
        data={"targets": "192.168.1.10", "profile": "rapido", "authorized": "1"},
        follow_redirects=False,
    )
    assert respuesta.status_code == 303
    assert len(cola.enviados) == 1
    scan_id = cola.enviados[0]
    assert db.get_scan(scan_id)["targets"] == "192.168.1.10"


def test_sin_marcar_la_autorizacion_no_se_lanza(client, cola):
    respuesta = client.post("/scans", data={"targets": "192.168.1.10", "profile": "rapido"})
    assert respuesta.status_code == 400
    assert "autorizacion" in respuesta.text
    assert cola.enviados == []


def test_objetivo_invalido_devuelve_el_formulario(client, cola):
    respuesta = client.post(
        "/scans", data={"targets": "-oX /tmp/x", "profile": "rapido", "authorized": "1"}
    )
    assert respuesta.status_code == 400
    assert cola.enviados == []


def test_rango_enorme_se_frena_sin_force(client, cola):
    respuesta = client.post(
        "/scans", data={"targets": "10.0.0.0/8", "profile": "rapido", "authorized": "1"}
    )
    assert respuesta.status_code == 400
    assert "limite" in respuesta.text
    assert cola.enviados == []


def test_vista_previa(client):
    respuesta = client.post("/api/preview", data={"targets": "192.168.1.0/24", "profile": "rapido"})
    datos = respuesta.json()
    assert datos["ok"] is True
    assert datos["hosts"] == 256
    assert datos["private"] is True


def test_vista_previa_con_error(client):
    datos = client.post("/api/preview", data={"targets": "--script=vuln"}).json()
    assert datos["ok"] is False
    assert "error" in datos


def test_detalle_y_estado(client, nmap_xml):
    scan_id = db.create_scan(name="p", targets="192.168.1.10", profile="vulnerabilidades")
    run = parse_string(nmap_xml)
    hallazgos = analysis.analyze(run, target_is_private=True)
    db.save_results(scan_id, run, hallazgos, analysis.risk_score(hallazgos))
    db.set_status(scan_id, "done")

    detalle = client.get(f"/scans/{scan_id}")
    assert detalle.status_code == 200
    assert "192.168.1.10" in detalle.text
    assert "OpenSSH" in detalle.text
    assert "Telnet" in detalle.text

    estado = client.get(f"/api/scans/{scan_id}/status").json()
    assert estado["status"] == "done"
    assert estado["counts"]["high"] >= 1

    informe = client.get(f"/scans/{scan_id}/report")
    assert informe.status_code == 200
    assert "Informe de escaneo" in informe.text


def test_filtro_de_severidad_en_el_detalle(client, nmap_xml):
    scan_id = db.create_scan(name="p", targets="192.168.1.10", profile="vulnerabilidades")
    run = parse_string(nmap_xml)
    hallazgos = analysis.analyze(run, target_is_private=True)
    db.save_results(scan_id, run, hallazgos, analysis.risk_score(hallazgos))

    solo_criticas = client.get(f"/scans/{scan_id}?min_severity=4")
    assert solo_criticas.status_code == 200


def test_escaneo_inexistente(client):
    assert client.get("/scans/9999").status_code == 404
    assert client.get("/api/scans/9999/status").status_code == 404


def test_borrar_escaneo(client, cola):
    scan_id = db.create_scan(name="p", targets="10.0.0.1", profile="rapido")
    respuesta = client.post(f"/scans/{scan_id}/delete", follow_redirects=False)
    assert respuesta.status_code == 303
    assert db.get_scan(scan_id) is None


def test_repetir_desde_el_panel(client, cola):
    scan_id = db.create_scan(name="p", targets="10.0.0.1", profile="rapido")
    respuesta = client.post(f"/scans/{scan_id}/rerun", follow_redirects=False)
    assert respuesta.status_code == 303
    assert len(cola.enviados) == 1
    assert cola.enviados[0] != scan_id


def test_vista_de_hallazgos(client, nmap_xml):
    scan_id = db.create_scan(name="p", targets="192.168.1.10", profile="vulnerabilidades")
    run = parse_string(nmap_xml)
    hallazgos = analysis.analyze(run, target_is_private=True)
    db.save_results(scan_id, run, hallazgos, analysis.risk_score(hallazgos))

    respuesta = client.get("/findings?min_severity=3")
    assert respuesta.status_code == 200
    assert "Telnet" in respuesta.text


def test_enriquecimiento_y_inventario_visibles(client, monkeypatch, nmap_xml):
    scan_id = db.create_scan(name="p", targets="192.168.1.10", profile="rapido")
    db.save_results(scan_id, parse_string(nmap_xml), [], 0)
    db.set_status(scan_id, "done")

    firmware_choices = []

    def fake_enrich(_scan_id, *, include_firmware=False):
        firmware_choices.append(include_firmware)
        db.replace_cve_candidates(_scan_id, [{
            "host": "192.168.1.10", "port": 22, "protocol": "tcp",
            "detected_cpe": "cpe:/a:openbsd:openssh:6.6.1p1",
            "queried_cpe": "cpe:2.3:a:openbsd:openssh:6.6.1p1:*:*:*:*:*:*:*",
            "cve_id": "CVE-2024-12345", "cvss": 7.5, "summary": "Example",
        }])
        return 1

    def fake_inventory(_scan_id, *, host, local):
        db.save_host_inventory(_scan_id, host, {
            "os_name": "Windows", "os_version": "10.0", "os_build": "22631", "ubr": 1,
            "bios_version": "1.2", "intel_me_firmware": "16.1.42.2872", "intel_me_note": None,
            "updates": [{"kb": "KB123"}], "software": [], "updates_note": None,
        }, "test")
        return 1

    monkeypatch.setattr(web_app.nvd, "enrich_scan", fake_enrich)
    monkeypatch.setattr(web_app.windows_inventory, "inventory_scan", fake_inventory)
    assert client.post(f"/scans/{scan_id}/enrich/nvd", follow_redirects=False).status_code == 303
    assert client.post(f"/scans/{scan_id}/inventory/windows", data={
        "host": "192.168.1.10",
    }, follow_redirects=False).status_code == 303
    detail = client.get(f"/scans/{scan_id}").text
    assert 'name="include_firmware"' in detail
    assert firmware_choices == [False]
    assert client.post(f"/scans/{scan_id}/enrich/nvd", data={
        "include_firmware": "1",
    }, follow_redirects=False).status_code == 303
    assert firmware_choices == [False, True]
    assert "CVE-2024-12345" in detail
    assert "Posible afectacion" in detail
    assert "KB123" in detail
    assert "BIOS 1.2" in detail
    report = client.get(f"/scans/{scan_id}/report").text
    assert "CVE-2024-12345" in report
    assert "KB123" in report

    patch_calls = []

    def fake_patches(_scan_id):
        patch_calls.append(_scan_id)
        return 0

    monkeypatch.setattr(web_app.msrc, "assess_scan", fake_patches)
    assert client.post(f"/scans/{scan_id}/enrich/msrc", follow_redirects=False).status_code == 303
    assert patch_calls == [scan_id]


def test_inventario_linux_desde_panel(client, monkeypatch, nmap_xml):
    scan_id = db.create_scan(name="linux", targets="192.168.1.10", profile="rapido")
    db.save_results(scan_id, parse_string(nmap_xml), [], 0)
    db.set_status(scan_id, "done")
    calls = []

    def fake_inventory(_scan_id, *, host, user, port, local):
        calls.append((host, user, port, local))
        db.save_host_inventory(_scan_id, host, {
            "platform": "linux", "os_name": "Debian GNU/Linux", "os_version": "12",
            "os_id": "debian", "kernel": "6.1.0", "packages": [], "sshd": None,
            "firewall": {"observed": True, "active": True}, "aslr": 2,
            "selinux": None, "apparmor": "y",
        }, "test")
        return 1

    monkeypatch.setattr(web_app.linux_inventory, "inventory_scan", fake_inventory)
    response = client.post(f"/scans/{scan_id}/inventory/linux", data={
        "host": "192.168.1.10", "user": "audit", "port": "2222",
    }, follow_redirects=False)
    assert response.status_code == 303
    assert calls == [("192.168.1.10", "audit", 2222, False)]
    detail = client.get(f"/scans/{scan_id}").text
    assert "Inventario Linux autenticado" in detail
    assert "Debian GNU/Linux" in detail
