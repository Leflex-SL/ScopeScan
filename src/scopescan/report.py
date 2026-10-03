"""Informe HTML autocontenido de un escaneo.

Sin CSS externo ni JavaScript: el informe se adjunta en un correo o se entrega
como evidencia, y tiene que verse igual en cualquier maquina y dentro de diez
anos, cuando este servidor ya no exista.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import attack_paths, db, nvd
from .models import Assessment, Severity

TEMPLATE_DIR = Path(__file__).resolve().parent / "web" / "templates"


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.globals["severity_label"] = lambda value: Severity(int(value)).label
    env.globals["severity_slug"] = lambda value: Severity(int(value)).slug
    env.globals["assessment_label"] = lambda value: Assessment(value).label
    env.globals["nvd_match_note"] = nvd.match_note
    return env


def _cves(raw: str | None) -> list[str]:
    try:
        return json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []


def render_report(scan_id: int) -> str:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"No existe el escaneo {scan_id}")

    findings = db.get_findings(scan_id)
    counts = db.severity_counts(scan_id)
    hosts = db.hosts_with_ports(scan_id)

    # Resumen ejecutivo: los hallazgos que de verdad hay que mirar hoy.
    prioritarios = [
        f for f in findings
        if f["severity"] >= int(Severity.HIGH) and f["assessment"] != "candidate"
    ]

    template = _environment().get_template("report.html")
    return template.render(
        scan=scan,
        findings=findings,
        prioritarios=prioritarios,
        counts=counts,
        hosts=hosts,
        attack_paths=attack_paths.build(scan_id),
        candidates=db.get_cve_candidates(scan_id),
        exploitdb_results=db.get_exploitdb_results(scan_id),
        exploit_runs=db.get_exploit_runs(scan_id),
        controls=db.get_control_results(scan_id),
        patch_statuses=db.get_windows_patch_statuses(scan_id),
        patch_candidates=db.get_windows_patch_candidates(scan_id),
        inventories=db.get_host_inventories(scan_id),
        json=json,
        cves=_cves,
        scripts=db.row_scripts,
        hostnames=db.row_list,
        # Hora local a proposito: el informe lo lee una persona en su huso.
        generated=datetime.now().strftime("%d/%m/%Y %H:%M"),  # noqa: DTZ005
        total_open=sum(len(ports) for _host, ports in hosts),
    )


def write_report(scan_id: int, destination: Path) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_report(scan_id), encoding="utf-8")
    return destination
