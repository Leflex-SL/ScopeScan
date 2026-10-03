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

from . import db, nvd
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


def render_report(scan_id: int, *, payload: dict | None = None) -> str:
    # Import locally to avoid the export/report module cycle.
    from .export import scan_payload
    payload = payload if payload is not None else scan_payload(scan_id)
    scan = payload["scan"]
    findings = [dict(f, cves=json.dumps(f["cves"])) for f in payload["findings"]]
    hosts = []
    for host in payload["hosts"]:
        host = dict(host)
        ports = [dict(port, scripts=json.dumps(port["scripts"]), cpes=json.dumps(port["cpes"]))
                 for port in host.pop("ports")]
        host["hostnames"] = json.dumps(host["hostnames"])
        hosts.append((host, ports))
    prioritarios = [f for f in findings if f["severity"] >= int(Severity.HIGH)
                   and f["assessment"] != "candidate"]
    controls = [dict(item, references_json=json.dumps(item["references"]))
                for item in payload["controls"]]
    return _environment().get_template("report.html").render(
        scan=scan, findings=findings, prioritarios=prioritarios,
        counts=payload["summary"]["severity_counts"], hosts=hosts,
        attack_paths=payload["attack_paths"], candidates=payload["cve_candidates"],
        exploitdb_results=payload["exploitdb_results"], exploit_runs=payload["exploit_runs"],
        controls=controls, patch_statuses=payload["windows_patch_statuses"],
        patch_candidates=payload["windows_patch_candidates"], inventories=payload["inventories"],
        json=json, cves=_cves, scripts=db.row_scripts, hostnames=db.row_list,
        generated=datetime.now().strftime("%d/%m/%Y %H:%M"),  # noqa: DTZ005
        observation=payload.get("observation", {}), delta=payload.get("delta", {}),
        total_open=sum(len(ports) for _host, ports in hosts),
    )


def write_report(scan_id: int, destination: Path) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_report(scan_id), encoding="utf-8")
    return destination
