"""Exportacion estructurada de resultados.

El informe HTML esta pensado para lectura humana. Este modulo produce artefactos
estables para automatizar entregables: JSON completo del escaneo y CSV de
hallazgos para hojas de calculo.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unicodedata
import zipfile
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from . import attack_paths, db, report
from .config import raw_dir
from .models import Assessment, Severity

SCHEMA_VERSION = 1
MAX_BUNDLE_ARTIFACT_BYTES = 2_000_000


def _loads(raw: str | None, fallback: Any) -> Any:
    try:
        return json.loads(raw or "")
    except (json.JSONDecodeError, TypeError):
        return fallback


def _row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return dict(row)


def _value(value: Any) -> Any:
    if isinstance(value, sqlite3.Row):
        return exportable_row(value)
    if isinstance(value, dict):
        return {str(k): _value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_value(item) for item in value]
    return value


def exportable_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Convierte una fila de SQLite en dict JSON-friendly."""
    return {key: _value(value) for key, value in _row(row).items()}


def _scan_or_raise(scan_id: int) -> sqlite3.Row:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    return scan


def scan_payload(scan_id: int) -> dict[str, Any]:
    with db.read_snapshot():
        return _scan_payload(scan_id)


def _scan_payload(scan_id: int) -> dict[str, Any]:
    """Devuelve todo lo relevante de un escaneo en una estructura JSON estable."""
    scan = _scan_or_raise(scan_id)
    hosts = []
    for host, ports in db.hosts_with_ports(scan_id):
        host_data = exportable_row(host)
        host_data["hostnames"] = _loads(host_data.get("hostnames"), [])
        host_data["extraports"] = _loads(host_data.get("extraports"), {})
        host_data["ports"] = []
        for port in ports:
            port_data = exportable_row(port)
            port_data["cpes"] = _loads(port_data.get("cpes"), [])
            port_data["scripts"] = _loads(port_data.get("scripts"), [])
            host_data["ports"].append(port_data)
        hosts.append(host_data)

    findings = []
    for finding in db.get_findings(scan_id):
        item = exportable_row(finding)
        severity = Severity(int(item["severity"]))
        item["severity_label"] = severity.label
        item["severity_slug"] = severity.slug
        item["assessment_label"] = Assessment(item["assessment"]).label
        item["cves"] = _loads(item.get("cves"), [])
        findings.append(item)

    controls = []
    for control in db.get_control_results(scan_id):
        item = exportable_row(control)
        item["references"] = _loads(item.pop("references_json", "[]"), [])
        controls.append(item)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "scan": exportable_row(scan),
        "observation": _loads(scan["execution_context"], {}),
        "delta": db.scan_delta(scan_id),
        "summary": {
            "severity_counts": db.severity_counts(scan_id),
            "hosts": scan["hosts_total"],
            "hosts_up": scan["hosts_up"],
            "open_ports": sum(
                1
                for host in hosts
                for port in host["ports"]
                if port.get("state") == "open"
            ),
            "findings": len(findings),
            "risk_score": scan["risk_score"],
        },
        "hosts": hosts,
        "findings": findings,
        "cve_candidates": [exportable_row(row) for row in db.get_cve_candidates(scan_id)],
        "exploitdb_results": [
            exportable_row(row) for row in db.get_exploitdb_results(scan_id)
        ],
        "metasploit_results": [exportable_row(row) for row in db.get_msf_results(scan_id)],
        "exploit_runs": [exportable_row(row) for row in db.get_exploit_runs(scan_id)],
        "attack_paths": _value(attack_paths.build(scan_id)),
        "controls": controls,
        "inventories": db.get_host_inventories(scan_id),
        "windows_patch_statuses": [
            exportable_row(row) for row in db.get_windows_patch_statuses(scan_id)
        ],
        "windows_patch_candidates": [
            exportable_row(row) for row in db.get_windows_patch_candidates(scan_id)
        ],
        "enrichment": {
            kind: exportable_row(row)
            for kind, row in db.get_enrichment_statuses(scan_id).items()
        },
    }
    return payload


def render_json(scan_id: int, *, payload: dict[str, Any] | None = None) -> str:
    """JSON legible y determinista para guardar en disco o adjuntar."""
    return json.dumps(payload if payload is not None else scan_payload(scan_id), ensure_ascii=False, indent=2) + "\n"


def _spreadsheet_cell(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    probe = value
    while probe and (probe[0].isspace() or unicodedata.category(probe[0]) in {"Cc", "Cf"}):
        probe = probe[1:]
    return "'" + value if probe.startswith(("=", "+", "-", "@")) else value


def render_findings_csv(scan_id: int, *, payload: dict[str, Any] | None = None) -> str:
    """CSV de hallazgos, compatible con Excel/LibreOffice."""
    payload = payload if payload is not None else scan_payload(scan_id)
    out = io.StringIO(newline="")
    fields = [
        "scan_id",
        "host",
        "port",
        "protocol",
        "service",
        "severity",
        "severity_label",
        "assessment",
        "title",
        "source",
        "cves",
        "cvss",
        "evidence",
        "remediation",
    ]
    writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for finding in payload["findings"]:
        row = dict(finding)
        row["severity_label"] = Severity(int(row["severity"])).label
        row["cves"] = ";".join(row.get("cves", []))
        writer.writerow({key: _spreadsheet_cell(value) for key, value in row.items()})
    return out.getvalue()


def render_bundle(scan_id: int, *, max_artifact_bytes: int = MAX_BUNDLE_ARTIFACT_BYTES) -> bytes:
    """ZIP de entrega: informe HTML, JSON, CSV y artefactos MSF preparados."""
    with tempfile.SpooledTemporaryFile(max_size=1_000_000, mode="w+b") as out:
        _write_bundle(scan_id, out, max_artifact_bytes=max_artifact_bytes)
        out.seek(0)
        return out.read()


def write_bundle(scan_id: int, destination: Path,
                 *, max_artifact_bytes: int = MAX_BUNDLE_ARTIFACT_BYTES) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w+b") as out:
        _write_bundle(scan_id, out, max_artifact_bytes=max_artifact_bytes)
    return destination


def spool_bundle(scan_id: int) -> Path:
    """Managed temporary ZIP; the caller removes it after the response finishes."""
    base = raw_dir() / "exports"
    base.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="bundle-", suffix=".zip", dir=base)
    path = Path(name)
    try:
        with os.fdopen(fd, "w+b") as out:
            _write_bundle(scan_id, out)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def _write_bundle(scan_id: int, out,
                  *, max_artifact_bytes: int = MAX_BUNDLE_ARTIFACT_BYTES) -> None:
    payload = scan_payload(scan_id)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        prefix = f"scopescan-{scan_id:05d}"
        zf.writestr(f"{prefix}/report.html", report.render_report(scan_id, payload=payload))
        zf.writestr(f"{prefix}/scan.json", render_json(scan_id, payload=payload))
        zf.writestr(f"{prefix}/findings.csv", render_findings_csv(scan_id, payload=payload))
        artifact_errors = []
        for artifact in _metasploit_artifacts(scan_id, runs=payload["exploit_runs"]):
            try:
                _write_limited_artifact(zf, artifact, f"{prefix}/metasploit/{artifact.name}",
                                        max_bytes=max_artifact_bytes)
            except OSError as exc:
                artifact_errors.append({"name": artifact.name, "error": type(exc).__name__})
        entries = []
        for name in zf.namelist():
            digest = hashlib.sha256()
            with zf.open(name) as source:
                for chunk in iter(lambda: source.read(65536), b""):
                    digest.update(chunk)
            entries.append({"path": name, "sha256": digest.hexdigest(),
                            "bytes": zf.getinfo(name).file_size})
        manifest = evidence_manifest(payload, entries)
        manifest["artifact_errors"] = artifact_errors
        zf.writestr(f"{prefix}/manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))


def _write_limited_artifact(
    zf: zipfile.ZipFile, path: Path, arcname: str, *, max_bytes: int
) -> None:
    """Incluye un artefacto sin permitir ZIPs enormes por logs gigantes."""
    size = path.stat().st_size
    if max_bytes <= 0 or size <= max_bytes:
        with path.open("rb") as source, zf.open(arcname, "w") as target:
            shutil.copyfileobj(source, target, length=65536)
        return
    with path.open("rb") as fh:
        chunk = fh.read(max_bytes)
    note = (
        f"\n\n[scopescan] Artefacto truncado para el bundle: "
        f"{size} bytes originales, {max_bytes} bytes incluidos.\n"
    ).encode()
    zf.writestr(arcname, chunk + note)


def _metasploit_artifacts(scan_id: int, *, runs: list[dict[str, Any]] | None = None) -> list[Path]:
    """Devuelve solo `.rc`/logs pertenecientes al raw_dir gestionado por scopescan."""
    base = raw_dir().resolve()
    artifacts: list[Path] = []
    seen: set[Path] = set()
    for run in runs if runs is not None else db.get_exploit_runs(scan_id):
        for key in ("rc_path", "log_path"):
            raw_path = str(run[key] or "").strip()
            if not raw_path:
                continue
            path = Path(raw_path).expanduser()
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved in seen or not resolved.is_file():
                continue
            try:
                resolved.relative_to(base)
            except ValueError:
                continue
            artifacts.append(resolved)
            seen.add(resolved)
    return artifacts


def evidence_manifest(payload: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        application_version = version("scopescan")
    except PackageNotFoundError:
        application_version = "unknown"
    scan = payload["scan"]
    return {
        "schema_version": 1,
        "scan_id": scan["id"],
        "generated_at": datetime.now(UTC).isoformat(),
        "application": {"name": "ScopeScan", "version": application_version},
        "scan": {key: scan.get(key) for key in ("created_at", "started_at", "finished_at",
                                                "status", "profile", "targets", "nmap_args", "raw_xml_path")},
        "enrichment": payload["enrichment"],
        "coverage": {"hosts": payload["summary"]["hosts"],
                     "inventoried_hosts": sorted(payload["inventories"]),
                     "missing": ["engine and feed versions unavailable in legacy scans",
                                 "artifact timestamps unavailable when not recorded"]},
        "artifacts": entries,
        "hash_algorithm": "sha256",
        "note": "Hashes identify included bytes. Truncated artifacts carry an explicit marker.",
    }
