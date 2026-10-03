"""Orquestacion de un escaneo completo: validar, lanzar, parsear, analizar, guardar."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import analysis, db, nmap_parser, nmap_runner
from .config import MAX_HOSTS_DEFAULT, NmapNotFound, is_privileged, raw_dir, scan_timeout
from .models import Finding, NmapRun
from .profiles import DEFAULT_PROFILE, get_profile
from .targets import InvalidTarget, TargetSet, parse_targets


@dataclass
class ScanRequest:
    targets: str
    profile: str = DEFAULT_PROFILE
    name: str = ""
    authorized_by: str = ""
    notes: str = ""
    force: bool = False
    max_hosts: int = MAX_HOSTS_DEFAULT


@dataclass
class PreparedScan:
    request: ScanRequest
    target_set: TargetSet
    argv_preview: list[str]
    warnings: list[str]


def prepare(request: ScanRequest) -> PreparedScan:
    """Valida el encargo y calcula que se va a ejecutar, sin lanzarlo todavia.

    Separar esto de la ejecucion permite que el panel enseñe el comando exacto y
    los avisos antes de que el usuario confirme.
    """
    target_set = parse_targets(request.targets, max_hosts=request.max_hosts, force=request.force)
    profile = get_profile(request.profile)
    privileged = is_privileged()

    warnings = list(target_set.warnings) + profile.warnings(privileged=privileged)

    try:
        argv = nmap_runner.build_argv(
            targets=target_set.argv,
            profile_args=profile.nmap_args(privileged=privileged),
            xml_path=Path("<salida>.xml"),
        )
    except NmapNotFound as exc:
        warnings.append(str(exc))
        argv = []

    return PreparedScan(
        request=request, target_set=target_set, argv_preview=argv, warnings=warnings
    )


def queue_scan(request: ScanRequest) -> int:
    """Crea la fila del escaneo en estado 'queued' y devuelve su id."""
    prepared = prepare(request)
    name = request.name.strip() or f"{prepared.target_set.raw} ({request.profile})"
    return db.create_scan(
        name=name,
        targets=prepared.target_set.raw,
        profile=request.profile,
        target_private=prepared.target_set.all_private,
        authorized_by=request.authorized_by,
        notes=request.notes,
    )


def execute(scan_id: int, *, cancel: threading.Event | None = None) -> None:
    """Ejecuta un escaneo ya encolado. Pensado para correr en un hilo aparte.

    No propaga excepciones: cualquier fallo se registra en la fila del escaneo,
    porque el unico sitio donde el usuario lo va a ver es el panel.
    """
    row = db.get_scan(scan_id)
    if row is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    if cancel is not None and cancel.is_set():
        db.set_status(scan_id, "cancelled", error="Cancelado antes de empezar")
        return
    if not db.claim_scan_execution(scan_id):
        return

    try:
        target_set = parse_targets(row["targets"], force=True)
        profile = get_profile(row["profile"])
    except (InvalidTarget, KeyError) as exc:
        db.set_status(scan_id, "failed", error=str(exc))
        return

    # Hora local: el nombre del XML se lee a ojo al buscarlo en disco.
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")  # noqa: DTZ005
    xml_path = raw_dir() / f"scan-{scan_id:05d}-{stamp}.xml"

    try:
        argv = nmap_runner.build_argv(
            targets=target_set.argv,
            profile_args=profile.nmap_args(privileged=is_privileged()),
            xml_path=xml_path,
        )
    except NmapNotFound as exc:
        db.set_status(scan_id, "failed", error=str(exc))
        return

    db.set_nmap_args(scan_id, " ".join(argv), str(xml_path))
    db.set_status(scan_id, "running")
    db.set_progress(scan_id, 0, "Iniciando nmap")

    def on_progress(percent: float, task: str) -> None:
        # -1 significa "sin porcentaje todavia": se conserva el ultimo conocido.
        if percent < 0:
            current = db.get_scan(scan_id)
            percent = float(current["progress"]) if current else 0.0
        db.set_progress(scan_id, percent, task)

    try:
        execution = nmap_runner.run(argv, progress=on_progress, cancel=cancel,
                                    timeout=scan_timeout())
    except OSError as exc:
        db.set_status(scan_id, "failed", error=f"No se pudo lanzar nmap: {exc}")
        return

    _store(scan_id, execution, target_private=bool(row["target_private"]))


def _store(scan_id: int, execution: nmap_runner.NmapExecution, *, target_private: bool) -> None:
    """Parsea el XML, analiza y guarda. El XML parcial de un escaneo cancelado
    tambien se aprovecha: lo escaneado hasta ese momento es informacion valida."""
    run: NmapRun | None = None
    parse_error = ""
    if execution.xml_path.exists():
        try:
            run = nmap_parser.parse_file(execution.xml_path)
        except nmap_parser.NmapParseError as exc:
            parse_error = str(exc)

    if run is not None:
        findings: list[Finding] = analysis.analyze(run, target_is_private=target_private)
        db.save_results(scan_id, run, findings, analysis.risk_score(findings))

    if execution.cancelled:
        db.set_status(scan_id, "cancelled", error="Cancelado por el usuario")
        return

    if not execution.ok:
        db.set_status(scan_id, "failed", error=nmap_runner.explain_failure(execution))
        return

    if run is None:
        db.set_status(
            scan_id,
            "failed",
            error=parse_error or "nmap termino sin generar el XML de resultados",
        )
        return

    db.set_progress(scan_id, 100, "Completado")
    db.set_status(scan_id, "done")


def rerun(scan_id: int) -> int:
    """Encola de nuevo un escaneo con los mismos parametros. Devuelve el nuevo id."""
    row = db.get_scan(scan_id)
    if row is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    return db.create_scan(
        name=row["name"],
        targets=row["targets"],
        profile=row["profile"],
        target_private=bool(row["target_private"]),
        authorized_by=row["authorized_by"],
        notes=row["notes"],
    )
