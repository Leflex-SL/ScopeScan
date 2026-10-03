"""Bounded evidence imports. External data never becomes execution instructions."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import analysis, db, nmap_parser
from .config import raw_dir
from .models import Assessment, Finding, Host, NmapRun, Port, Service, Severity
from .targets import parse_target
from .verification import enrich_coverage

EXTERNAL_SCHEMA = "scopescan.external.v1"
MAX_IMPORT_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 10000
MAX_CLOCK_SKEW = timedelta(minutes=5)
_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_.:-]{1,160}$")


class ImportError(ValueError):
    """An external document violates the evidence contract."""


def _read(path: str | Path) -> bytes:
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_IMPORT_BYTES:
        raise ImportError("El resultado debe ser un fichero de hasta 32 MiB")
    with path.open("rb") as stream:
        data = stream.read(MAX_IMPORT_BYTES + 1)
    if len(data) > MAX_IMPORT_BYTES:
        raise ImportError("El resultado supera 32 MiB")
    return data


def _copy_raw(data: bytes, suffix: str) -> tuple[Path, str]:
    digest = hashlib.sha256(data).hexdigest()
    path = raw_dir() / f"import-{uuid.uuid4().hex}-{digest[:16]}{suffix}"
    # Exclusive creation and no source path reuse; imports cannot overwrite managed evidence.
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o444)
    return path, digest


def _timestamp(value) -> str:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            parsed = datetime.fromtimestamp(value, UTC)
        else:
            parsed = datetime.fromisoformat(str(value))
            if parsed.tzinfo is None:
                raise ValueError("falta zona horaria")
        normalized = parsed.astimezone(UTC)
        if normalized > datetime.now(UTC) + MAX_CLOCK_SKEW:
            raise ImportError("La fecha del resultado esta mas de cinco minutos en el futuro; "
                              "corrige el reloj o la fecha del documento antes de importarlo")
        return normalized.isoformat()
    except ImportError:
        raise
    except (ValueError, OverflowError, OSError) as exc:
        raise ImportError("observed_at debe ser una fecha ISO-8601 con zona horaria") from exc


def _text(value, *, limit: int = 16000) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ImportError(f"Texto invalido o superior a {limit} caracteres")
    return value


def _records(value) -> list:
    if not isinstance(value, list) or len(value) > MAX_RECORDS:
        raise ImportError(f"La coleccion debe tener como maximo {MAX_RECORDS} elementos")
    return value


def _host(value) -> str:
    if not isinstance(value, str):
        raise ImportError("Los hosts externos deben ser direcciones IP expresadas como texto")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ImportError("Los resultados externos deben identificar hosts por IP") from exc


def _store(run: NmapRun, findings: list[Finding], data: bytes, suffix: str, *, name: str,
           namespace: str, authorized_by: str, provenance: dict) -> int:
    if not run.hosts:
        raise ImportError("El resultado no contiene hosts observados")
    if namespace and not _IDENTIFIER.fullmatch(namespace):
        raise ImportError("namespace invalido")
    raw_path, digest = _copy_raw(data, suffix)
    provenance.update({"imported": True, "source_timestamp": provenance["observed_at"],
                       "raw_path": str(raw_path), "sha256": digest,
                       "claim_status": "external_unverified"})
    run.provenance = provenance
    run.coverage["provenance"] = "external"
    for finding in findings:
        finding.confirmed = False
        finding.assessment = Assessment.CANDIDATE
        finding.evidence = "[Afirmacion externa; no verificada localmente] " + finding.evidence
    targets = " ".join(h.address for h in run.hosts)
    scan_id = db.create_scan(name=name or f"Importacion {provenance['engine']}", targets=targets,
                             profile="imported", authorized_by=authorized_by,
                             target_private=all(parse_target(h.address).private for h in run.hosts),
                             notes="Resultado externo importado; no es una orden de ejecucion")
    context = {"namespace": namespace or f"import:{scan_id}", "coverage": run.coverage,
               "observed_at": provenance["observed_at"], "provenance": provenance}
    db.set_scan_context(scan_id, execution_context=context)
    db.set_nmap_args(scan_id, "", str(raw_path))
    db.save_results(scan_id, run, findings, analysis.risk_score(findings))
    db.set_progress(scan_id, 100, "Importacion completada")
    db.set_status(scan_id, "done")
    return scan_id


def import_nmap(path: str | Path, *, name: str = "", namespace: str = "",
                authorized_by: str = "") -> int:
    data = _read(path)
    try:
        run = nmap_parser.parse_string(data.decode("utf-8"))
    except (UnicodeError, nmap_parser.NmapParseError) as exc:
        raise ImportError(str(exc)) from exc
    for host in run.hosts:
        host.address = _host(host.address)
    observed_at = _timestamp(run.start) if run.start else _timestamp(db.now())
    enrich_coverage(run)
    findings = analysis.analyze(run, target_is_private=all(parse_target(h.address).private
                                                        for h in run.hosts))
    provenance = {**run.provenance, "observed_at": observed_at, "format": "nmap.xml"}
    if not run.start:
        run.coverage["status"] = "unknown"
        provenance["timestamp_inferred"] = True
    return _store(run, findings, data, ".xml", name=name, namespace=namespace,
                  authorized_by=authorized_by, provenance=provenance)


def import_external_json(path: str | Path, *, name: str = "", namespace: str = "",
                         authorized_by: str = "") -> int:
    data = _read(path)
    try:
        document = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise ImportError("JSON externo ilegible") from exc
    if not isinstance(document, dict) or document.get("schema") != EXTERNAL_SCHEMA:
        raise ImportError(f"Se requiere schema={EXTERNAL_SCHEMA}")
    engine = _text(document.get("engine"), limit=160)
    if not _IDENTIFIER.fullmatch(engine):
        raise ImportError("Identificador engine invalido")
    version = _text(document.get("engine_version"), limit=160)
    if not version.strip():
        raise ImportError("engine_version debe indicar una version concreta")
    rules_version = _text(document.get("rules_version", ""), limit=160)
    observed_at = _timestamp(_text(document.get("observed_at"), limit=128))
    coverage = document.get("coverage")
    if (not isinstance(coverage, dict) or not isinstance(coverage.get("status"), str)
            or coverage["status"] not in {"complete", "partial", "unknown"}):
        raise ImportError("coverage.status debe ser complete, partial o unknown")
    protocols = coverage.get("protocols", {})
    if not isinstance(protocols, dict) or not set(protocols) <= {"tcp", "udp", "sctp", "ip"}:
        raise ImportError("coverage.protocols invalido")
    normalized_protocols = {}
    for protocol, ports in protocols.items():
        if isinstance(ports, str):
            try:
                ports = nmap_parser.parse_port_spec(ports)
            except nmap_parser.NmapParseError as exc:
                raise ImportError(str(exc)) from exc
        if not isinstance(ports, list) or len(ports) > 65536 \
                or any(type(p) is not int or not 0 <= p <= 65535 for p in ports):
            raise ImportError("Puertos de cobertura invalidos")
        normalized_protocols[protocol] = sorted(set(ports))
    run = NmapRun(scanner_version=version, exit_status="success",
                  start=int(datetime.fromisoformat(observed_at).timestamp()))
    total_endpoints = 0
    for record in _records(document.get("hosts", [])):
        if not isinstance(record, dict):
            raise ImportError("Host invalido")
        address = _host(record.get("address", ""))
        state = record.get("state", "unknown")
        if not isinstance(state, str) or state not in {"up", "down", "unknown", "skipped"}:
            raise ImportError("Estado de host invalido")
        host = Host(address=address, addrtype="ipv6" if ":" in address else "ipv4", state=state)
        for endpoint in _records(record.get("ports", [])):
            total_endpoints += 1
            if total_endpoints > MAX_RECORDS:
                raise ImportError(f"El resultado supera {MAX_RECORDS} endpoints")
            if not isinstance(endpoint, dict):
                raise ImportError("Endpoint invalido")
            port = endpoint.get("port")
            protocol = endpoint.get("protocol", "tcp")
            if (type(port) is not int or not 1 <= port <= 65535
                    or not isinstance(protocol, str) or protocol not in {"tcp", "udp", "sctp"}):
                raise ImportError("Puerto/protocolo invalido")
            service = endpoint.get("service", {})
            if not isinstance(service, dict):
                raise ImportError("Servicio invalido")
            if (not isinstance(endpoint.get("state", "unknown"), str)
                    or endpoint.get("state", "unknown") not in {"open", "closed", "filtered", "unfiltered",
                                                          "open|filtered", "closed|filtered", "unknown"}):
                raise ImportError("Estado de puerto invalido")
            host.ports.append(Port(portid=port, protocol=protocol,
                                   state=_text(endpoint.get("state", "unknown"), limit=64),
                                   service=Service(**{key: _text(service.get(key, ""), limit=1024)
                                                      for key in ("name", "product", "version",
                                                                  "extrainfo", "tunnel")})))
        run.hosts.append(host)
    addresses = {h.address for h in run.hosts}
    findings = []
    for record in _records(document.get("findings", [])):
        if not isinstance(record, dict):
            raise ImportError("Hallazgo invalido")
        host = _host(record.get("host", ""))
        rule_id = _text(record.get("rule_id"), limit=160)
        if host not in addresses or not _IDENTIFIER.fullmatch(rule_id):
            raise ImportError("Host o rule_id del hallazgo invalido")
        port = record.get("port")
        protocol = record.get("protocol", "tcp" if port is not None else "host")
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ImportError("Puerto del hallazgo invalido")
        if not isinstance(protocol, str) or protocol not in {"tcp", "udp", "sctp", "host"}:
            raise ImportError("Protocolo del hallazgo invalido")
        try:
            severity = Severity[record.get("severity", "info").upper()]
        except (KeyError, AttributeError) as exc:
            raise ImportError("severity invalida") from exc
        cvss = record.get("cvss")
        if cvss is not None and (type(cvss) not in {int, float} or not math.isfinite(cvss)
                                 or not 0 <= cvss <= 10):
            raise ImportError("CVSS invalido")
        cves = [_text(v, limit=64) for v in _records(record.get("cve_ids", []))]
        findings.append(Finding(title=_text(record.get("title"), limit=1024), severity=severity,
                                source=f"external:{engine}:{rule_id}", host=host, port=port,
                                protocol=protocol, description=_text(record.get("description", "")),
                                evidence=_text(record.get("evidence", "")),
                                remediation=_text(record.get("remediation", "")), cvss=cvss,
                                cve_ids=cves))
    rules = [_text(rule, limit=160) for rule in _records(coverage.get("rules", []))]
    run.coverage = {"status": coverage["status"], "engine": engine, "engine_version": version,
                    "rules_version": rules_version, "protocols": normalized_protocols,
                    "hosts": sorted(addresses), "rules": [f"external:{engine}:{r}" for r in rules],
                    "endpoints": [{"host": h.address, "port": p.portid, "protocol": p.protocol,
                                   "state": p.state, "rules": [f"external:{engine}:{r}" for r in rules]}
                                  for h in run.hosts for p in h.ports]}
    run.hosts_total = len(run.hosts)
    run.hosts_up = len(run.live_hosts)
    return _store(run, findings, data, ".json", name=name, namespace=namespace,
                  authorized_by=authorized_by,
                  provenance={"engine": engine, "engine_version": version,
                              "rules_version": rules_version, "observed_at": observed_at,
                              "format": EXTERNAL_SCHEMA})
