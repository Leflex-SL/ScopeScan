"""Vista consolidada de ruta de ataque por host y puerto.

No confirma nada por si sola: junta la evidencia que ya existe en el escaneo
para que el panel pueda enseñar una secuencia revisable.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import db, msf_modules
from .models import Severity


def build(scan_id: int) -> list[dict[str, Any]]:
    scan = db.get_scan(scan_id)
    public_scope = bool(scan and not scan["target_private"])
    findings_by_loc: dict[tuple[str, int | None, str], list[Any]] = defaultdict(list)
    cves_by_loc: dict[tuple[str, int | None, str], set[str]] = defaultdict(set)
    paths: dict[tuple[str, int | None, str], dict[str, Any]] = {}

    _seed_ports(scan_id, paths)

    for finding in db.get_findings(scan_id):
        key = (finding["host"], finding["port"], finding["protocol"] or "tcp")
        paths.setdefault(key, _empty_path(*key))
        findings_by_loc[key].append(finding)
        cves_by_loc[key].update(db.row_list(finding["cves"]))

    candidates_by_cve: dict[str, list[Any]] = defaultdict(list)
    for candidate in db.get_cve_candidates(scan_id):
        key = (candidate["host"], candidate["port"], candidate["protocol"] or "tcp")
        paths.setdefault(key, _empty_path(*key))
        cves_by_loc[key].add(candidate["cve_id"])
        candidates_by_cve[candidate["cve_id"]].append(candidate)

    exploitdb_by_cve: dict[str, list[Any]] = defaultdict(list)
    for item in db.get_exploitdb_results(scan_id):
        exploitdb_by_cve[item["cve_id"]].append(item)

    msf_by_loc: dict[tuple[str, int | None, str], list[Any]] = defaultdict(list)
    for item in db.get_msf_results(scan_id):
        msf_by_loc[(item["host"], item["port"], item["protocol"] or "tcp")].append(item)

    runs_by_loc: dict[tuple[str, int | None, str], list[Any]] = defaultdict(list)
    for run in db.get_exploit_runs(scan_id):
        key = (run["host"], run["port"], run["protocol"] or "tcp")
        paths.setdefault(key, _empty_path(*key))
        runs_by_loc[key].append(run)

    out: list[dict[str, Any]] = []
    for key, path in paths.items():
        path_findings = findings_by_loc.get(key, [])
        path_cves = sorted(cves_by_loc.get(key, set()))
        path_candidates = [
            item for cve in path_cves for item in candidates_by_cve.get(cve, [])
            if item["host"] == key[0] and item["port"] == key[1]
        ]
        path_exploitdb = [item for cve in path_cves for item in exploitdb_by_cve.get(cve, [])]
        path_msf = msf_by_loc.get(key, [])
        path_runs = runs_by_loc.get(key, [])
        exploitable_modules = [
            item for item in path_msf
            if item["result"] in (msf_modules.VULNERABLE, msf_modules.LIKELY)
            and (mod := msf_modules.module_by_path(item["module"])) is not None
            and mod.exploitable
        ]

        max_severity = max((int(f["severity"]) for f in path_findings), default=0)
        best_msf = _best_msf(path_msf)
        best_poc = _best_poc(path_exploitdb)
        exploited = any(run["result"] == msf_modules.EXPLOITED for run in path_runs)
        known_exploited = any(c["known_exploited"] for c in path_candidates)
        epss = max((c["epss"] or 0.0 for c in path_candidates), default=0.0)

        score = _score(
            max_severity=max_severity,
            best_msf=best_msf["result"] if best_msf else "",
            exploitdb_count=len(path_exploitdb),
            exploitdb_score=int(best_poc["context_score"]) if best_poc else 0,
            exploited=exploited,
            known_exploited=known_exploited,
            epss=epss,
            public_scope=public_scope,
        )
        if score == 0 and not path_cves and not path_findings and not path_msf and not path_runs:
            continue

        path.update(
            {
                "findings": path_findings,
                "cves": path_cves,
                "candidates": path_candidates,
                "exploitdb": path_exploitdb,
                "best_poc": best_poc,
                "msf": path_msf,
                "best_msf": best_msf,
                "exploitable_modules": exploitable_modules,
                "exploit_runs": path_runs,
                "max_severity": max_severity,
                "max_severity_slug": Severity(max_severity).slug,
                "exploited": exploited,
                "public_scope": public_scope,
                "known_exploited": known_exploited,
                "epss": epss,
                "score": score,
                "state": _state(exploited, best_msf, path_exploitdb, path_candidates, path_findings),
                "recommendation": _recommendation(
                    exploited, best_msf, path_exploitdb, known_exploited, epss,
                    max_severity, public_scope
                ),
            }
        )
        out.append(path)

    return sorted(out, key=lambda item: (-item["score"], item["host"], item["port"] or 0))


def _seed_ports(scan_id: int, paths: dict[tuple[str, int | None, str], dict[str, Any]]) -> None:
    for host, ports in db.hosts_with_ports(scan_id):
        for port in ports:
            key = (host["address"], int(port["portid"]), port["protocol"] or "tcp")
            paths[key] = _empty_path(
                key[0],
                key[1],
                key[2],
                service=port["service_name"] or "",
                product=" ".join(p for p in (port["product"], port["version"]) if p),
            )


def _empty_path(
    host: str,
    port: int | None,
    protocol: str,
    *,
    service: str = "",
    product: str = "",
) -> dict[str, Any]:
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "service": service,
        "product": product,
    }


def _best_msf(rows: list[Any]) -> Any | None:
    rank = {
        msf_modules.EXPLOITED: 6,
        msf_modules.VULNERABLE: 5,
        msf_modules.LIKELY: 4,
        msf_modules.UNKNOWN: 3,
        msf_modules.ERROR: 2,
        msf_modules.SAFE: 1,
        msf_modules.FAILED: 0,
    }
    return max(rows, key=lambda row: rank.get(row["result"], 0), default=None)


def _best_poc(rows: list[Any]) -> Any | None:
    return max(rows, key=lambda row: int(row["context_score"] or 0), default=None)


def _score(
    *,
    max_severity: int,
    best_msf: str,
    exploitdb_count: int,
    exploitdb_score: int,
    exploited: bool,
    known_exploited: bool,
    epss: float,
    public_scope: bool,
) -> int:
    score = max_severity * 15
    if exploited:
        score += 45
    if best_msf == msf_modules.VULNERABLE:
        score += 35
    elif best_msf == msf_modules.LIKELY:
        score += 25
    if exploitdb_count:
        score += 15
    if exploitdb_score >= 70:
        score += 10
    elif exploitdb_score >= 45:
        score += 5
    if known_exploited:
        score += 20
    if public_scope and max_severity >= int(Severity.MEDIUM):
        score += 10
    if epss >= 0.5:
        score += 10
    elif epss >= 0.1:
        score += 5
    return min(score, 100)


def _state(
    exploited: bool,
    best_msf: Any | None,
    exploitdb_rows: list[Any],
    candidates: list[Any],
    findings: list[Any],
) -> str:
    if exploited:
        return "Explotada"
    if best_msf and best_msf["result"] == msf_modules.VULNERABLE:
        return "Verificada"
    if best_msf and best_msf["result"] == msf_modules.LIKELY:
        return "Probable"
    if exploitdb_rows:
        best_poc = _best_poc(exploitdb_rows)
        if best_poc and int(best_poc["context_score"] or 0) >= 45:
            return "PoC contextual"
        return "PoC publica"
    if candidates:
        return "CVE candidata"
    if findings:
        return "Hallazgo"
    return "Observada"


def _recommendation(
    exploited: bool,
    best_msf: Any | None,
    exploitdb_rows: list[Any],
    known_exploited: bool,
    epss: float,
    max_severity: int,
    public_scope: bool,
) -> str:
    if exploited:
        return "Aislar el host, parchear o mitigar y revisar credenciales/sesiones obtenidas."
    if best_msf and best_msf["result"] in (msf_modules.VULNERABLE, msf_modules.LIKELY):
        return "Parchear o mitigar con prioridad: Metasploit confirma explotabilidad."
    if public_scope and max_severity >= int(Severity.MEDIUM):
        return "Reducir exposicion publica y aplicar parche/mitigacion antes de validar PoC."
    if exploitdb_rows and (known_exploited or epss >= 0.1):
        return "Priorizar validacion y parcheo: hay PoC publica y senales externas de explotacion."
    if max_severity >= int(Severity.HIGH):
        return "Corregir el hallazgo y repetir verificacion tras el cambio."
    return "Revisar aplicabilidad y dejar evidencia antes de escalar la accion."
