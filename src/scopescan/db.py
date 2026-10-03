"""Persistencia en SQLite.

Un escaneo tarda minutos u horas y el panel web tiene que poder consultarlo
mientras corre, asi que el estado vive en disco y no en memoria del proceso.

Cada llamada abre y cierra su conexion: sqlite3 no comparte conexiones entre
hilos con seguridad, y el hilo de escaneo y el del servidor web son distintos.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import db_path
from .models import Assessment, Finding, NmapRun, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    targets         TEXT NOT NULL,
    profile         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued',
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    error           TEXT,
    nmap_args       TEXT,
    raw_xml_path    TEXT,
    hosts_up        INTEGER DEFAULT 0,
    hosts_total     INTEGER DEFAULT 0,
    elapsed         REAL DEFAULT 0,
    risk_score      INTEGER DEFAULT 0,
    progress        REAL DEFAULT 0,
    progress_task   TEXT DEFAULT '',
    target_private  INTEGER DEFAULT 1,
    authorized_by   TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    deletion_pending INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    addrtype     TEXT,
    mac          TEXT,
    vendor       TEXT,
    state        TEXT,
    hostnames    TEXT,
    os_name      TEXT,
    os_accuracy  INTEGER,
    extraports   TEXT
);

CREATE TABLE IF NOT EXISTS ports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    portid       INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    state        TEXT,
    reason       TEXT,
    service_name TEXT,
    product      TEXT,
    version      TEXT,
    extrainfo    TEXT,
    ostype       TEXT,
    cpes         TEXT,
    scripts      TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    port         INTEGER,
    protocol     TEXT,
    service      TEXT,
    title        TEXT NOT NULL,
    severity     INTEGER NOT NULL,
    source       TEXT,
    description  TEXT,
    evidence     TEXT,
    remediation  TEXT,
    cvss         REAL,
    cves         TEXT,
    confirmed    INTEGER DEFAULT 0,
    assessment   TEXT NOT NULL DEFAULT 'exposure'
);

CREATE TABLE IF NOT EXISTS nvd_cache (
    cpe          TEXT PRIMARY KEY,
    fetched_at   TEXT NOT NULL,
    candidates   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_cache (
    cache_key    TEXT PRIMARY KEY,
    fetched_at   TEXT NOT NULL,
    payload      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS host_inventory (
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    source       TEXT NOT NULL,
    data         TEXT NOT NULL,
    PRIMARY KEY (scan_id, host)
);

CREATE TABLE IF NOT EXISTS cve_candidates (
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    detected_cpe TEXT NOT NULL,
    queried_cpe  TEXT NOT NULL,
    cve_id       TEXT NOT NULL,
    cvss         REAL,
    summary      TEXT NOT NULL,
    match_type   TEXT NOT NULL DEFAULT 'unresolved',
    requires_other_cpe INTEGER NOT NULL DEFAULT 0,
    matched_criteria TEXT NOT NULL DEFAULT '',
    cvss_source TEXT NOT NULL DEFAULT '',
    cvss_vector TEXT NOT NULL DEFAULT '',
    vendor_advisory TEXT NOT NULL DEFAULT '',
    epss REAL,
    epss_percentile REAL,
    epss_date TEXT NOT NULL DEFAULT '',
    known_exploited INTEGER NOT NULL DEFAULT 0,
    kev_due_date TEXT NOT NULL DEFAULT '',
    kev_action TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, host, port, protocol, queried_cpe, cve_id)
);

CREATE TABLE IF NOT EXISTS enrichment_jobs (
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    status       TEXT NOT NULL,
    error        TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (scan_id, kind)
);

CREATE TABLE IF NOT EXISTS control_results (
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    platform     TEXT NOT NULL,
    control_id   TEXT NOT NULL,
    title        TEXT NOT NULL,
    status       TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    references_json TEXT NOT NULL DEFAULT '[]',
    collected_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, host, control_id)
);

CREATE TABLE IF NOT EXISTS windows_patch_status (
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host           TEXT NOT NULL,
    release_id     TEXT NOT NULL,
    product_id     TEXT NOT NULL,
    product_name   TEXT NOT NULL,
    installed_build TEXT NOT NULL,
    required_build TEXT NOT NULL,
    required_kb    TEXT NOT NULL,
    status         TEXT NOT NULL,
    unresolved     INTEGER NOT NULL DEFAULT 0,
    checked_at     TEXT NOT NULL,
    PRIMARY KEY (scan_id, host)
);

CREATE TABLE IF NOT EXISTS windows_patch_candidates (
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host           TEXT NOT NULL,
    cve_id         TEXT NOT NULL,
    title          TEXT NOT NULL,
    cvss           REAL,
    cvss_vector    TEXT NOT NULL DEFAULT '',
    kb             TEXT NOT NULL DEFAULT '',
    fixed_build    TEXT NOT NULL,
    installed_build TEXT NOT NULL,
    url            TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, host, cve_id)
);

CREATE TABLE IF NOT EXISTS msf_results (
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    port         INTEGER,
    protocol     TEXT NOT NULL DEFAULT 'tcp',
    module       TEXT NOT NULL,
    module_kind  TEXT NOT NULL,
    action       TEXT NOT NULL,
    result       TEXT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',
    checked_at   TEXT NOT NULL,
    PRIMARY KEY (scan_id, host, port, module)
);

CREATE TABLE IF NOT EXISTS exploitdb_results (
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id       TEXT NOT NULL,
    edb_id       TEXT NOT NULL,
    title        TEXT NOT NULL,
    type         TEXT NOT NULL DEFAULT '',
    platform     TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    date         TEXT NOT NULL DEFAULT '',
    url          TEXT NOT NULL DEFAULT '',
    context_score INTEGER NOT NULL DEFAULT 0,
    matched_context TEXT NOT NULL DEFAULT '',
    checked_at   TEXT NOT NULL,
    PRIMARY KEY (scan_id, cve_id, edb_id)
);

CREATE TABLE IF NOT EXISTS exploit_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    port          INTEGER,
    protocol      TEXT NOT NULL DEFAULT 'tcp',
    engine        TEXT NOT NULL,
    module        TEXT NOT NULL,
    action        TEXT NOT NULL,
    status        TEXT NOT NULL,
    result        TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '',
    rc_path       TEXT NOT NULL DEFAULT '',
    log_path      TEXT NOT NULL DEFAULT '',
    authorized_by TEXT NOT NULL DEFAULT '',
    started_at    TEXT NOT NULL,
    finished_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity DESC);
CREATE INDEX IF NOT EXISTS idx_exploit_runs_scan ON exploit_runs(scan_id, started_at DESC);
"""


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


_snapshot_connection: ContextVar[sqlite3.Connection | None] = ContextVar(
    "scopescan_snapshot", default=None
)


@contextmanager
def read_snapshot() -> Iterator[None]:
    """Reuse one read transaction for all getters during an export."""
    if _snapshot_connection.get() is not None:
        yield
        return
    with connect() as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        token = _snapshot_connection.set(conn)
        try:
            yield
        finally:
            _snapshot_connection.reset(token)


@contextmanager
def connect(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    snapshot = _snapshot_connection.get()
    if path is None and snapshot is not None:
        yield snapshot
        return
    conn = sqlite3.connect(path or db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: Path | None = None) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        scan_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
        if "deletion_pending" not in scan_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN deletion_pending INTEGER NOT NULL DEFAULT 0")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
        if "assessment" not in columns:
            conn.execute("ALTER TABLE findings ADD COLUMN assessment TEXT NOT NULL DEFAULT 'exposure'")
            conn.execute("UPDATE findings SET assessment = 'confirmed' WHERE confirmed = 1")
            conn.execute("""UPDATE findings SET assessment = 'candidate'
                            WHERE confirmed = 0 AND source LIKE 'nse:%' AND cves != '[]'""")
            conn.execute("""UPDATE findings SET assessment = 'candidate'
                            WHERE source IN ('rule:openssh-antiguo', 'rule:apache-antiguo',
                              'rule:nginx-antiguo', 'rule:samba-antiguo', 'rule:vsftpd-backdoor')""")
        candidate_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(cve_candidates)")
        }
        for column, declaration in (
            ("match_type", "TEXT NOT NULL DEFAULT 'unresolved'"),
            ("requires_other_cpe", "INTEGER NOT NULL DEFAULT 0"),
            ("matched_criteria", "TEXT NOT NULL DEFAULT ''"),
            ("cvss_source", "TEXT NOT NULL DEFAULT ''"),
            ("cvss_vector", "TEXT NOT NULL DEFAULT ''"),
            ("vendor_advisory", "TEXT NOT NULL DEFAULT ''"),
            ("epss", "REAL"),
            ("epss_percentile", "REAL"),
            ("epss_date", "TEXT NOT NULL DEFAULT ''"),
            ("known_exploited", "INTEGER NOT NULL DEFAULT 0"),
            ("kev_due_date", "TEXT NOT NULL DEFAULT ''"),
            ("kev_action", "TEXT NOT NULL DEFAULT ''"),
        ):
            if column not in candidate_columns:
                conn.execute(f"ALTER TABLE cve_candidates ADD COLUMN {column} {declaration}")
        exploitdb_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(exploitdb_results)")
        }
        for column, declaration in (
            ("context_score", "INTEGER NOT NULL DEFAULT 0"),
            ("matched_context", "TEXT NOT NULL DEFAULT ''"),
        ):
            if column not in exploitdb_columns:
                conn.execute(f"ALTER TABLE exploitdb_results ADD COLUMN {column} {declaration}")
        if not list(conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='exploit_runs'"
        )):
            conn.executescript("""
CREATE TABLE exploit_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    port          INTEGER,
    protocol      TEXT NOT NULL DEFAULT 'tcp',
    engine        TEXT NOT NULL,
    module        TEXT NOT NULL,
    action        TEXT NOT NULL,
    status        TEXT NOT NULL,
    result        TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '',
    rc_path       TEXT NOT NULL DEFAULT '',
    log_path      TEXT NOT NULL DEFAULT '',
    authorized_by TEXT NOT NULL DEFAULT '',
    started_at    TEXT NOT NULL,
    finished_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_exploit_runs_scan ON exploit_runs(scan_id, started_at DESC);
""")
        from .continuity import migrate

        migrate(conn)


def create_scan(
    *,
    name: str,
    targets: str,
    profile: str,
    target_private: bool = True,
    authorized_by: str = "",
    notes: str = "",
    scope_id: int | None = None,
    execution_context: dict[str, Any] | None = None,
) -> int:
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO scans (name, targets, profile, status, created_at,
                                  target_private, authorized_by, notes)
               VALUES (?, ?, ?, 'queued', ?, ?, ?, ?)""",
            (name, targets, profile, now(), int(target_private), authorized_by, notes),
        )
        scan_id = int(cur.lastrowid)
        conn.execute("UPDATE scans SET scope_id=?,execution_context=? WHERE id=?",
                     (scope_id, json.dumps(execution_context or {}), scan_id))
        return scan_id


def set_status(scan_id: int, status: str, *, error: str | None = None) -> None:
    fields = ["status = ?"]
    values: list[Any] = [status]
    if status == "running":
        fields.append("started_at = ?")
        values.append(now())
    if status in ("done", "failed", "cancelled"):
        fields.append("finished_at = ?")
        values.append(now())
    if error is not None:
        fields.append("error = ?")
        values.append(error)
    values.append(scan_id)
    with connect() as conn:
        conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id = ?", values)
        if status in {"done", "failed", "cancelled"}:
            from .continuity import reconcile, sync_enrichment

            reconcile(conn, scan_id)
            if status == "done":
                inventory_hosts = conn.execute("SELECT host FROM host_inventory WHERE scan_id=?", (scan_id,)).fetchall()
                for inventory_host in inventory_hosts:
                    sync_enrichment(conn, scan_id, inventory_host["host"])


def set_progress(scan_id: int, percent: float, task: str = "") -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET progress = ?, progress_task = ? WHERE id = ?",
            (round(percent, 1), task, scan_id),
        )


def set_nmap_args(scan_id: int, args: str, raw_xml_path: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET nmap_args = ?, raw_xml_path = ? WHERE id = ?",
            (args, raw_xml_path, scan_id),
        )


def save_results(scan_id: int, run: NmapRun, findings: list[Finding], risk: int) -> None:
    """Guarda hosts, puertos y hallazgos de un escaneo terminado."""
    with connect() as conn:
        conn.execute("DELETE FROM hosts WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM ports WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))

        for host in run.hosts:
            best_os = host.best_os
            cur = conn.execute(
                """INSERT INTO hosts (scan_id, address, addrtype, mac, vendor, state,
                                      hostnames, os_name, os_accuracy, extraports)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    host.address,
                    host.addrtype,
                    host.mac,
                    host.vendor,
                    host.state,
                    json.dumps(host.hostnames),
                    best_os.name if best_os else "",
                    best_os.accuracy if best_os else 0,
                    json.dumps(host.extraports),
                ),
            )
            host_id = int(cur.lastrowid)
            for port in host.ports:
                conn.execute(
                    """INSERT INTO ports (host_id, scan_id, portid, protocol, state, reason,
                                          service_name, product, version, extrainfo, ostype,
                                          cpes, scripts)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        host_id,
                        scan_id,
                        port.portid,
                        port.protocol,
                        port.state,
                        port.reason,
                        port.service.name,
                        port.service.product,
                        port.service.version,
                        port.service.extrainfo,
                        port.service.ostype,
                        json.dumps(port.service.cpes),
                        json.dumps([{"id": s.id, "output": s.output} for s in port.scripts]),
                    ),
                )

        for finding in findings:
            conn.execute(
                """INSERT INTO findings (scan_id, host, port, protocol, service, title,
                                         severity, source, description, evidence,
                                         remediation, cvss, cves, confirmed, assessment,
                                         rule_id, component)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    finding.host,
                    finding.port,
                    finding.protocol,
                    finding.service,
                    finding.title,
                    int(finding.severity),
                    finding.source,
                    finding.description,
                    finding.evidence,
                    finding.remediation,
                    finding.cvss,
                    json.dumps(finding.cve_ids),
                    int(finding.confirmed),
                    finding.assessment.value,
                    finding.rule_id or finding.source,
                    finding.component,
                ),
            )

        conn.execute(
            """UPDATE scans SET hosts_up = ?, hosts_total = ?, elapsed = ?,
                                risk_score = ?, progress = 100 WHERE id = ?""",
            (run.hosts_up, run.hosts_total, run.elapsed, risk, scan_id),
        )
        from dataclasses import asdict

        from .continuity import normal_host, persist

        context = json.loads(conn.execute("SELECT execution_context FROM scans WHERE id=?",
                                          (scan_id,)).fetchone()[0] or "{}")
        coverage = dict(context.get("coverage", {}), **run.coverage)
        provenance = run.provenance or context.get("provenance", {})
        if isinstance(provenance, dict) and provenance.get("imported"):
            coverage["provenance"] = "imported:" + str(provenance.get("source", "external"))
        normalized_findings = [asdict(f) for f in findings]
        pending = {"hosts": [normal_host(h) for h in run.hosts], "findings": normalized_findings,
                       "coverage": coverage, "observed_at": run.start or None,
                       "success": run.exit_status == "success"}
        conn.execute("UPDATE scans SET continuity_pending=? WHERE id=?", (json.dumps(pending), scan_id))
        # Source args do not establish actual execution coverage.
        status = conn.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()[0]
        persist(conn, scan_id, run.hosts, normalized_findings, coverage,
                run.start or None, success=status == "done" and run.exit_status == "success")


def list_scans(limit: int = 50, *, offset: int = 0, search: str = "") -> list[sqlite3.Row]:
    with connect() as conn:
        return list(
            conn.execute(
                """SELECT s.*,
                          (SELECT COUNT(*) FROM findings f
                            WHERE f.scan_id = s.id AND f.severity >= ?) AS findings_relevantes,
                          (SELECT COUNT(*) FROM findings f
                            WHERE f.scan_id = s.id AND f.severity = ?) AS criticas
                     FROM scans s WHERE s.name LIKE ? OR s.targets LIKE ?
                     ORDER BY s.id DESC LIMIT ? OFFSET ?""",
                (int(Severity.LOW), int(Severity.CRITICAL),
                 "%" + search + "%", "%" + search + "%", limit, offset),
            )
        )


def get_scan(scan_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def get_hosts(scan_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(
            conn.execute(
                "SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (scan_id,)
            )
        )


def get_ports(scan_id: int, *, only_open: bool = True) -> dict[int, list[sqlite3.Row]]:
    """Puertos agrupados por host_id."""
    query = "SELECT * FROM ports WHERE scan_id = ?"
    if only_open:
        query += " AND state = 'open'"
    query += " ORDER BY portid"
    grouped: dict[int, list[sqlite3.Row]] = {}
    with connect() as conn:
        for row in conn.execute(query, (scan_id,)):
            grouped.setdefault(row["host_id"], []).append(row)
    return grouped


def get_findings(scan_id: int, *, min_severity: int = 0) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(
            conn.execute(
                """SELECT * FROM findings WHERE scan_id = ? AND severity >= ?
                   ORDER BY severity DESC, host, port""",
                (scan_id, min_severity),
            )
        )


def severity_counts(scan_id: int) -> dict[str, int]:
    counts = {sev.slug: 0 for sev in Severity}
    with connect() as conn:
        for row in conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        ):
            counts[Severity(row["severity"]).slug] = row["n"]
    return counts


def global_stats() -> dict[str, Any]:
    """Cifras para el panel: escaneos, hosts vivos y hallazgos por severidad."""
    with connect() as conn:
        scans = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        running = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE status IN ('queued', 'running')"
        ).fetchone()["n"]
        hosts = conn.execute(
            "SELECT COUNT(DISTINCT address) AS n FROM hosts WHERE state = 'up'"
        ).fetchone()["n"]
        open_ports = conn.execute(
            "SELECT COUNT(*) AS n FROM ports WHERE state = 'open'"
        ).fetchone()["n"]
        counts = {sev.slug: 0 for sev in Severity}
        for row in conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        ):
            counts[Severity(row["severity"]).slug] = row["n"]
    return {
        "scans": scans,
        "running": running,
        "hosts": hosts,
        "open_ports": open_ports,
        "severities": counts,
    }


def recent_findings(limit: int = 100, min_severity: int = int(Severity.LOW),
                    *, offset: int = 0, search: str = "") -> list[sqlite3.Row]:
    with connect() as conn:
        return list(
            conn.execute(
                """SELECT f.*, s.name AS scan_name, s.created_at AS scan_date
                     FROM findings f JOIN scans s ON s.id = f.scan_id
                    WHERE f.severity >= ? AND (f.title LIKE ? OR f.host LIKE ? OR s.name LIKE ?)
                    ORDER BY f.severity DESC, f.scan_id DESC, f.id DESC LIMIT ? OFFSET ?""",
                (min_severity, *["%" + search + "%"] * 3, limit, offset),
            )
        )


def save_msf_results(scan_id: int, rows: list[dict[str, Any]]) -> int:
    """Guarda (o reemplaza) los veredictos de Metasploit de un escaneo.

    Clave (scan_id, host, port, module): relanzar la verificacion actualiza el
    veredicto en vez de duplicarlo.
    """
    stamp = now()
    with connect() as conn:
        for r in rows:
            conn.execute(
                """INSERT INTO msf_results
                     (scan_id, host, port, protocol, module, module_kind, action,
                      result, detail, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, host, port, module) DO UPDATE SET
                     module_kind=excluded.module_kind, action=excluded.action,
                     result=excluded.result, detail=excluded.detail,
                     checked_at=excluded.checked_at""",
                (
                    scan_id, r["host"], r.get("port"), r.get("protocol", "tcp"),
                    r["module"], r["module_kind"], r["action"],
                    r["result"], r.get("detail", ""), stamp,
                ),
            )
    return len(rows)


def get_msf_results(scan_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(
            conn.execute(
                """SELECT * FROM msf_results WHERE scan_id = ?
                   ORDER BY host, port, module""",
                (scan_id,),
            )
        )


def replace_exploitdb_results(scan_id: int, rows: list[dict[str, Any]]) -> int:
    stamp = now()
    with connect() as conn:
        conn.execute("DELETE FROM exploitdb_results WHERE scan_id = ?", (scan_id,))
        conn.executemany(
            """INSERT INTO exploitdb_results
                 (scan_id, cve_id, edb_id, title, type, platform, path, date, url,
                  context_score, matched_context, checked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    scan_id, row["cve_id"], row["edb_id"], row["title"],
                    row.get("type", ""), row.get("platform", ""), row.get("path", ""),
                    row.get("date", ""), row.get("url", ""),
                    int(row.get("context_score", 0) or 0), row.get("matched_context", ""),
                    stamp,
                )
                for row in rows
            ],
        )
    return len(rows)


def get_exploitdb_results(scan_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(
            conn.execute(
                """SELECT * FROM exploitdb_results WHERE scan_id = ?
                   ORDER BY context_score DESC, cve_id, type, platform, title""",
                (scan_id,),
            )
        )


def create_exploit_run(
    scan_id: int,
    *,
    host: str,
    port: int | None,
    protocol: str = "tcp",
    engine: str,
    module: str,
    action: str,
    rc_path: str = "",
    log_path: str = "",
    authorized_by: str = "",
) -> int:
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO exploit_runs
                 (scan_id, host, port, protocol, engine, module, action, status,
                  rc_path, log_path, authorized_by, started_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)""",
            (
                scan_id, host, port, protocol, engine, module, action,
                rc_path, log_path, authorized_by, now(),
            ),
        )
        return int(cur.lastrowid)


def finish_exploit_run(
    run_id: int,
    *,
    status: str,
    result: str = "",
    detail: str = "",
) -> None:
    with connect() as conn:
        conn.execute(
            """UPDATE exploit_runs
                  SET status = ?, result = ?, detail = ?, finished_at = ?
                WHERE id = ?""",
            (status, result, detail, now(), run_id),
        )


def get_exploit_runs(scan_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(
            conn.execute(
                """SELECT * FROM exploit_runs WHERE scan_id = ?
                   ORDER BY started_at DESC, id DESC""",
                (scan_id,),
            )
        )


class ScanUnavailable(ValueError):
    """An atomic lifecycle transition refused a missing, busy or deleting scan."""


def _delete_scan_rows(conn: sqlite3.Connection, scan_id: int) -> None:
    for table in ("exploit_runs", "msf_results", "exploitdb_results", "enrichment_jobs",
                  "cve_candidates", "host_inventory", "findings", "ports", "hosts"):
        conn.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    from .continuity import after_scan_deletion

    after_scan_deletion(conn, scan_id)


def request_scan_deletion(scan_id: int, *, defer: bool = False) -> bool:
    """Serialize deletion with claims, including the HTTP-to-background-task gap."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        scan = conn.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            return False
        active = conn.execute(
            "SELECT 1 FROM enrichment_jobs WHERE scan_id=? AND status IN ('running', 'queued')",
            (scan_id,),
        ).fetchone()
        if active is not None:
            raise ScanUnavailable("Espera a que termine el enriquecimiento")
        if scan["status"] == "running" and not defer:
            raise ScanUnavailable("Escaneo activo sin worker local; espera a que termine")
        if defer:
            conn.execute("UPDATE scans SET deletion_pending=1 WHERE id=?", (scan_id,))
            return True
        _delete_scan_rows(conn, scan_id)
        return False


def delete_scan(scan_id: int) -> None:
    request_scan_deletion(scan_id)


def claim_scan_execution(scan_id: int) -> bool:
    with connect() as conn:
        cursor = conn.execute(
            """UPDATE scans SET status='running', started_at=?
               WHERE id=? AND status='queued' AND deletion_pending=0""", (now(), scan_id)
        )
        return cursor.rowcount == 1


def hosts_with_ports(scan_id: int) -> list[tuple[sqlite3.Row, list[sqlite3.Row]]]:
    ports = get_ports(scan_id)
    return [(host, ports.get(host["id"], [])) for host in get_hosts(scan_id)]


def row_scripts(port_row: sqlite3.Row) -> list[dict[str, str]]:
    try:
        return json.loads(port_row["scripts"] or "[]")
    except (json.JSONDecodeError, TypeError):
        return []


def row_list(value: str | None) -> list[str]:
    try:
        return json.loads(value or "[]")
    except (json.JSONDecodeError, TypeError):
        return []


def reset_stale_scans() -> int:
    """Marca como fallidos los escaneos que quedaron 'running' de un arranque anterior.

    Si el proceso muere a medio escaneo, la fila se queda en 'running' para
    siempre. Al arrancar se limpian, porque el hilo que las actualizaba ya no existe.
    """
    with connect() as conn:
        cur = conn.execute(
            """UPDATE scans SET status = 'failed',
                                error = 'Interrumpido: el proceso termino durante el escaneo',
                                finished_at = ?
                WHERE status IN ('running', 'queued')""",
            (now(),),
        )
        return cur.rowcount


def get_nvd_cache(cpe: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM nvd_cache WHERE cpe = ?", (cpe,)).fetchone()


def put_nvd_cache(cpe: str, candidates: list[dict[str, Any]]) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO nvd_cache (cpe, fetched_at, candidates) VALUES (?, ?, ?)
               ON CONFLICT(cpe) DO UPDATE SET fetched_at=excluded.fetched_at,
                                              candidates=excluded.candidates""",
            (cpe, now(), json.dumps(candidates)),
        )


def replace_cve_candidates(scan_id: int, rows: list[dict[str, Any]]) -> None:
    import math

    for row in rows:
        for field, maximum in (("cvss", 10), ("epss", 1), ("epss_percentile", 1)):
            value = row.get(field)
            if value is not None and (isinstance(value, bool) or not math.isfinite(float(value)) or not 0 <= float(value) <= maximum):
                raise ValueError(f"Invalid {field}")
    with connect() as conn:
        conn.execute("DELETE FROM cve_candidates WHERE scan_id = ?", (scan_id,))
        conn.executemany(
            """INSERT OR IGNORE INTO cve_candidates
               (scan_id, host, port, protocol, detected_cpe, queried_cpe, cve_id, cvss,
                summary, match_type, requires_other_cpe, matched_criteria, cvss_source,
                cvss_vector, vendor_advisory, epss, epss_percentile, epss_date,
                known_exploited, kev_due_date, kev_action)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (scan_id, row["host"], row["port"], row["protocol"], row["detected_cpe"],
                 row["queried_cpe"], row["cve_id"], row["cvss"], row["summary"],
                 row.get("match_type", "unresolved"), int(row.get("requires_other_cpe", False)),
                 row.get("matched_criteria", ""), row.get("cvss_source", ""),
                 row.get("cvss_vector", ""), row.get("vendor_advisory", ""),
                 row.get("epss"), row.get("epss_percentile"), row.get("epss_date", ""),
                 int(row.get("known_exploited", False)), row.get("kev_due_date", ""),
                 row.get("kev_action", ""))
                for row in rows
            ],
        )
        for row in rows:
            conn.execute("UPDATE cve_candidates SET kev_assessed=?,kev_checked_at=? WHERE scan_id=? AND host=? AND port=? AND protocol=? AND queried_cpe=? AND cve_id=?", (int(row["kev_assessed"]) if row.get("kev_assessed") is not None else None, row.get("kev_checked_at"), scan_id, row["host"], row["port"], row["protocol"], row["queried_cpe"], row["cve_id"]))
        from .continuity import sync_enrichment

        sync_enrichment(conn, scan_id)


def get_cve_candidates(scan_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(conn.execute(
            """SELECT * FROM cve_candidates WHERE scan_id = ?
               ORDER BY known_exploited DESC, epss DESC, cvss DESC, cve_id, host, port""",
            (scan_id,)
        ))


def get_feed_cache(cache_key: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM feed_cache WHERE cache_key = ?", (cache_key,)).fetchone()


def put_feed_cache(cache_key: str, payload: Any) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO feed_cache (cache_key, fetched_at, payload) VALUES (?, ?, ?)
               ON CONFLICT(cache_key) DO UPDATE SET fetched_at=excluded.fetched_at,
                 payload=excluded.payload""",
            (cache_key, now(), json.dumps(payload)),
        )


def save_host_inventory(
    scan_id: int, host: str, data: dict[str, Any], source: str,
    *, findings: list[Finding] | None = None, controls: list[dict[str, Any]] | None = None,
) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO host_inventory (scan_id, host, collected_at, source, data)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(scan_id, host) DO UPDATE SET
               collected_at=excluded.collected_at, source=excluded.source, data=excluded.data""",
            (scan_id, host, now(), source, json.dumps(data)),
        )
        # Un build o inventario nuevo invalida cualquier comparacion MSRC anterior.
        conn.execute("DELETE FROM windows_patch_status WHERE scan_id = ? AND host = ?",
                     (scan_id, host))
        conn.execute("DELETE FROM windows_patch_candidates WHERE scan_id = ? AND host = ?",
                     (scan_id, host))
        if findings is not None:
            conn.execute(
                "DELETE FROM findings WHERE scan_id = ? AND host = ? "
                "AND source LIKE 'auth:%'", (scan_id, host),
            )
            conn.executemany(
                """INSERT INTO findings (scan_id, host, port, protocol, service, title,
                   severity, source, description, evidence, remediation, cvss, cves,
                   confirmed, assessment, rule_id, component)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (scan_id, f.host, f.port, f.protocol, f.service, f.title,
                     int(f.severity), f.source, f.description, f.evidence, f.remediation,
                     f.cvss, json.dumps(f.cve_ids), int(f.confirmed), f.assessment.value,
                     f.rule_id or f.source, f.component)
                    for f in findings
                ],
            )
            from .analysis import risk_score_evidence

            evidence = (
                (Severity(row["severity"]), Assessment(row["assessment"]))
                for row in conn.execute(
                    "SELECT severity, assessment FROM findings WHERE scan_id = ?", (scan_id,)
                )
            )
            conn.execute(
                "UPDATE scans SET risk_score = ? WHERE id = ?",
                (risk_score_evidence(evidence), scan_id),
            )
        if controls is not None:
            conn.execute(
                "DELETE FROM control_results WHERE scan_id = ? AND host = ?", (scan_id, host)
            )
            conn.executemany(
                """INSERT INTO control_results
                   (scan_id, host, platform, control_id, title, status, evidence,
                    references_json, collected_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (scan_id, host, data.get("platform", "windows"), item["control_id"],
                     item["title"], item["status"], item["evidence"],
                     json.dumps(item.get("references", [])), now())
                    for item in controls
                ],
            )
        from .continuity import sync_enrichment

        sync_enrichment(conn, scan_id, host)


def get_host_inventories(scan_id: int) -> dict[str, dict[str, Any]]:
    with connect() as conn:
        return {
            row["host"]: json.loads(row["data"])
            for row in conn.execute("SELECT host, data FROM host_inventory WHERE scan_id = ?", (scan_id,))
        }


def inventory_exists(scan_id: int, host: str) -> bool:
    with connect() as conn:
        return conn.execute("SELECT 1 FROM host_inventory WHERE scan_id=? AND host=?",
                            (scan_id, host)).fetchone() is not None


def get_host_inventory_summaries(scan_id: int) -> dict[str, dict[str, Any]]:
    """Keep bulk package/software arrays in SQLite until explicitly requested."""
    with connect() as conn:
        rows = conn.execute(
            """SELECT host, json_remove(data, '$.packages', '$.software', '$.updates') AS summary,
                   json_array_length(data, '$.packages') AS package_count,
                   json_array_length(data, '$.software') AS software_count,
                   json_array_length(data, '$.updates') AS update_count
                 FROM host_inventory WHERE scan_id=?""", (scan_id,)
        )
        return {row["host"]: dict(json.loads(row["summary"]),
                                  package_count=row["package_count"] or 0,
                                  software_count=row["software_count"] or 0,
                                  update_count=row["update_count"] or 0) for row in rows}


def inventory_page(scan_id: int, host: str, collection: str, *, offset: int = 0,
                   limit: int = 100, search: str = "") -> tuple[list[dict], int]:
    if collection not in {"packages", "software", "updates"}:
        raise ValueError("Unsupported inventory collection")
    with connect() as conn:
        query = """FROM host_inventory h, json_each(h.data, ?) j
                   WHERE h.scan_id=? AND h.host=? AND
                   (json_extract(j.value, '$.name') LIKE ? OR
                    json_extract(j.value, '$.kb') LIKE ? OR
                    json_extract(j.value, '$.version') LIKE ?)"""
        params = ("$." + collection, scan_id, host, *["%" + search + "%"] * 3)
        total = conn.execute("SELECT COUNT(*) " + query, params).fetchone()[0]
        items = [json.loads(row[0]) for row in conn.execute(
            "SELECT j.value " + query + " ORDER BY CAST(j.key AS INTEGER) LIMIT ? OFFSET ?",
            (*params, limit, offset))]
        return items, total


def get_control_results(scan_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(conn.execute(
            """SELECT * FROM control_results WHERE scan_id = ?
               ORDER BY CASE status WHEN 'fail' THEN 0 WHEN 'unknown' THEN 1
                 WHEN 'pass' THEN 2 ELSE 3 END, host, control_id""",
            (scan_id,),
        ))


def replace_windows_patch_assessment(
    scan_id: int, host: str, status: dict[str, Any], candidates: list[dict[str, Any]],
) -> None:
    with connect() as conn:
        conn.execute(
            "DELETE FROM windows_patch_candidates WHERE scan_id = ? AND host = ?",
            (scan_id, host),
        )
        conn.executemany(
            """INSERT INTO windows_patch_candidates
               (scan_id, host, cve_id, title, cvss, cvss_vector, kb, fixed_build,
                installed_build, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (scan_id, host, row["cve_id"], row["title"], row.get("cvss"),
                 row.get("cvss_vector", ""), row.get("kb", ""), row["fixed_build"],
                 row["installed_build"], row.get("url", ""))
                for row in candidates
            ],
        )
        conn.execute(
            """INSERT INTO windows_patch_status
               (scan_id, host, release_id, product_id, product_name, installed_build,
                required_build, required_kb, status, unresolved, checked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(scan_id, host) DO UPDATE SET
                 release_id=excluded.release_id, product_id=excluded.product_id,
                 product_name=excluded.product_name, installed_build=excluded.installed_build,
                 required_build=excluded.required_build, required_kb=excluded.required_kb,
                 status=excluded.status, unresolved=excluded.unresolved,
                 checked_at=excluded.checked_at""",
            (scan_id, host, status["release_id"], status["product_id"],
             status["product_name"], status["installed_build"],
             status.get("required_build", ""), status.get("required_kb", ""),
             status["status"], status.get("unresolved", 0), now()),
        )
        control_status = "fail" if status["status"] == "outdated" else (
            "pass" if status["status"] == "current" else "unknown"
        )
        evidence = (
            f"Build instalado {status['installed_build']}; build requerido "
            f"{status.get('required_build') or 'sin dato'}; "
            f"MSRC {status['release_id']}; producto {status['product_name']}"
        )
        conn.execute(
            """INSERT INTO control_results
               (scan_id, host, platform, control_id, title, status, evidence,
                references_json, collected_at)
               VALUES (?, ?, 'windows', 'WIN-OS-PATCHLEVEL', ?, ?, ?, ?, ?)
               ON CONFLICT(scan_id, host, control_id) DO UPDATE SET
                 title=excluded.title, status=excluded.status, evidence=excluded.evidence,
                 references_json=excluded.references_json, collected_at=excluded.collected_at""",
            (scan_id, host, "Nivel acumulativo de parches Windows vigente", control_status,
             evidence, json.dumps(["Microsoft Security Update Guide",
                                   "ENS RD 311/2022 art. 21"]), now()),
        )
        conn.execute(
            "DELETE FROM findings WHERE scan_id = ? AND host = ? "
            "AND source LIKE 'auth:windows:msrc:%'", (scan_id, host),
        )
        conn.executemany(
            """INSERT INTO findings (scan_id, host, protocol, title, severity, source,
               description, evidence, remediation, cvss, cves, confirmed, assessment)
               VALUES (?, ?, 'host', ?, ?, ?, ?, ?, ?, ?, ?, 1, 'confirmed')""",
            [
                (scan_id, host, f"{row['cve_id']}: {row['title']}",
                 int(Severity.from_cvss(float(row["cvss"]))) if row.get("cvss") is not None
                 else int(Severity.MEDIUM),
                 f"auth:windows:msrc:{row['cve_id'].lower()}",
                 ("MSRC marca el producto exacto como afectado y el build instalado "
                  "es anterior al build corregido publicado por Microsoft."),
                 (f"Producto: {status['product_name']}; instalado {row['installed_build']}; "
                  f"corregido {row['fixed_build']}; KB{row.get('kb') or ' sin dato'}"),
                 f"Instalar KB{row.get('kb') or ' indicada por MSRC'} o una acumulativa posterior.",
                 row.get("cvss"), json.dumps([row["cve_id"]]))
                for row in candidates
            ],
        )
        from .analysis import risk_score_evidence

        risk_evidence = (
            (Severity(row["severity"]), Assessment(row["assessment"]))
            for row in conn.execute(
                "SELECT severity, assessment FROM findings WHERE scan_id = ?", (scan_id,)
            )
        )
        conn.execute(
            "UPDATE scans SET risk_score = ? WHERE id = ?",
            (risk_score_evidence(risk_evidence), scan_id),
        )
        from .continuity import sync_enrichment

        sync_enrichment(conn, scan_id, host)


def get_windows_patch_statuses(scan_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(conn.execute(
            "SELECT * FROM windows_patch_status WHERE scan_id = ? ORDER BY host", (scan_id,)
        ))


def get_windows_patch_candidates(scan_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return list(conn.execute(
            """SELECT * FROM windows_patch_candidates WHERE scan_id = ?
               ORDER BY cvss DESC, cve_id, host""", (scan_id,)
        ))


def claim_enrichment_job(scan_id: int, kind: str) -> bool:
    """Acquire one running enrichment per scan/kind atomically."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        available = conn.execute(
            "SELECT 1 FROM scans WHERE id=? AND deletion_pending=0", (scan_id,)
        ).fetchone()
        if available is None:
            raise ScanUnavailable("Escaneo inexistente o pendiente de borrado")
        cursor = conn.execute(
            """INSERT INTO enrichment_jobs (scan_id, kind, status, error, updated_at)
               VALUES (?, ?, 'running', '', ?)
               ON CONFLICT(scan_id, kind) DO UPDATE SET status='running', error='',
                 updated_at=excluded.updated_at WHERE enrichment_jobs.status != 'running'""",
            (scan_id, kind, now()),
        )
        return cursor.rowcount == 1


def enrichment_claim_active(scan_id: int, kind: str) -> bool:
    with connect() as conn:
        return conn.execute(
            """SELECT 1 FROM enrichment_jobs j JOIN scans s ON s.id=j.scan_id
               WHERE s.id=? AND s.deletion_pending=0 AND j.kind=? AND j.status='running'""",
            (scan_id, kind),
        ).fetchone() is not None


def set_enrichment_status(scan_id: int, kind: str, status: str, error: str = "") -> None:
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        scan = conn.execute("SELECT deletion_pending FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            return  # A late callback must not recreate work or violate a deleted scan's FK.
        if status in {"running", "queued"} and scan["deletion_pending"]:
            raise ScanUnavailable("Escaneo pendiente de borrado")
        conn.execute(
            """INSERT INTO enrichment_jobs (scan_id, kind, status, error, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(scan_id, kind) DO UPDATE SET status=excluded.status,
                 error=excluded.error, updated_at=excluded.updated_at""",
            (scan_id, kind, status, error, now()),
        )


def get_enrichment_statuses(scan_id: int) -> dict[str, sqlite3.Row]:
    with connect() as conn:
        return {row["kind"]: row for row in conn.execute(
            "SELECT * FROM enrichment_jobs WHERE scan_id = ?", (scan_id,)
        )}


def reset_stale_enrichments() -> None:
    with connect() as conn:
        conn.execute(
            """UPDATE enrichment_jobs SET status='failed',
               error='Interrumpido al reiniciar el servidor', updated_at=?
            WHERE status='running'""", (now(),)
        )


def set_scan_context(scan_id: int, *, scope_id: int | None = None,
                     execution_context: dict[str, Any] | None = None) -> None:
    """Attach operator scope/execution metadata before results are persisted."""
    with connect() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            raise ValueError("Unknown scan")
        context = json.loads(scan["execution_context"] or "{}")
        context.update(execution_context or {})
        conn.execute("UPDATE scans SET scope_id=?,execution_context=? WHERE id=?",
                     (scope_id if scope_id is not None else scan["scope_id"], json.dumps(context), scan_id))


def create_scope(*, name: str, targets: str, exclusions: str, profile: str,
                 authorized_by: str, notes: str = "", pinned_targets: list[str],
                 resolutions: dict[str, Any], max_hosts: int = 4096) -> int:
    specification = {"targets": targets, "exclusions": exclusions, "profile": profile,
                         "authorized_by": authorized_by, "notes": notes,
                         "pinned_targets": pinned_targets, "resolutions": resolutions,
                         "max_hosts": max_hosts}
    with connect() as conn:
        cur = conn.execute("INSERT INTO saved_scopes(name,specification,created_at) VALUES(?,?,?)",
                           (name, json.dumps(specification), now()))
        return int(cur.lastrowid)


def get_scope(scope_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM saved_scopes WHERE id=?", (scope_id,)).fetchone()
        if row is None:
            return None
        return dict(json.loads(row["specification"]), id=row["id"], name=row["name"], created_at=row["created_at"])


def list_scopes(*, search: str = "", limit: int = 100, offset: int = 0) -> tuple[list[dict], int]:
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM saved_scopes WHERE name LIKE ?", ("%" + search + "%",)).fetchone()[0]
        rows = conn.execute("SELECT * FROM saved_scopes WHERE name LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                            ("%" + search + "%", min(max(1, limit), 1000), max(0, offset)))
        return [dict(json.loads(r["specification"]), id=r["id"], name=r["name"], created_at=r["created_at"]) for r in rows], total


def delete_scope(scope_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM saved_scopes WHERE id=?", (scope_id,))


def update_scope(scope_id: int, *, name: str, targets: str, exclusions: str, profile: str,
                 authorized_by: str, notes: str = "", pinned_targets: list[str],
                 resolutions: dict[str, Any], max_hosts: int = 4096) -> None:
    specification = {"targets": targets, "exclusions": exclusions, "profile": profile,
                     "authorized_by": authorized_by, "notes": notes,
                     "pinned_targets": pinned_targets, "resolutions": resolutions,
                     "max_hosts": max_hosts}
    with connect() as conn:
        cursor = conn.execute("UPDATE saved_scopes SET name=?,specification=? WHERE id=?", (name, json.dumps(specification), scope_id))
        if not cursor.rowcount:
            raise ValueError("Unknown scope")


def get_finding(finding_id: str) -> dict[str, Any] | None:
    from .continuity import current_item

    with connect() as conn:
        row = conn.execute("SELECT * FROM current_findings WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            return None
        item = current_item(row)
        asset = conn.execute("SELECT namespace,scope_id FROM assets WHERE id=?", (row["asset_id"],)).fetchone()
        item.update(namespace=asset["namespace"], scope_id=asset["scope_id"])
        return item


get_current_finding = get_finding


def list_current_findings(*, scope_id: int | None = None, asset_id: str | None = None,
                          status: str | None = None, search: str = "", limit: int = 100,
                          offset: int = 0, min_severity: int = 0,
                          assessment: str | None = None,
                          lifecycle: str | None = None) -> tuple[list[dict], int]:
    from .continuity import current_item

    clauses, params = ["1=1"], []
    for column, value in (("a.scope_id", scope_id), ("f.asset_id", asset_id), ("f.status", status)):
        if value is not None:
            clauses.append(column + "=?")
            params.append(value)
    clauses.append("json_extract(f.payload,'$.severity')>=?")
    params.append(min_severity)
    for column, value in (("json_extract(f.payload,'$.assessment')", assessment), ("f.lifecycle", lifecycle)):
        if value is not None:
            clauses.append(column + "=?")
            params.append(value)
    clauses.append("(json_extract(f.payload,'$.title') LIKE ? OR a.address LIKE ? OR f.rule_id LIKE ? OR json_extract(f.payload,'$.host') LIKE ?)")
    params.extend(["%" + search + "%"] * 4)
    query = " FROM current_findings f JOIN assets a ON a.id=f.asset_id WHERE " + " AND ".join(clauses)
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*)" + query, params).fetchone()[0]
        items = conn.execute("SELECT f.*" + query + " ORDER BY json_extract(f.payload,'$.severity') DESC,f.id LIMIT ? OFFSET ?",
                             (*params, min(max(1, limit), 1000), max(0, offset)))
        return [current_item(row) for row in items], total


def _asset_risk(conn, row) -> tuple[dict, int]:
    from .risk import asset_risk
    findings = [dict(r) for r in conn.execute("""SELECT id,scan_id,status,lifecycle,port,protocol,
      json_extract(payload,'$.host') AS host,json_extract(payload,'$.severity') AS severity,
      json_extract(payload,'$.assessment') AS assessment,json_extract(payload,'$.cve_ids') AS cves
      FROM current_findings WHERE asset_id=?""", (row["id"],))]
    for finding in findings:
        finding["cve_ids"] = json.loads(finding.pop("cves") or "[]")
    candidate_scans = {f["scan_id"] for f in findings if f["scan_id"]}
    if row["latest_scan_id"]:
        candidate_scans.add(row["latest_scan_id"])
    candidates = []
    for candidate_scan in candidate_scans:
        candidates.extend(dict(r) for r in conn.execute("SELECT host,port,protocol,cve_id,known_exploited,kev_assessed,kev_checked_at,epss,epss_date FROM cve_candidates WHERE scan_id=?", (candidate_scan,)))
    risk = asset_risk(findings, address=row["address"], criticality=row["criticality"], candidates=candidates)
    return risk, sum(f["lifecycle"] not in {"resolved", "evidence_unavailable"} and f["status"] != "closed" for f in findings)


def _asset_item(conn, row, *, detail: bool = False) -> dict:
    item = {key: row[key] for key in ("id", "namespace", "scope_id", "address", "criticality", "latest_at", "latest_scan_id")}
    item["risk"], item["finding_count"] = _asset_risk(conn, row)
    risk = item["risk"]
    risk["factor_total"] = len(risk["factors"])
    risk["factors"] = risk["factors"][:100] if detail else []
    risk["factors_url"] = f"/api/assets/{row['id']}/risk-factors"
    item["findings_url"] = f"/api/current-findings?asset_id={row['id']}"
    item["observations_url"] = f"/api/assets/{row['id']}/observations"
    item["aliases"] = [dict(r) for r in conn.execute("SELECT address,kind FROM asset_aliases WHERE asset_id=? ORDER BY kind,address LIMIT 100", (row["id"],))]
    item["alias_count"] = conn.execute("SELECT COUNT(*) FROM asset_aliases WHERE asset_id=?", (row["id"],)).fetchone()[0]
    if detail:
        ports, total = _asset_ports(conn, row["id"], limit=100, offset=0)
        item["current_state"] = {"ports": ports, "ports_total": total,
                                 "ports_url": f"/api/assets/{row['id']}/ports"}
    return item


def _asset_ports(conn, asset_id: str, *, limit: int, offset: int) -> tuple[list[dict], int]:
    query = " FROM assets a,json_each(a.latest_snapshot,'$.ports') p WHERE a.id=?"
    total = conn.execute("SELECT COUNT(*)" + query, (asset_id,)).fetchone()[0]
    fields = ("address", "portid", "protocol", "state", "service_name", "product", "version", "current_assessment", "network_scan_id")
    columns = ",".join("substr(json_extract(p.value,'$." + field + "'),1,256) AS " + field if field not in {"portid", "network_scan_id"} else "json_extract(p.value,'$." + field + "') AS " + field for field in fields)
    rows = conn.execute("SELECT " + columns + query + " ORDER BY p.key LIMIT ? OFFSET ?", (asset_id, min(max(1, limit), 100), max(0, offset)))
    return [dict(r) for r in rows], total


def list_asset_ports(asset_id: str, *, limit: int = 100, offset: int = 0) -> tuple[list[dict], int]:
    with connect() as conn:
        return _asset_ports(conn, asset_id, limit=limit, offset=offset)


def list_asset_risk_factors(asset_id: str, *, limit: int = 100, offset: int = 0) -> tuple[list[dict], int]:
    with connect() as conn:
        row = conn.execute("SELECT id,address,criticality,latest_scan_id FROM assets WHERE id=?", (asset_id,)).fetchone()
        if row is None:
            return [], 0
        risk, _ = _asset_risk(conn, row)
        return risk["factors"][max(0, offset):max(0, offset) + min(max(1, limit), 100)], len(risk["factors"])


def list_assets(*, scope_id: int | None = None, search: str = "", limit: int = 100,
                offset: int = 0) -> tuple[list[dict], int]:
    query = " FROM assets WHERE (address LIKE ? OR EXISTS (SELECT 1 FROM asset_aliases a WHERE a.asset_id=assets.id AND a.address LIKE ?))"
    params: list[Any] = ["%" + search + "%"] * 2
    if scope_id is not None:
        query += " AND scope_id=?"
        params.append(scope_id)
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*)" + query, params).fetchone()[0]
        rows = conn.execute("SELECT id,namespace,scope_id,address,criticality,latest_at,latest_scan_id" + query + " ORDER BY latest_at DESC,id LIMIT ? OFFSET ?",
                            (*params, min(max(1, limit), 1000), max(0, offset))).fetchall()
        return [_asset_item(conn, row) for row in rows], total


def get_asset(asset_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT id,namespace,scope_id,address,criticality,latest_at,latest_scan_id FROM assets WHERE id=?", (asset_id,)).fetchone()
        if row is None:
            return None
        item = _asset_item(conn, row, detail=True)
        query = """ FROM (SELECT asset_id,scan_id,observed_at,snapshot,coverage,'scan' AS kind
                           FROM asset_observations UNION ALL
                           SELECT asset_id,scan_id,observed_at,snapshot,coverage,kind
                           FROM enrichment_observations) WHERE asset_id=?"""
        item["observation_count"] = conn.execute("SELECT COUNT(*)" + query, (asset_id,)).fetchone()[0]
        return item


def list_asset_observations(asset_id: str, *, limit: int = 100, offset: int = 0,
                            summaries: bool = False) -> tuple[list[dict], int]:
    with connect() as conn:
        query = """ FROM (SELECT asset_id,scan_id,observed_at,snapshot,coverage,'scan' AS kind
                           FROM asset_observations UNION ALL
                           SELECT asset_id,scan_id,observed_at,snapshot,coverage,kind
                           FROM enrichment_observations) WHERE asset_id=?"""
        total = conn.execute("SELECT COUNT(*)" + query, (asset_id,)).fetchone()[0]
        projection = "asset_id,scan_id,observed_at,kind,json_object('state',json_extract(snapshot,'$.state')) AS snapshot,json_object('status',json_extract(coverage,'$.status'),'engine',json_extract(coverage,'$.engine')) AS coverage" if summaries else "*"
        rows = conn.execute("SELECT " + projection + query + " ORDER BY observed_at DESC LIMIT ? OFFSET ?", (asset_id, min(max(1, limit), 1000), max(0, offset)))
        return [dict(dict(r), snapshot=json.loads(r["snapshot"]), coverage=json.loads(r["coverage"])) for r in rows], total


def current_summary() -> dict:
    from .continuity import current_item

    with connect() as conn:
        rows = [current_item(r) for r in conn.execute("SELECT * FROM current_findings WHERE status!='closed' AND lifecycle NOT IN ('resolved','evidence_unavailable')")]
        return {"assets": conn.execute("SELECT COUNT(*) FROM assets WHERE latest_scan_id IS NOT NULL").fetchone()[0],
                "findings": len(rows), "severity": {s.slug: sum(int(r["severity"]) == int(s) for r in rows) for s in Severity},
                "assessment": {a.value: sum(r["assessment"] == a.value for r in rows) for a in Assessment},
                "not_assessed": sum(r["lifecycle"] == "not_assessed" for r in rows),
                "expired_exceptions": sum(r["exception_expired"] for r in rows)}


def scan_delta(scan_id: int) -> dict:
    with connect() as conn:
        row = conn.execute("SELECT delta FROM scan_deltas WHERE scan_id=?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else {"hosts": [], "ports": [], "services": [], "findings": [], "coverage": {"status": "unknown"}, "warnings": ["No persisted comparison"]}


def add_asset_alias(asset_id: str, address: str, *, actor: str) -> None:
    import ipaddress

    address = str(ipaddress.ip_address(address))
    if not actor.strip():
        raise ValueError("Actor required")
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        asset = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if asset is None:
            raise ValueError("Unknown asset")
        existing = conn.execute("SELECT asset_id FROM asset_aliases WHERE namespace=? AND address=? AND kind='address'", (asset["namespace"], address)).fetchone()
        if existing and existing[0] != asset_id:
            raise ValueError("Address belongs to a different asset; merging is not inferred")
        conn.execute("INSERT OR IGNORE INTO asset_aliases(namespace,address,asset_id,actor) VALUES(?,?,?,?)", (asset["namespace"], address, asset_id, actor))
        conn.execute("INSERT INTO asset_actions(asset_id,actor,created_at,action,payload) VALUES(?,?,?,'alias',?)", (asset_id, actor, now(), json.dumps({"address": address})))


def set_asset_criticality(asset_id: str, criticality: int, *, actor: str) -> None:
    if criticality not in range(1, 6) or not actor.strip():
        raise ValueError("Criticality must be 1..5 and actor is required")
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute("UPDATE assets SET criticality=? WHERE id=?", (criticality, asset_id))
        if not cursor.rowcount:
            raise ValueError("Unknown asset")
        conn.execute("INSERT INTO asset_actions(asset_id,actor,created_at,action,payload) VALUES(?,?,?,'criticality',?)", (asset_id, actor, now(), json.dumps({"criticality": criticality})))


def update_asset_metadata(asset_id: str, criticality: int, *, alias: str = "", actor: str) -> None:
    """Validate combined metadata before any mutation; one transaction and audit."""
    import ipaddress

    if type(criticality) is not int or criticality not in range(1, 6) or not actor.strip():
        raise ValueError("Criticality must be 1..5 and actor is required")
    address = str(ipaddress.ip_address(alias)) if alias.strip() else ""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        asset = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if asset is None:
            raise ValueError("Unknown asset")
        if address:
            existing = conn.execute("SELECT asset_id FROM asset_aliases WHERE namespace=? AND address=? AND kind='address'", (asset["namespace"], address)).fetchone()
            if existing and existing[0] != asset_id:
                raise ValueError("Address belongs to a different asset")
            conn.execute("INSERT OR IGNORE INTO asset_aliases(namespace,address,asset_id,actor) VALUES(?,?,?,?)", (asset["namespace"], address, asset_id, actor))
        conn.execute("UPDATE assets SET criticality=? WHERE id=?", (criticality, asset_id))
        conn.execute("INSERT INTO asset_actions(asset_id,actor,created_at,action,payload) VALUES(?,?,?,'metadata',?)", (asset_id, actor, now(), json.dumps({"criticality": criticality, "alias": address})))


def update_remediation(finding_id: str, *, actor: str, owner: str | None = None,
                       status: str | None = None, due_at: str | None = None,
                       exception_until: str | None = None, evidence: str | None = None,
                       verification_scan_id: int | None = None) -> dict:
    from .continuity import current_item, timestamp

    if not actor.strip():
        raise ValueError("Actor required")
    if status is not None and status not in {"open", "in_progress", "exception", "closed"}:
        raise ValueError("Invalid remediation status")
    for value in (due_at, exception_until):
        if value:
            timestamp(value)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM current_findings WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown finding")
        before = current_item(row)
        after = dict(before)
        for field, value in (("owner", owner), ("status", status), ("due_at", due_at), ("exception_until", exception_until)):
            if value is not None:
                after[field] = value
        if after["status"] == "exception" and (not after["exception_until"] or timestamp(after["exception_until"]) <= timestamp() or not evidence or len(evidence.strip()) < 10):
            raise ValueError("Exception requires future expiry and meaningful rationale")
        if status == "closed":
            if row["lifecycle"] != "resolved" or verification_scan_id != row["verification_scan_id"] or not evidence or len(evidence.strip()) < 10:
                raise ValueError("Closure requires compatible successful verification and meaningful evidence")
            verification = conn.execute("SELECT * FROM scans WHERE id=?", (verification_scan_id,)).fetchone()
            if verification is None or verification["status"] != "done":
                raise ValueError("Verification scan must be completed successfully")
            context = json.loads(verification["execution_context"] or "{}")
            if finding_id not in context.get("verification_of", []):
                raise ValueError("Verification must explicitly assess this finding")
            after["closure_evidence"] = evidence.strip()
        conn.execute("UPDATE current_findings SET owner=?,status=?,due_at=?,exception_until=?,closure_evidence=? WHERE id=?", (after["owner"], after["status"], after["due_at"], after["exception_until"], after["closure_evidence"], finding_id))
        conn.execute("INSERT INTO remediation_actions(finding_id,actor,created_at,before_state,after_state,evidence,verification_scan_id) VALUES(?,?,?,?,?,?,?)", (finding_id, actor, now(), json.dumps(before), json.dumps(after), evidence or "", verification_scan_id))
        return after


def remediation_history(finding_id: str) -> list[dict]:
    with connect() as conn:
        return [dict(dict(row), before_state=json.loads(row["before_state"]), after_state=json.loads(row["after_state"])) for row in conn.execute("SELECT * FROM remediation_actions WHERE finding_id=? ORDER BY id", (finding_id,))]
