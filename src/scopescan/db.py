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


def create_scan(
    *,
    name: str,
    targets: str,
    profile: str,
    target_private: bool = True,
    authorized_by: str = "",
    notes: str = "",
) -> int:
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO scans (name, targets, profile, status, created_at,
                                  target_private, authorized_by, notes)
               VALUES (?, ?, ?, 'queued', ?, ?, ?, ?)""",
            (name, targets, profile, now(), int(target_private), authorized_by, notes),
        )
        return int(cur.lastrowid)


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
                                         remediation, cvss, cves, confirmed, assessment)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                ),
            )

        conn.execute(
            """UPDATE scans SET hosts_up = ?, hosts_total = ?, elapsed = ?,
                                risk_score = ?, progress = 100 WHERE id = ?""",
            (run.hosts_up, run.hosts_total, run.elapsed, risk, scan_id),
        )


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
                   confirmed, assessment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (scan_id, f.host, f.port, f.protocol, f.service, f.title,
                     int(f.severity), f.source, f.description, f.evidence, f.remediation,
                     f.cvss, json.dumps(f.cve_ids), int(f.confirmed), f.assessment.value)
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
