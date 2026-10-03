"""Copy a legacy data directory safely, retaining originals and a recovery snapshot.

Run with the legacy panel stopped for a consistent XML/report + database snapshot.
SQLite's backup API incorporates committed WAL data without copying journal files.
Existing destination files are never overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

PATH_COLUMNS = {"scans": ("raw_xml_path",), "exploit_runs": ("rc_path", "log_path")}


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _quoted(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def counts(connection: sqlite3.Connection) -> dict[str, int]:
    tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {
        name: connection.execute(f"SELECT COUNT(*) FROM {_quoted(name)}").fetchone()[0]
        for (name,) in tables.fetchall()
    }


def relocate(value: str, source: Path, destination: Path) -> str:
    """Rewrite only paths inside the copied data tree, never external tool paths."""
    if not value:
        return value
    normalized = value.replace("\\", "/")
    prefix = str(source).replace("\\", "/").rstrip("/")
    if normalized.casefold().startswith(prefix.casefold() + "/"):
        return str(destination / Path(normalized[len(prefix) + 1 :]))
    return value


def consolidate(source: Path, destination: Path, legacy_roots: tuple[Path, ...] = ()) -> dict:
    source, destination = source.resolve(strict=True), destination.resolve()
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("Source and destination must be separate, non-nested directories")
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError("Destination must be empty; existing files will not be overwritten")
    destination.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.name.endswith(("-wal", "-shm", "-journal")):
            continue
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix not in {".sqlite3", ".sqlite", ".db"}:
            shutil.copy2(path, target)
            digest = sha256(path)
            if digest != sha256(target):
                raise RuntimeError(f"Hash mismatch: {relative}")
            records.append({"path": relative.as_posix(), "sha256": digest})
            continue
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as original, \
                closing(sqlite3.connect(target)) as copied:
            original.backup(copied)
        recovery = destination / "consolidation-recovery" / relative
        recovery.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, recovery)
        rewrites = 0
        with closing(sqlite3.connect(target)) as copied, copied:
            before = counts(copied)
            for table, columns in PATH_COLUMNS.items():
                existing = {row[1] for row in copied.execute(f"PRAGMA table_info({_quoted(table)})")}
                for column in columns:
                    if column not in existing:
                        continue
                    for rowid, value in copied.execute(
                        f"SELECT rowid, {_quoted(column)} FROM {_quoted(table)}"
                    ).fetchall():
                        updated = relocate(value, source, destination)
                        for legacy in legacy_roots:
                            updated = relocate(updated, legacy, destination)
                        if updated != value:
                            copied.execute(
                                f"UPDATE {_quoted(table)} SET {_quoted(column)}=? WHERE rowid=?",
                                (updated, rowid),
                            )
                            rewrites += 1
            if counts(copied) != before:
                raise RuntimeError(f"Row counts changed: {relative}")
            if copied.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError(f"SQLite integrity check failed: {relative}")
        records.append({"path": relative.as_posix(), "tables": before, "path_updates": rewrites,
                        "recovery_sha256": sha256(recovery), "sha256": sha256(target)})
    manifest = {"source": str(source), "destination": str(destination), "files": records}
    (destination / "consolidation-manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--legacy-data-root", type=Path, action="append", default=[])
    args = parser.parse_args()
    print(json.dumps(consolidate(args.source, args.destination, tuple(args.legacy_data_root)),
                     indent=2))
