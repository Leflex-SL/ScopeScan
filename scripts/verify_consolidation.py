"""Capture current mutable databases separately from immutable recovery hashes."""
from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from consolidate_data import counts, sha256


def verify(data: Path) -> dict:
    data = data.resolve(strict=True)
    manifest = json.loads((data / "consolidation-manifest.json").read_text(encoding="utf-8"))
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    capture = data / "consolidation-verification" / stamp
    capture.mkdir(parents=True, exist_ok=False)
    records = []
    for entry in manifest["files"]:
        path = data / entry["path"]
        if "recovery_sha256" not in entry:
            if sha256(path) != entry["sha256"]:
                raise RuntimeError(f"Preserved artifact changed: {entry['path']}")
            records.append({"path": entry["path"], "sha256": entry["sha256"]})
            continue
        recovery = data / "consolidation-recovery" / entry["path"]
        if sha256(recovery) != entry["recovery_sha256"]:
            raise RuntimeError(f"Immutable recovery changed: {entry['path']}")
        snapshot = capture / entry["path"]
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as original, \
                closing(sqlite3.connect(snapshot)) as copied:
            original.backup(copied)
            current_counts = counts(copied)
            if copied.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError(f"Corrupt database: {entry['path']}")
            for table, original_count in entry["tables"].items():
                if current_counts.get(table) != original_count:
                    raise RuntimeError(f"Preserved row count differs: {entry['path']} / {table}")
            xml_paths = []
            if "scans" in current_counts:
                xml_paths = [value for (value,) in copied.execute(
                    "SELECT raw_xml_path FROM scans") if value]
        records.append({"path": entry["path"], "recovery_sha256": sha256(recovery),
                        "current_snapshot_sha256": sha256(snapshot), "tables": current_counts,
                        "raw_paths": xml_paths})
    record = {"captured_at": datetime.now(UTC).isoformat(),
              "note": "Mutable database snapshots after relocation/application schema migration; "
                      "the initial manifest is historical, recovery snapshots remain unchanged.",
              "files": records}
    (capture / "verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.data), indent=2))
