from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "consolidate_data", Path(__file__).parents[1] / "scripts" / "consolidate_data.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_committed_wal_preserved_with_paths_and_recovery(tmp_path):
    source, target = tmp_path / "old", tmp_path / "new"
    (source / "raw").mkdir(parents=True)
    artifact = source / "raw" / "scan.xml"
    artifact.write_text("<nmaprun/>")
    connection = sqlite3.connect(source / "medscan.sqlite3")
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE scans(id INTEGER PRIMARY KEY, raw_xml_path TEXT)")
        connection.execute("INSERT INTO scans VALUES(1, ?)", (str(artifact),))
        connection.commit()
        assert Path(str(source / "medscan.sqlite3") + "-wal").exists()
        manifest = module.consolidate(source, target)
        entry = next(item for item in manifest["files"] if item["path"] == "medscan.sqlite3")
        assert entry["sha256"] == module.sha256(target / "medscan.sqlite3")
        assert entry["recovery_sha256"] == module.sha256(
            target / "consolidation-recovery" / "medscan.sqlite3")
        assert entry["sha256"] != entry["recovery_sha256"]
        assert connection.execute("SELECT raw_xml_path FROM scans").fetchone()[0] == str(artifact)
        with sqlite3.connect(target / "medscan.sqlite3") as copied:
            assert copied.execute("SELECT raw_xml_path FROM scans").fetchone()[0] == str(
                target / "raw" / "scan.xml")
            assert copied.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        with sqlite3.connect(target / "consolidation-recovery" / "medscan.sqlite3") as recovery:
            assert recovery.execute("SELECT raw_xml_path FROM scans").fetchone()[0] == str(artifact)
        assert len(manifest["files"]) == 2
        assert (target / "raw" / "scan.xml").read_text() == artifact.read_text()
        with pytest.raises(FileExistsError):
            module.consolidate(source, target)
    finally:
        connection.close()


def test_path_relocation_does_not_touch_sibling_or_external_tools(tmp_path):
    source, target = tmp_path / "old", tmp_path / "new"
    unrelated = str(tmp_path / "old-other" / "tool.rc")
    assert module.relocate(unrelated, source, target) == unrelated


def test_legacy_windows_path_case_and_separator_support():
    assert module.relocate("c:/OLD/data/raw/x.xml", Path("C:/old/data"),
                           Path("C:/new/data")).replace("\\", "/") == "C:/new/data/raw/x.xml"
