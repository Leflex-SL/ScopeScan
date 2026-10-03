from __future__ import annotations

from scopescan import config, db


def test_existing_history_is_reused_after_rename():
    scan_id = db.create_scan(name="historico", targets="127.0.0.1", profile="rapido")
    original = config.db_path()
    legacy = original.with_name("medscan.sqlite3")
    original.rename(legacy)

    db.init_db()

    assert config.db_path() == legacy
    assert db.get_scan(scan_id)["name"] == "historico"
    assert not original.exists()


def test_current_database_takes_priority_over_legacy():
    current = config.db_path()
    current.with_name("medscan.sqlite3").write_bytes(b"legacy")
    assert config.db_path() == current


def test_legacy_data_directory_is_supported(tmp_path, monkeypatch):
    monkeypatch.delenv("SCOPESCAN_DATA")
    monkeypatch.setenv("MEDSCAN_DATA", str(tmp_path / "legacy"))
    assert config.data_dir() == tmp_path / "legacy"
    monkeypatch.setenv("SCOPESCAN_DATA", str(tmp_path / "current"))
    assert config.data_dir() == tmp_path / "current"


def test_empty_current_flag_overrides_legacy_enablement(monkeypatch):
    monkeypatch.setenv("MEDSCAN_ENABLE_EXPLOIT", "1")
    monkeypatch.setenv("SCOPESCAN_ENABLE_EXPLOIT", "")
    assert not config.msf_exploit_enabled()


def test_legacy_panel_credentials_and_new_prefix_are_not_mixed(monkeypatch):
    monkeypatch.delenv("SCOPESCAN_PANEL_USER", raising=False)
    monkeypatch.delenv("SCOPESCAN_PANEL_PASSWORD", raising=False)
    monkeypatch.setenv("MEDSCAN_PANEL_USER", "legacy")
    monkeypatch.setenv("MEDSCAN_PANEL_PASSWORD", "old-secret")
    assert config.panel_auth_matches("legacy", "old-secret")

    monkeypatch.setenv("SCOPESCAN_PANEL_USER", "current")
    assert config.panel_auth_credentials() is None

    monkeypatch.setenv("SCOPESCAN_PANEL_PASSWORD", "new-secret")
    assert config.panel_auth_matches("current", "new-secret")
    assert not config.panel_auth_matches("legacy", "old-secret")
