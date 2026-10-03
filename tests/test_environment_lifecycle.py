from __future__ import annotations

from scopescan import config


def test_probe_cache_ttl_manual_refresh_and_configuration(monkeypatch):
    clock = [100.0]
    calls = []
    monkeypatch.setattr(config, "_environment_cache", None)
    monkeypatch.setattr(config.time, "monotonic", lambda: clock[0])
    snapshot = config.Environment(None, None, False, "test-data")

    def probe():
        calls.append(clock[0])
        return snapshot

    monkeypatch.setattr(config, "_probe_environment", probe)
    assert config.probe_environment() is snapshot
    assert config.probe_environment() is snapshot
    assert len(calls) == 1
    config.probe_environment(refresh=True)
    assert len(calls) == 2
    clock[0] += config.ENVIRONMENT_CACHE_TTL + 1
    config.probe_environment()
    assert len(calls) == 3
    monkeypatch.setenv("SCOPESCAN_NMAP", "changed")
    config.probe_environment()
    assert len(calls) == 4


def test_installed_data_directory_is_user_owned(monkeypatch, tmp_path):
    monkeypatch.delenv("SCOPESCAN_DATA")
    monkeypatch.delenv("MEDSCAN_DATA", raising=False)
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path / "site-packages")
    monkeypatch.setattr(config.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-appdata"))
    assert config.data_dir() == tmp_path / "local-appdata" / "ScopeScan"


def test_existing_project_data_has_priority(monkeypatch, tmp_path):
    monkeypatch.delenv("SCOPESCAN_DATA")
    monkeypatch.delenv("MEDSCAN_DATA", raising=False)
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    (tmp_path / "data").mkdir()
    assert config.data_dir() == tmp_path / "data"


def test_scan_deadline_configuration(monkeypatch):
    monkeypatch.setenv("SCOPESCAN_SCAN_TIMEOUT", "42")
    assert config.scan_timeout() == 42
