"""Exercise actual local Python programs; never run external scan targets."""

import json
import os
import sys
import threading
import time

import pytest

from scopescan.process_runner import run_process


def test_explicit_environment_and_working_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOPESCAN_TEST_PARENT_SECRET", "must-not-inherit")
    env = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR"}}
    env["SCOPESCAN_TEST_ALLOWED"] = "allowed"
    result = run_process([sys.executable, "-c",
                          "import json,os; print(json.dumps({'cwd':os.getcwd(),'allowed':os.getenv('SCOPESCAN_TEST_ALLOWED'),'secret':os.getenv('SCOPESCAN_TEST_PARENT_SECRET')}))"],
                         env=env, cwd=tmp_path, timeout=5)
    data = json.loads(result.stdout)
    assert result.returncode == 0
    assert data["cwd"] == str(tmp_path)
    assert data["allowed"] == "allowed"
    assert data["secret"] is None


def test_silent_output_file_limit_terminates_before_parse(tmp_path):
    output = tmp_path / "output.json"
    result = run_process([sys.executable, "-c",
                          ("import pathlib,time; "
                          f"p=pathlib.Path({str(output)!r}); p.write_bytes(b'x'*8192); time.sleep(20)")],
                         timeout=5, file_limits={output: 1024})
    assert result.file_limit_exceeded
    assert result.file_limit_path == str(output)
    assert "byte limit" in result.file_limit_reason
    assert result.returncode != 0
    assert not result.timed_out


def test_fast_output_file_limit_is_checked_after_process_exit(tmp_path):
    output = tmp_path / "output.json"
    result = run_process([sys.executable, "-c",
                          f"import pathlib; pathlib.Path({str(output)!r}).write_bytes(b'x'*8192)"],
                         timeout=5, file_limits={output: 1024})
    assert result.file_limit_exceeded


def test_file_limit_kills_descendant_with_silent_redirected_pipes(tmp_path):
    output, marker = tmp_path / "output", tmp_path / "survived"
    child = f"import time,pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).touch()"
    code = ("import subprocess,sys,pathlib,time; "
            f"subprocess.Popen([sys.executable,'-c',{child!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
            f"pathlib.Path({str(output)!r}).write_bytes(b'x'*8192); time.sleep(20)")
    result = run_process([sys.executable, "-c", code], timeout=5, file_limits={output: 1024})
    assert result.file_limit_exceeded
    time.sleep(2.1)
    assert not marker.exists()


def test_absolute_deadline_not_reset_across_process_calls():
    deadline = time.monotonic() + 3
    first = run_process([sys.executable, "-c", "import time;time.sleep(.2)"], deadline=deadline)
    assert first.returncode == 0
    # The second process receives the first call's deadline, not a fresh timeout.
    before = time.monotonic()
    second = run_process([sys.executable, "-c", "import time;time.sleep(20)"], deadline=deadline)
    assert second.timed_out
    assert time.monotonic() - before < 3.5


def test_expired_deadline_does_not_spawn(monkeypatch):
    monkeypatch.setattr("scopescan.process_runner.subprocess.Popen", lambda *a, **k: pytest.fail("spawned"))
    assert run_process(["unavailable"], deadline=time.monotonic() - 1).timed_out


def test_file_monitors_do_not_interfere_with_silent_cancellation(tmp_path):
    cancel = threading.Event()
    timer = threading.Timer(.2, cancel.set)
    timer.start()
    try:
        result = run_process([sys.executable, "-c", "import time;time.sleep(20)"],
                             timeout=5, cancel=cancel, file_limits={tmp_path / "absent": 1024})
    finally:
        timer.cancel()
    assert result.cancelled
    assert not result.file_limit_exceeded


def test_nonregular_output_refused_before_spawn(tmp_path, monkeypatch):
    monkeypatch.setattr("scopescan.process_runner.subprocess.Popen", lambda *a, **k: pytest.fail("spawned"))
    result = run_process(["unavailable"], file_limits={tmp_path: 1024})
    assert result.file_limit_exceeded
    assert "regular file" in result.file_limit_reason
