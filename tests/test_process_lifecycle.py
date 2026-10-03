from __future__ import annotations

import os
import sys
import threading
import time

import pytest

from scopescan import msf_runner, nmap_runner, process_runner


@pytest.mark.parametrize("runner,flag", [(nmap_runner, "-oX"), (msf_runner, "-r")])
def test_silent_process_cancellation(runner, flag, tmp_path):
    cancel = threading.Event()
    timer = threading.Timer(.2, cancel.set)
    timer.start()
    started = time.monotonic()
    try:
        result = runner.run([sys.executable, "-c", "import time; time.sleep(20)",
                             flag, str(tmp_path / "output")], cancel=cancel, timeout=10)
    finally:
        timer.cancel()
    assert result.cancelled
    assert not result.ok
    assert time.monotonic() - started < 5


def test_silent_deadline():
    result = process_runner.run_process(
        [sys.executable, "-c", "import time; time.sleep(20)"], timeout=.3)
    assert result.timed_out
    assert not result.cancelled
    assert result.returncode != 0


def test_output_bound_and_both_pipes():
    result = process_runner.run_process([
        sys.executable, "-c",
        "import sys; sys.stdout.write('x'*2000000); sys.stderr.write('y'*2000000)"
    ], timeout=10, max_output_chars=4096)
    assert result.returncode == 0
    assert result.output_truncated
    assert result.stdout == "x" * 4096
    assert result.stderr == "y" * 4096


def test_callback_failure_terminates_and_closes_pipes(monkeypatch):
    processes = []
    original = process_runner.subprocess.Popen

    def recorded(*args, **kwargs):
        proc = original(*args, **kwargs)
        processes.append(proc)
        return proc

    monkeypatch.setattr(process_runner.subprocess, "Popen", recorded)

    def fail(_line):
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed"):
        process_runner.run_process(
            [sys.executable, "-c", "import time; print('progress',flush=True); time.sleep(20)"],
            on_line=fail, timeout=10)
    assert processes[0].poll() is not None
    assert processes[0].stdout.closed
    assert processes[0].stderr.closed


def test_pre_cancelled_does_not_spawn(monkeypatch):
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(process_runner.subprocess, "Popen",
                        lambda *args, **kwargs: pytest.fail("should not spawn"))
    assert process_runner.run_process(["anything"], cancel=cancel).cancelled


def test_cancellation_kills_descendant_that_holds_pipes(tmp_path):
    marker = tmp_path / "child-survived"
    child_code = (
        f"import time,pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).write_text('alive')"
    )
    code = (
        "import subprocess,sys,time; "
        f"child={child_code!r}; "
        "subprocess.Popen([sys.executable,'-c',child]); "
        "print('child spawned',flush=True); time.sleep(20)"
    )
    cancel = threading.Event()
    result = process_runner.run_process(
        [sys.executable, "-c", code], cancel=cancel, timeout=10,
        on_line=lambda _line: cancel.set())
    assert result.cancelled
    time.sleep(2.1)
    assert not marker.exists(), "descendant survived cancellation"


@pytest.mark.skipif(os.name != "nt", reason="Windows job assignment gate")
def test_job_assignment_failure_never_launches_target(monkeypatch, tmp_path):
    marker = tmp_path / "engine-started"

    def denied(_proc):
        raise OSError("job assignment denied")

    monkeypatch.setattr(process_runner, "_WindowsJob", denied)
    with pytest.raises(OSError, match="job assignment denied"):
        process_runner.run_process([
            sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"
        ], timeout=5)
    assert not marker.exists()
