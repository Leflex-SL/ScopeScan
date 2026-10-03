"""Bounded subprocess output, independent deadlines and whole-tree cancellation."""

from __future__ import annotations

import codecs
import json
import os
import queue
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

MAX_OUTPUT_CHARS = 2 * 1024 * 1024
MAX_LINE_CHARS = 16384

# A gated launcher prevents the target from spawning before assignment to its job.
WINDOWS_LAUNCHER = (
    "import json,subprocess,sys; "
    "argv=json.loads(sys.stdin.buffer.readline()); "
    "sys.exit(subprocess.call(argv,stdin=subprocess.DEVNULL))"
)


class _WindowsJob:
    """Owned nested job; all children inherit membership after the stdin gate.

    https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
    """

    def __init__(self, proc: subprocess.Popen) -> None:
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t),
                ("maximum", ctypes.c_size_t), ("active", wintypes.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD),
            ]

        class Limits(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel = kernel
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Limits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        try:
            if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits),
                                                   ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not kernel.AssignProcessToJobObject(self.handle, int(proc._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            self.close()
            raise

    def terminate(self) -> None:
        if not self.kernel.TerminateJobObject(self.handle, 1):
            # Closing the last handle also enforces KILL_ON_JOB_CLOSE.
            self.close()

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str
    cancelled: bool = False
    timed_out: bool = False
    output_truncated: bool = False
    file_limit_exceeded: bool = False
    file_limit_path: str = ""
    file_limit_reason: str = ""


def _terminate_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        proc._scopescan_job.terminate()
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.kill()
        proc.wait(timeout=5)
    if os.name != "nt":
        # The parent can exit first while descendants retain the output pipes.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_process(
    argv: list[str], *, cancel: threading.Event | None = None,
    timeout: float | None = None, on_line: Callable[[str], None] | None = None,
    max_output_chars: int = MAX_OUTPUT_CHARS,
    env: Mapping[str, str] | None = None, cwd: str | Path | None = None,
    file_limits: Mapping[str | Path, int] | None = None,
    deadline: float | None = None,
) -> ProcessResult:
    if timeout is not None and timeout <= 0:
        raise ValueError("Timeout must be positive")
    if max_output_chars <= 0:
        raise ValueError("Output limit must be positive")
    import math

    if deadline is not None and not math.isfinite(deadline):
        raise ValueError("Deadline must be finite")
    if timeout is not None and not math.isfinite(timeout):
        raise ValueError("Timeout must be finite")
    started = time.monotonic()
    if timeout is not None:
        relative_deadline = started + timeout
        deadline = min(deadline, relative_deadline) if deadline is not None else relative_deadline
    monitored = []
    for path, limit in (file_limits or {}).items():
        if type(limit) is not int or limit <= 0:
            raise ValueError("File output limit must be a positive integer")
        monitored.append((Path(path).absolute(), limit))

    def file_limit_check() -> tuple[str, str]:
        for path, limit in monitored:
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode):
                return str(path), "Output file is not a regular file"
            if info.st_size > limit:
                return str(path), "Output file exceeded byte limit"
        return "", ""

    if cancel is not None and cancel.is_set():
        return ProcessResult(-1, "", "", cancelled=True)
    if deadline is not None and started >= deadline:
        return ProcessResult(-1, "", "", timed_out=True)
    exceeded_path, exceeded_reason = file_limit_check()
    if exceeded_path:
        return ProcessResult(-1, "", "", file_limit_exceeded=True,
                             file_limit_path=exceeded_path, file_limit_reason=exceeded_reason)
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {
        "start_new_session": True
    }
    options.update(env=dict(env) if env is not None else None, cwd=cwd)
    job = None
    if os.name == "nt":
        proc = subprocess.Popen([sys.executable, "-c", WINDOWS_LAUNCHER],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, **options)
        try:
            job = _WindowsJob(proc)
            proc._scopescan_job = job
            proc.stdin.write((json.dumps(argv) + "\n").encode("utf-8"))
            proc.stdin.close()
        except BaseException:
            if job is not None:
                job.close()
            proc.kill()
            proc.wait(timeout=5)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
            raise
    else:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    messages: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=64)
    stopping = threading.Event()

    def reader(channel: str, stream) -> None:
        try:
            while not stopping.is_set():
                chunk = stream.read1(4096)
                while not stopping.is_set():
                    try:
                        messages.put((channel, chunk or None), timeout=.05)
                        break
                    except queue.Full:
                        pass
                if not chunk:
                    break
        finally:
            stream.close()

    readers = [threading.Thread(target=reader, args=(channel, stream), daemon=True)
               for channel, stream in (("stdout", proc.stdout), ("stderr", proc.stderr))]
    for thread in readers:
        thread.start()
    decoders = {name: codecs.getincrementaldecoder("utf-8")("replace")
                for name in ("stdout", "stderr")}
    output = {"stdout": "", "stderr": ""}
    open_streams = set(output)
    pending_line = ""
    cancelled = timed_out = truncated = False
    try:
        while open_streams or proc.poll() is None:
            if cancel is not None and cancel.is_set():
                cancelled = True
                _terminate_tree(proc)
                break
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                _terminate_tree(proc)
                break
            exceeded_path, exceeded_reason = file_limit_check()
            if exceeded_path:
                _terminate_tree(proc)
                break
            try:
                channel, chunk = messages.get(timeout=.05)
            except queue.Empty:
                continue
            decoded = decoders[channel].decode(chunk or b"", final=chunk is None)
            combined = output[channel] + decoded
            if len(combined) > max_output_chars:
                truncated = True
            output[channel] = combined[-max_output_chars:]
            if channel == "stdout" and on_line is not None:
                pending_line += decoded
                while "\n" in pending_line or len(pending_line) >= MAX_LINE_CHARS:
                    newline = pending_line.find("\n")
                    length = newline + 1 if 0 <= newline < MAX_LINE_CHARS else MAX_LINE_CHARS
                    line, pending_line = pending_line[:length], pending_line[length:]
                    on_line(line.rstrip())
            if chunk is None:
                open_streams.discard(channel)
        if pending_line and on_line is not None and not (cancelled or timed_out):
            on_line(pending_line.rstrip())
        proc.wait(timeout=5)
        if not exceeded_path:
            exceeded_path, exceeded_reason = file_limit_check()
            if exceeded_path:
                _terminate_tree(proc)
    except BaseException:
        _terminate_tree(proc)
        raise
    finally:
        if job is not None:
            job.close()
        stopping.set()
        for thread in readers:
            thread.join(timeout=2)
        if proc.poll() is None:
            _terminate_tree(proc)
    return ProcessResult(proc.returncode, output["stdout"].rstrip(), output["stderr"].rstrip(),
                         cancelled, timed_out, truncated, bool(exceeded_path),
                         exceeded_path, exceeded_reason)
