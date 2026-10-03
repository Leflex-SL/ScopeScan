"""Explicitly authorized, isolated Syft 1.54.0 external-process cataloguing."""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path

from ._adapter_support import command_for, isolated_environment
from .engine_store import redact_text
from .process_runner import run_process
from .sbom import MAX_BYTES, parse

VERSION = "1.54.0"
LOCAL_SCHEMES = {"docker-archive", "oci-archive", "oci-dir", "file", "dir"}


def registry_reference(location: str) -> bool:
    parts = location.split("@")
    if len(parts) > 2 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", parts[0]):
        return False
    if "//" in parts[0] or parts[0].endswith(":"):
        return False
    return len(parts) == 1 or re.fullmatch(r"sha256:[a-fA-F0-9]{64}", parts[1]) is not None


def source(value: str, *, allow_registry: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 4096 or ":" not in value or redact_text(value) != value or any(ord(x) < 32 for x in value):
        raise ValueError("Use an explicit source scheme without credentials")
    scheme, location = value.split(":", 1)
    if scheme == "registry":
        if not allow_registry or not registry_reference(location):
            raise ValueError("Registry sources require explicit network authorization")
        return value
    if scheme not in LOCAL_SCHEMES:
        raise ValueError("Supported sources: explicit registry, docker-archive, oci-archive, oci-dir, file, dir")
    roots = [Path(item).expanduser().resolve() for item in os.environ.get("SCOPESCAN_SOFTWARE_ROOTS", "").split(os.pathsep) if item]
    path = Path(location).expanduser()
    if not path.is_absolute() or not roots:
        raise ValueError("Local software sources require an absolute path within worker SCOPESCAN_SOFTWARE_ROOTS")
    path = path.resolve(strict=True)
    if not any(path.is_relative_to(root) for root in roots):
        raise ValueError("Source is outside worker trusted software roots")
    if (scheme in {"dir", "oci-dir"}) != path.is_dir() or not (path.is_dir() or path.is_file()):
        raise ValueError("Source type does not match the explicit scheme")
    return scheme + ":" + str(path)


def _check_result(result, label):
    if result.cancelled:
        raise ValueError(f"{label} cancelled")
    if result.timed_out or result.output_truncated or result.file_limit_exceeded:
        raise ValueError(f"{label} exceeded its deadline/output budget")
    if result.returncode != 0:
        raise ValueError(f"{label} failed: " + redact_text(result.stderr[:2000]))


class SyftAdapter:
    def __init__(self, command: tuple[str, ...] | None = None):
        self.command = command

    def execute(self, value: str, *, allow_registry=False, timeout=120, cancel: threading.Event | None = None):
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 3600:
            raise ValueError("Software timeout must be 0..3600 seconds")
        approved = source(value, allow_registry=allow_registry)
        command = command_for("syft", self.command)
        deadline = time.monotonic() + timeout
        with tempfile.TemporaryDirectory(prefix="scopescan-syft-") as temp:
            root = Path(temp)
            env = isolated_environment(root)
            env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
            version = run_process([*command, "version", "-o", "json"], cancel=cancel, deadline=deadline, env=env, cwd=root, max_output_chars=16_000)
            _check_result(version, "Syft version check")
            try:
                actual = json.loads(version.stdout).get("version", "").lstrip("v")
            except (ValueError, AttributeError) as exc:
                raise ValueError("Invalid Syft version output") from exc
            if actual != VERSION:
                raise ValueError("Supported Syft version is " + VERSION)
            result = run_process([*command, "scan", approved, "-o", "cyclonedx-json"], cancel=cancel, deadline=deadline, env=env, cwd=root, max_output_chars=MAX_BYTES)
            _check_result(result, "Syft cataloguing")
        normalized = parse(result.stdout.encode())
        normalized["source"] = approved
        normalized["engine_version"] = VERSION
        return normalized
