"""Grype 0.119.0 SBOM matching with explicitly configured, non-updating database."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ._adapter_support import command_for, isolated_environment
from .engine_store import sanitize
from .process_runner import run_process
from .sbom import MAX_BYTES, bounded_json, objects, text, timestamp
from .syft_adapter import _check_result

VERSION = "0.119.0"


def parse(payload: bytes) -> dict:
    bounded_json(payload)
    safe, redactions = sanitize(payload, "application/json")
    document = bounded_json(safe)
    matches = objects(document.get("matches"), "Grype matches")
    descriptor = document.get("descriptor")
    if not isinstance(descriptor, dict) or not isinstance(descriptor.get("db"), dict):
        raise ValueError("Grype result needs database provenance")  # noqa: TRY004 - external schema validation
    if descriptor.get("name") != "grype":
        raise ValueError("Grype result must identify its producer")
    reported_version = text(descriptor.get("version"), required=True)
    database = descriptor["db"]
    if not database:
        raise ValueError("Grype database provenance is empty")
    database_status = text(database.get("status"))
    if type(database.get("valid")) is not bool:
        raise ValueError("Grype database provenance requires its typed validity flag")
    text(database.get("schemaVersion"), required=True)
    if not database["valid"] or database.get("error") or database_status in {"invalid", "missing"}:
        raise ValueError("Grype database is unavailable or invalid")
    observations = []
    observed_matches = {}
    components = {}
    for match in matches:
        artifact, vulnerability = match.get("artifact"), match.get("vulnerability")
        if not isinstance(artifact, dict) or not isinstance(vulnerability, dict):
            raise ValueError("Malformed Grype artifact/vulnerability")  # noqa: TRY004 - external schema validation
        ref = text(artifact.get("id"), required=True)
        component = {"ref": ref, "name": text(artifact.get("name"), required=True), "version": text(artifact.get("version")), "purl": text(artifact.get("purl")), "type": "library", "source": artifact}
        if ref in components and components[ref] != component:
            raise ValueError("Grype artifact identity is ambiguous")
        components[ref] = component
        rule_id = text(vulnerability.get("id"), required=True)
        provider = text(vulnerability.get("namespace"))
        match_key = (ref, rule_id, provider)
        if match_key in observed_matches:
            observed_matches[match_key]["match_details"].extend(objects(match.get("matchDetails", [])))
            continue
        observation = {"component_ref": ref, "rule_id": rule_id, "identity_scope": provider,
                             "outcome": "candidate", "severity": text(vulnerability.get("severity", "Unknown")),
                             "confirmed": False, "vulnerability": vulnerability, "match_details": objects(match.get("matchDetails", [])),
                             "related_vulnerabilities": match.get("relatedVulnerabilities", []),
                             "fix": vulnerability.get("fix", {}), "source": "grype-package-match"}
        observations.append(observation)
        observed_matches[match_key] = observation
    built = database.get("built") or database.get("builtAt")
    errors = []
    stale = None
    if built:
        built = timestamp(built)
        stale = datetime.fromisoformat(built) < datetime.now(UTC) - timedelta(days=5)
        if stale:
            errors.append("Imported Grype database was built more than five days ago")
    else:
        errors.append("Grype database build date is unknown")
    return {"format": "grype", "format_version": reported_version, "observed_at": timestamp(descriptor.get("timestamp")),
            "components": list(components.values()), "observations": observations, "dependencies": [],
            "database": database, "database_built_at": built, "database_stale": stale,
            "database_checksum": database.get("checksum", "unknown"), "descriptor": descriptor, "distro": document.get("distro"), "source": document.get("source"),
            "coverage": "sbom_components_and_database_supplied", "status": "partial" if errors else "complete", "errors": errors,
            "document": document, "raw": safe, "received_sha256": hashlib.sha256(payload).hexdigest(),
            "raw_sha256": hashlib.sha256(safe).hexdigest(), "redactions": redactions}


class GrypeAdapter:
    def __init__(self, command: tuple[str, ...] | None = None):
        self.command = command

    def execute(self, sbom: bytes, *, timeout=120, cancel: threading.Event | None = None):
        from .sbom import parse as parse_sbom
        normalized_sbom = parse_sbom(sbom)
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 3600:
            raise ValueError("Software timeout must be 0..3600 seconds")
        cache = os.environ.get("SCOPESCAN_GRYPE_DB_CACHE_DIR", "")
        if not cache or not Path(cache).is_absolute() or not Path(cache).is_dir():
            raise ValueError("Configure worker SCOPESCAN_GRYPE_DB_CACHE_DIR with a previously updated Grype database")
        command = command_for("grype", self.command)
        deadline = time.monotonic() + timeout
        with tempfile.TemporaryDirectory(prefix="scopescan-grype-") as temp:
            root = Path(temp)
            env = isolated_environment(root)
            env.update(GRYPE_CHECK_FOR_APP_UPDATE="false", GRYPE_DB_AUTO_UPDATE="false", GRYPE_DB_CACHE_DIR=str(Path(cache).resolve()),
                       GRYPE_DB_REQUIRE_UPDATE_CHECK="false", GRYPE_DB_VALIDATE_BY_HASH_ON_START="true", GRYPE_DB_VALIDATE_AGE="true", GRYPE_TIMESTAMP="true")
            version = run_process([*command, "version", "-o", "json"], cancel=cancel, deadline=deadline, env=env, cwd=root, max_output_chars=16_000)
            _check_result(version, "Grype version check")
            try:
                actual = json.loads(version.stdout).get("version", "").lstrip("v")
            except (ValueError, AttributeError) as exc:
                raise ValueError("Invalid Grype version output") from exc
            if actual != VERSION:
                raise ValueError("Supported Grype version is " + VERSION)
            source = root / "input.json"
            source.write_bytes(normalized_sbom["raw"])
            result = run_process([*command, "sbom:" + str(source), "-o", "json"], cancel=cancel, deadline=deadline, env=env, cwd=root, max_output_chars=MAX_BYTES)
            _check_result(result, "Grype SBOM matching")
        value = parse(result.stdout.encode())
        declared_path = value["database"].get("path")
        if declared_path:
            path = Path(text(declared_path, required=True)).resolve(strict=True)
            if not path.is_relative_to(Path(cache).resolve()) or not path.is_file() or path.stat().st_size > 1_000_000_000:
                raise ValueError("Grype database evidence path is outside the configured bounded cache")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    if cancel is not None and cancel.is_set():
                        raise ValueError("Grype database hashing cancelled")
                    if time.monotonic() >= deadline:
                        raise ValueError("Grype database hashing exceeded its deadline")
                    digest.update(chunk)
            value["database_sha256"] = digest.hexdigest()
        else:
            value["database_sha256"] = None
            value["errors"].append("Grype did not report the database path; database SHA256 is unknown")
            value["status"] = "partial"
        value["sbom_received_sha256"] = normalized_sbom["received_sha256"]
        value["engine_version"] = VERSION
        return value
