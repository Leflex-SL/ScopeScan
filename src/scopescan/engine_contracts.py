"""Bounded engine contracts. Finding is the existing application model."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from .models import Finding


def _stamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError()
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("Evidence timestamps require a timezone and cannot be in the future") from exc


def _pairs(value: tuple, *, nested: bool = False) -> None:
    if not isinstance(value, tuple) or len(value) > 65536:
        raise ValueError("Metadata requires bounded immutable pairs")
    keys = []
    for pair in value:
        if not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[0], str) or not pair[0] or len(pair[0]) > 4096:
            raise ValueError("Invalid metadata pair")
        keys.append(pair[0])
        if nested:
            if not isinstance(pair[1], tuple) or any(not isinstance(x, str) for x in pair[1]):
                raise ValueError("Resolution addresses require immutable tuples")
            for address in pair[1]:
                ipaddress.ip_address(address)
        elif not isinstance(pair[1], str) or len(pair[1]) > 4096:
            raise ValueError("Metadata values must be bounded strings")
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate metadata keys")


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int | None
    protocol: str = "tcp"
    service: str = ""
    hostname: str = ""  # Operator-provided and pinned; never reverse DNS.

    def __post_init__(self):
        if str(ipaddress.ip_address(self.host)) != self.host:
            raise ValueError("Endpoint requires a canonical IP address")
        if self.port is None and self.protocol == "host":
            pass
        elif type(self.port) is not int or not 1 <= self.port <= 65535 or self.protocol == "host":
            raise ValueError("Invalid endpoint port")
        if self.protocol not in {"tcp", "udp", "host"}:
            raise ValueError("Invalid endpoint protocol")
        if self.hostname and (not isinstance(self.hostname, str) or len(self.hostname) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in self.hostname.split("."))):
            raise ValueError("Invalid operator hostname")


@dataclass(frozen=True)
class ScanScope:
    namespace: str
    authorized_by: str
    endpoints: tuple[Endpoint, ...]
    scope_id: int | None = None
    resolutions: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self):
        if not self.namespace.strip() or not self.authorized_by.strip():
            raise ValueError("Namespace and authorization are required")
        if not isinstance(self.endpoints, tuple) or not 1 <= len(self.endpoints) <= 65536:
            raise ValueError("Scope needs 1–65536 immutable endpoints")
        _pairs(self.resolutions, nested=True)
        if self.scope_id is not None and (type(self.scope_id) is not int or self.scope_id <= 0):
            raise ValueError("Invalid saved scope ID")
        bindings = dict(self.resolutions)
        for endpoint in self.endpoints:
            if not isinstance(endpoint, Endpoint):
                raise TypeError("Invalid scope endpoint")
            if endpoint.hostname and endpoint.host not in bindings.get(endpoint.hostname, ()):
                raise ValueError("Hostname is not pinned to its endpoint")

    def contains(self, host: str, port: int | None, protocol: str = "tcp") -> bool:
        return any(e.host == host and e.port == port and e.protocol == protocol for e in self.endpoints)


@dataclass(frozen=True)
class Provenance:
    engine: str
    engine_version: str
    rules_version: str
    templates: tuple[tuple[str, str], ...] = ()
    feeds: tuple[tuple[str, str], ...] = ()
    imported: bool = False
    source: str = "local"

    def __post_init__(self):
        if any(not isinstance(x, str) or not x.strip() or len(x) > 4096 for x in (self.engine, self.engine_version, self.rules_version, self.source)) or type(self.imported) is not bool:
            raise ValueError("Engine/rule/source versions are required")
        _pairs(self.templates)
        _pairs(self.feeds)


@dataclass(frozen=True)
class Observation:
    endpoint: Endpoint
    rule_id: str
    outcome: str  # positive / negative / unknown
    evidence: str
    observed_at: str
    finding: Finding | None = None

    def __post_init__(self):
        if self.outcome not in {"positive", "negative", "unknown"} or not self.rule_id:
            raise ValueError("Invalid observation rule/outcome")
        if self.outcome in {"positive", "negative"} and not self.evidence.strip():
            raise ValueError("Positive and negative results require evidence")
        if self.outcome == "positive" and self.finding is None:
            raise ValueError("Positive result requires a Finding")
        if self.outcome != "positive" and self.finding is not None:
            raise ValueError("Only positive observations may contain a Finding")
        if self.finding and (self.finding.host != self.endpoint.host or self.finding.port != self.endpoint.port or self.finding.protocol != self.endpoint.protocol):
            raise ValueError("Finding differs from its observed endpoint")
        if self.finding and self.finding.rule_id != self.rule_id:
            raise ValueError("Finding rule differs from its observation")
        _stamp(self.observed_at)


@dataclass(frozen=True)
class EnginePlan:
    engine: str
    scope: ScanScope
    endpoints: tuple[Endpoint, ...]
    rules: tuple[str, ...]
    timeout: float = 120.0
    max_output_bytes: int = 2_000_000
    options: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        if not self.engine or not isinstance(self.endpoints, tuple) or not self.endpoints or not isinstance(self.rules, tuple) or not self.rules or any(not isinstance(r, str) or not r for r in self.rules):
            raise ValueError("Engine plan needs engine, endpoints and rules")
        if type(self.timeout) not in (int, float) or not math.isfinite(self.timeout) or not 0 < self.timeout <= 3600 or type(self.max_output_bytes) is not int or not 1 <= self.max_output_bytes <= 8_000_000:
            raise ValueError("Invalid engine execution bounds")
        _pairs(self.options)
        if any(e not in self.scope.endpoints for e in self.endpoints):
            raise ValueError("Engine endpoint escapes the authorized scope")
        if len(json.dumps(asdict(self)).encode())>2_000_000:
            raise ValueError("Engine plan exceeds 2 MB")

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class EngineResult:
    engine: str
    status: str  # complete / partial / failed / cancelled
    provenance: Provenance
    observations: tuple[Observation, ...] = ()
    raw: bytes = b""  # Already sanitized by adapter; store repeats secret-key redaction.
    errors: tuple[str, ...] = ()
    started_at: str = ""
    finished_at: str = ""
    raw_media_type: str = "application/json"

    def __post_init__(self):
        if self.status not in {"complete", "partial", "failed", "cancelled"} or self.engine != self.provenance.engine:
            raise ValueError("Invalid engine result status/provenance")
        if not isinstance(self.raw, bytes) or len(self.raw) > 8_000_000 or not isinstance(self.observations, tuple) or len(self.observations) > 10000 or any(not isinstance(o, Observation) for o in self.observations):
            raise ValueError("Engine result exceeds evidence bounds")
        if not isinstance(self.errors, tuple) or len(self.errors)>1000 or any(not isinstance(e, str) or len(e) > 65536 for e in self.errors):
            raise ValueError("Invalid engine errors")
        for value in (self.started_at, self.finished_at):
            if value:
                _stamp(value)


@dataclass(frozen=True)
class Job:
    id: str
    plan: EnginePlan
    state: str = "queued"
    cancel: threading.Event = field(default_factory=threading.Event, compare=False, repr=False)


@runtime_checkable
class EngineAdapter(Protocol):
    name: str

    def available(self) -> tuple[bool, str]: ...
    def plan(self, scope: ScanScope, *, timeout: float = 120.0) -> EnginePlan: ...
    def execute(self, plan: EnginePlan, *, cancel: threading.Event | None = None) -> EngineResult: ...
