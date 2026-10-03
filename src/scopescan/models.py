"""Modelo de datos: resultado de nmap ya parseado y hallazgos derivados."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any


class Severity(IntEnum):
    """Niveles de Nessus. El orden numerico permite ordenar y filtrar."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "Informativo",
            Severity.LOW: "Baja",
            Severity.MEDIUM: "Media",
            Severity.HIGH: "Alta",
            Severity.CRITICAL: "Critica",
        }[self]

    @property
    def slug(self) -> str:
        return self.name.lower()

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """Corte CVSS v3 estandar (FIRST): 9.0+ critica, 7.0+ alta, 4.0+ media."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Assessment(StrEnum):
    """Qué demuestra la evidencia, independiente de la gravedad CVSS."""

    EXPOSURE = "exposure"
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"

    @property
    def label(self) -> str:
        return {
            Assessment.EXPOSURE: "Exposición observada",
            Assessment.CANDIDATE: "Posible afectación",
            Assessment.CONFIRMED: "Comprobación positiva",
        }[self]


@dataclass
class ScriptResult:
    id: str
    output: str
    elements: dict[str, str] = field(default_factory=dict)


@dataclass
class Service:
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    ostype: str = ""
    tunnel: str = ""
    method: str = ""
    confidence: int = 0
    cpes: list[str] = field(default_factory=list)

    @property
    def display(self) -> str:
        """Texto compacto tipo 'OpenSSH 8.2p1 (Ubuntu Linux; protocol 2.0)'."""
        parts = [p for p in (self.product, self.version) if p]
        base = " ".join(parts) or self.name or "desconocido"
        if self.extrainfo:
            base = f"{base} ({self.extrainfo})"
        return base

    @property
    def has_version(self) -> bool:
        return bool(self.version)


@dataclass
class Port:
    portid: int
    protocol: str = "tcp"
    state: str = "unknown"
    reason: str = ""
    service: Service = field(default_factory=Service)
    scripts: list[ScriptResult] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.state == "open"


@dataclass
class OSMatch:
    name: str
    accuracy: int


@dataclass
class Host:
    address: str
    addrtype: str = "ipv4"
    mac: str = ""
    vendor: str = ""
    state: str = "unknown"
    hostnames: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    hostscripts: list[ScriptResult] = field(default_factory=list)
    osmatches: list[OSMatch] = field(default_factory=list)
    # Puertos cerrados/filtrados agrupados por nmap en <extraports>.
    extraports: dict[str, int] = field(default_factory=dict)
    timed_out: bool = False

    @property
    def is_up(self) -> bool:
        return self.state == "up"

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.is_open]

    @property
    def best_os(self) -> OSMatch | None:
        return max(self.osmatches, key=lambda m: m.accuracy, default=None)

    @property
    def label(self) -> str:
        return f"{self.address} ({self.hostnames[0]})" if self.hostnames else self.address


@dataclass
class NmapRun:
    args: str = ""
    scanner_version: str = ""
    start: int = 0
    elapsed: float = 0.0
    exit_status: str = ""
    summary: str = ""
    hosts: list[Host] = field(default_factory=list)
    hosts_up: int = 0
    hosts_total: int = 0
    coverage: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def live_hosts(self) -> list[Host]:
        return [h for h in self.hosts if h.is_up]


@dataclass
class Finding:
    """Un hallazgo: lo que Nessus llama plugin result.

    `source` distingue de donde sale: un script NSE ('nse:<id>') o una regla
    propia sobre el servicio detectado ('rule:<id>'). Se guarda para poder
    explicar en el informe por que aparece.
    """

    title: str
    severity: Severity
    source: str
    host: str
    port: int | None = None
    protocol: str = "tcp"
    service: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    confirmed: bool = False  # comprobacion positiva por NSE o inventario autenticado
    assessment: Assessment = Assessment.EXPOSURE
    # Logical identity excludes presentation text and observed versions.
    rule_id: str = ""
    component: str = ""

    @property
    def location(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol}" if self.port else self.host
