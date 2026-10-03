"""Distribution package advisories evaluated without upstream/banner assumptions."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime

from .engine_contracts import EnginePlan, EngineResult, Observation, Provenance, ScanScope
from .engine_store import redact_text, sanitize
from .models import Assessment, Finding, Severity
from .package_versions import compare_versions

SCHEMA = "scopescan.linux-advisories.v1"
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}$")
PROVIDERS = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "rhel": "Red Hat",
    "centos": "Red Hat",
    "rocky": "Rocky Linux",
    "almalinux": "AlmaLinux",
    "ol": "Oracle",
    "fedora": "Fedora",
    "amazon": "Amazon Linux",
}


def parse_advisories(payload: bytes) -> dict:
    if len(payload) > 16_000_000:
        raise ValueError("Avisos Linux exceden 16 MB")
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeError):
        raise ValueError("JSON de avisos Linux invalido") from None
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError(f"Se requiere {SCHEMA}")
    for key in ("provider", "distro", "release", "feed_version", "observed_at"):
        if not isinstance(data.get(key), str) or not data[key] or len(data[key]) > 300:
            raise ValueError(f"Campo de aviso Linux invalido: {key}")
    if PROVIDERS.get(data["distro"]) != data["provider"]:
        raise ValueError("Proveedor no corresponde a la distribucion")
    moment = datetime.fromisoformat(data["observed_at"])
    if moment.tzinfo is None or (moment - datetime.now(UTC)).total_seconds() > 300:
        raise ValueError("Fecha de feed Linux invalida")
    if not isinstance(data.get("advisories"), list) or len(data["advisories"]) > 10000:
        raise ValueError("Coleccion de avisos Linux invalida")
    for row in data["advisories"]:
        if not isinstance(row, dict):
            raise ValueError("Aviso Linux invalido")  # noqa: TRY004
        for key in ("id", "package", "fixed_version", "repository"):
            if not isinstance(row.get(key), str) or len(row[key]) > 300:
                raise ValueError(f"Campo de aviso invalido: {key}")
        if not row["id"] or not row["package"] or not row["repository"]:
            raise ValueError("Aviso sin identidad, paquete o repositorio")
        if (
            not isinstance(row.get("cves"), list)
            or len(row["cves"]) > 100
            or not all(isinstance(x, str) and CVE.fullmatch(x) for x in row["cves"])
        ):
            raise ValueError("CVEs de aviso invalidas")
        if "arch" in row and not isinstance(row["arch"], str):
            raise ValueError("Arquitectura de aviso invalida")
    cleaned = {
        key: data[key]
        for key in ("schema", "provider", "distro", "release", "feed_version", "observed_at")
    }
    cleaned["advisories"] = [
        {
            key: row[key]
            for key in ("id", "package", "fixed_version", "repository", "cves", "arch")
            if key in row
        }
        for row in data["advisories"]
    ]
    cleaned["source_sha256"] = hashlib.sha256(payload).hexdigest()
    cleaned_bytes, redactions = sanitize(json.dumps(cleaned).encode(),"application/json")
    cleaned = json.loads(cleaned_bytes)
    cleaned["redaction_manifest"] = redactions
    return cleaned


def assess_inventory(inventory: dict, feed: dict) -> dict:
    """A fixed native version refutes only a proved distribution repository package."""
    applicable = (
        inventory.get("os_id") == feed["distro"] and inventory.get("os_version") == feed["release"]
    )
    output = []
    for advisory in feed["advisories"]:
        packages = [
            x
            for x in inventory.get("packages", [])
            if advisory["package"] in (x.get("name", "").split(":")[0], x.get("source_name"))
        ]
        if not packages:
            output.append(
                {
                    "advisory": advisory["id"],
                    "package": advisory["package"],
                    "arch": advisory.get("arch", ""),
                    "state": "not_assessed",
                    "reason": "Paquete no observado",
                }
            )
        for package in packages:
            repo = (
                package.get("repository_class") == "distribution"
                and package.get("repository") == advisory["repository"]
            )
            architecture = not advisory.get("arch") or package.get("arch") == advisory["arch"]
            installed_version = (
                package["version"]
                if package["name"].split(":")[0] == advisory["package"]
                else package.get("source_version", "")
            )
            comparison = compare_versions(
                installed_version, advisory["fixed_version"], inventory.get("package_manager")
            )
            if not applicable or not architecture or comparison is None:
                state, reason = "not_assessed", "Distribucion, arquitectura o version no comprobada"
            elif comparison < 0:
                state, reason = "candidate", "Version nativa anterior a la correccion del aviso"
            elif repo:
                state, reason = "fixed", "Version corregida y origen de distribucion comprobado"
            else:
                state, reason = "not_assessed", "Origen del repositorio no comprobado"
            output.append(
                {
                    "advisory": advisory["id"],
                    "package": package["name"],
                    "installed_version": installed_version,
                    "fixed_version": advisory["fixed_version"],
                    "cves": advisory["cves"],
                    "state": state,
                    "reason": reason,
                    "repository_verified": repo,
                    "arch": package.get("arch", ""),
                    "confirmed": False,
                }
            )
    return {
        "provider": feed["provider"],
        "feed_version": feed["feed_version"],
        "source_sha256": feed["source_sha256"],
        "observed_at": feed["observed_at"],
        "distro": feed["distro"],
        "release": feed["release"],
        "results": output,
        "coverage": "advisories_supplied",
        "inventory_complete": inventory.get("packages_complete"),
    }


class LinuxAdvisoryAdapter:
    name = "linux-advisories"

    def __init__(self, inventory: dict, payload: bytes, *, host: str):
        _validate_inventory(inventory)
        if inventory.get("host") and inventory["host"] != host:
            raise ValueError("El host del inventario Linux no coincide con su asociacion")
        # Immutable copies prevent an inventory/feed change after operator preview.
        self._inventory_bytes = json.dumps(inventory, sort_keys=True).encode()
        if len(self._inventory_bytes) > 8_000_000 or len(payload) > 8_000_000:
            raise ValueError("Inventario/feed Linux excede 8 MB")
        self.payload, self.host = payload, host
        self.feed = parse_advisories(payload)
        inventory_keys = [(x["name"], x.get("arch", "")) for x in inventory.get("packages", [])]
        if len(inventory_keys) != len(set(inventory_keys)):
            raise ValueError("Paquetes Linux duplicados por nombre y arquitectura")

    def available(self):
        return True, "Evaluacion nativa sobre inventario y avisos de distribucion suministrados"

    def _assessment(self):
        return assess_inventory(json.loads(self._inventory_bytes), parse_advisories(self.payload))

    def plan(self, scope: ScanScope, *, timeout=120.0):
        endpoint = next(
            (x for x in scope.endpoints if x.host == self.host and x.protocol == "host"), None
        )
        if endpoint is None:
            raise ValueError("Avisos Linux necesitan autorizacion host explicita")
        rules = tuple(dict.fromkeys(_rule(x) for x in self._assessment()["results"])) or (
            "linux-advisory:inventory",
        )
        return EnginePlan(
            self.name,
            scope,
            (endpoint,),
            rules,
            timeout,
            8_000_000,
            (("input_sha256", hashlib.sha256(self._inventory_bytes + self.payload).hexdigest()),),
        )

    def execute(self, plan: EnginePlan, *, cancel=None):
        if plan.engine != self.name or not plan.scope.contains(self.host, None, "host"):
            raise ValueError("Plan de avisos Linux invalido")
        if (
            dict(plan.options).get("input_sha256")
            != hashlib.sha256(self._inventory_bytes + self.payload).hexdigest()
        ):
            raise ValueError("Inventario/feed Linux cambio desde el plan")
        self.feed = parse_advisories(self.payload)
        provenance = Provenance(
            self.name,
            "1",
            SCHEMA,
            feeds=((self.feed["provider"], self.feed["feed_version"]),),
            imported=True,
            source="distribution-advisory-import",
        )
        if cancel and cancel.is_set():
            return EngineResult(self.name, "cancelled", provenance)
        result = self._assessment()
        endpoint = next(x for x in plan.endpoints if x.host == self.host and x.protocol == "host")
        observed = self.feed["observed_at"]
        inventory = json.loads(self._inventory_bytes)
        # Feed publication time cannot be substituted for inventory observation time.
        inventory_observed = inventory.get("observed_at")
        if not isinstance(inventory_observed, str):
            raise ValueError("Inventario Linux requiere observed_at con zona horaria")  # noqa: TRY004
        observations = []
        for row in result["results"]:
            rule = _rule(row)
            outcome = {"candidate": "positive", "fixed": "negative"}.get(row["state"], "unknown")
            evidence = redact_text(json.dumps(dict(row, feed_observed_at=observed), sort_keys=True))
            finding = None
            if outcome == "positive":
                finding = Finding(
                    host=self.host,
                    port=None,
                    protocol="host",
                    source=self.name,
                    title=f"{row['advisory']}: actualizar {row['package']}",
                    severity=Severity.MEDIUM,
                    description="Version nativa anterior a la correccion de la distribucion; posible afectacion.",
                    evidence=evidence,
                    remediation=f"Aplicar {row['fixed_version']} del repositorio de distribucion.",
                    cve_ids=row.get("cves", []),
                    confirmed=False,
                    assessment=Assessment.CANDIDATE,
                    rule_id=rule,
                    component=row["package"] + ":" + row.get("arch", ""),
                )
            observations.append(
                Observation(endpoint, rule, outcome, evidence, inventory_observed, finding)
            )
        status = "partial" if any(x.outcome == "unknown" for x in observations) else "complete"
        raw = json.dumps(
            {"feed": self.feed, "assessment": result, "inventory_observed_at": inventory_observed},
            sort_keys=True,
        ).encode()
        raw, _ = sanitize(raw,"application/json")
        return EngineResult(
            self.name,
            status,
            provenance,
            tuple(observations),
            raw,
            (),
            inventory_observed,
            inventory_observed,
        )


def _rule(row):
    return f"linux-advisory:{row['advisory']}:{row['package']}:{row.get('arch', '')}"


def _validate_inventory(inventory):
    if not isinstance(inventory, dict):
        raise ValueError("Inventario Linux debe ser un objeto")  # noqa: TRY004
    for key in ("os_id", "os_version", "package_manager", "observed_at"):
        if (
            not isinstance(inventory.get(key), str)
            or not inventory[key]
            or len(inventory[key]) > 300
        ):
            raise ValueError(f"Campo de inventario Linux invalido: {key}")
    packages = inventory.get("packages")
    if not isinstance(packages, list) or len(packages) > 10000:
        raise ValueError("Paquetes de inventario Linux invalidos")
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("Paquete de inventario Linux invalido")  # noqa: TRY004
        for key in ("name", "version"):
            if not isinstance(package.get(key), str) or not package[key] or len(package[key]) > 300:
                raise ValueError(f"Campo de paquete Linux invalido: {key}")
        for key in ("arch", "source_name", "source_version", "repository", "repository_class"):
            if key in package and (not isinstance(package[key], str) or len(package[key]) > 300):
                raise ValueError(f"Campo de paquete Linux invalido: {key}")
