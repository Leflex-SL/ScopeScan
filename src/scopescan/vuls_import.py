"""Import the documented Vuls ScanResult contract; never execute its config."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from .engine_contracts import EnginePlan, EngineResult, Observation, Provenance, ScanScope
from .engine_store import redact_text
from .models import Assessment, Finding, Severity

CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}$")
MODEL_VERSION = "vuls-scanresult-model-2026-10-03"


def _text(obj, key, *, required=False, maximum=300):
    value = obj.get(key, "")
    if not isinstance(value, str) or len(value) > maximum or (required and not value):
        raise ValueError(f"Campo Vuls invalido: {key}")
    return redact_text(value)


def parse_vuls(payload: bytes, *, host: str, scope: ScanScope) -> EngineResult:
    if len(payload) > 8_000_000:
        raise ValueError("Vuls excede 8 MB")
    if not scope.contains(host, None, "host"):
        raise ValueError("El host Vuls requiere autorizacion de controles host en el alcance")
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("JSON Vuls invalido") from None
    if not isinstance(data, dict):
        raise ValueError("Vuls requiere un objeto ScanResult")  # noqa: TRY004
    family, release = _text(data, "family", required=True), _text(data, "release", required=True)
    observed_at = _text(data, "scannedAt", required=True)
    # Observation validates the timestamp even when no vulnerabilities exist.
    endpoint = next(
        x for x in scope.endpoints if x.host == host and x.port is None and x.protocol == "host"
    )
    Observation(endpoint, "vuls:inventory", "unknown", "", observed_at)
    version = _text(data, "reportedVersion") or _text(data, "scannedVersion", required=True)
    for key in ("ipv4Addrs", "ipv6Addrs"):
        addresses = data.get(key, [])
        if not isinstance(addresses, list) or len(addresses) > 1000:
            raise ValueError("Lista de direcciones Vuls invalida")
        for address in addresses:
            if not isinstance(address, str):
                raise ValueError("Direccion Vuls invalida")  # noqa: TRY004
            ipaddress.ip_address(address)
    recorded_addresses = data.get("ipv4Addrs", []) + data.get("ipv6Addrs", [])
    if recorded_addresses and host not in recorded_addresses:
        raise ValueError("El host enlazado no coincide con las direcciones del informe Vuls")
    if "container" in data and not isinstance(data["container"], dict):
        raise ValueError("Objeto container Vuls invalido")
    if data.get("container") and any(data["container"].values()):
        raise ValueError("Vuls de contenedores requiere importacion de componentes SBOM")
    packages, vulnerabilities = data.get("packages", {}), data.get("scannedCves", {})
    if (
        not isinstance(packages, dict)
        or not isinstance(vulnerabilities, dict)
        or len(packages) > 10000
        or len(vulnerabilities) > 10000
    ):
        raise ValueError("Colecciones Vuls invalidas o excesivas")
    cleaned_packages = {}
    for name, package in packages.items():
        if not isinstance(name, str) or len(name) > 300 or not isinstance(package, dict):
            raise ValueError("Paquete Vuls invalido")
        cleaned_packages[name] = {
            key: _text(package, key)
            for key in (
                "name",
                "version",
                "release",
                "arch",
                "repository",
                "vendor",
                "repositoryClass",
            )
        }
    errors, warnings = data.get("errors", []), data.get("warnings", [])
    errors = [] if errors is None else errors
    warnings = [] if warnings is None else warnings
    if (
        not isinstance(errors, list)
        or not isinstance(warnings, list)
        or len(errors) + len(warnings) > 10000
    ):
        raise ValueError("Errores o warnings Vuls invalidos")
    if not all(isinstance(x, str) for x in errors + warnings):
        raise ValueError("Errores o warnings Vuls deben ser cadenas")
    source_packages = data.get("SrcPackages", {}) or {}
    if not isinstance(source_packages, dict) or len(source_packages) > 10000:
        raise ValueError("Paquetes fuente Vuls invalidos")
    cleaned_sources = {}
    for name, package in source_packages.items():
        if not isinstance(name, str) or len(name) > 300 or not isinstance(package, dict):
            raise ValueError("Paquete fuente Vuls invalido")
        binary_names = package.get("binaryNames", [])
        if (
            not isinstance(binary_names, list)
            or len(binary_names) > 1000
            or not all(isinstance(x, str) and len(x) <= 300 for x in binary_names)
        ):
            raise ValueError("Paquetes binarios Vuls invalidos")
        cleaned_sources[name] = {key: _text(package, key) for key in ("name", "version", "arch")}
        cleaned_sources[name]["binaryNames"] = binary_names
    observations, cleaned_vulnerabilities, providers = [], {}, set()
    for cve_id, vulnerability in vulnerabilities.items():
        if (
            not isinstance(cve_id, str)
            or not CVE.fullmatch(cve_id)
            or not isinstance(vulnerability, dict)
        ):
            raise ValueError("Vulnerabilidad Vuls invalida")
        if vulnerability.get("cveID", cve_id) != cve_id:
            raise ValueError("Identidades CVE Vuls no coinciden")
        affected = vulnerability.get("affectedPackages", []) or []
        contents = vulnerability.get("cveContents", {}) or {}
        if (
            not isinstance(affected, list)
            or len(affected) > 1000
            or not isinstance(contents, dict)
            or len(contents) > 100
        ):
            raise ValueError("Aplicabilidad Vuls invalida")
        # Only provider names are retained; source content may contain arbitrary fields.
        for provider in contents:
            if not isinstance(provider, str) or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,100}", provider
            ):
                raise ValueError("Proveedor Vuls invalido")
            providers.add(redact_text(provider))
        cleaned_affected = []
        distro_advisories = vulnerability.get("distroAdvisories", []) or []
        if not isinstance(distro_advisories, list) or len(distro_advisories) > 1000:
            raise ValueError("Avisos Vuls invalidos")
        cleaned_advisories = []
        for advisory in distro_advisories:
            if not isinstance(advisory, dict):
                raise ValueError("Aviso Vuls invalido")  # noqa: TRY004
            cleaned_advisories.append(
                {
                    key: _text(advisory, key)
                    for key in ("advisoryID", "severity", "issued", "updated")
                }
            )
        seen_names = set()
        for affected_package in affected:
            if not isinstance(affected_package, dict):
                raise ValueError("Paquete afectado Vuls invalido")  # noqa: TRY004
            name = _text(affected_package, "name", required=True)
            if name in seen_names:
                raise ValueError("Paquete afectado Vuls duplicado")
            seen_names.add(name)
            fixed = _text(affected_package, "fixedIn")
            fix_state = _text(affected_package, "fixState")
            not_fixed = affected_package.get("notFixedYet", False)
            if type(not_fixed) is not bool:
                raise ValueError("notFixedYet Vuls invalido")
            cleaned_affected.append(
                {"name": name, "fixedIn": fixed, "fixState": fix_state, "notFixedYet": not_fixed}
            )
            package = cleaned_packages.get(name)
            rule = f"vuls:{cve_id}:{name}"
            if not package or not package["version"]:
                observations.append(
                    Observation(
                        endpoint, rule, "unknown", "Paquete afectado no observado", observed_at
                    )
                )
                continue
            full_version = package["version"] + (
                "-" + package["release"] if package["release"] else ""
            )
            evidence = json.dumps(
                {
                    "cve": cve_id,
                    "package": name,
                    "version": full_version,
                    "distro": family,
                    "release": release,
                    "arch": package["arch"],
                    "repository": package["repository"],
                    "repository_class": package["repositoryClass"] or "unknown",
                    "fixed_in": fixed,
                    "fix_state": fix_state,
                    "not_fixed_yet": not_fixed,
                    "providers": sorted(redact_text(provider) for provider in contents),
                    "distro_advisories": cleaned_advisories,
                },
                sort_keys=True,
            )
            finding = Finding(
                host=host,
                port=None,
                protocol="host",
                severity=Severity.MEDIUM,
                title=f"{cve_id}: posible afectacion de {name}",
                description="Afirmacion de paquete afectado importada de Vuls; no confirma explotabilidad.",
                evidence=evidence,
                remediation="Consultar el aviso de la distribucion y actualizar el paquete.",
                cve_ids=[cve_id],
                source="vuls",
                assessment=Assessment.CANDIDATE,
                confirmed=False,
                rule_id=rule,
                component=name,
            )
            observations.append(
                Observation(endpoint, rule, "positive", evidence, observed_at, finding)
            )
        cleaned_vulnerabilities[cve_id] = {
            "cveID": cve_id,
            "affectedPackages": cleaned_affected,
            "providers": sorted(redact_text(provider) for provider in contents),
            "distroAdvisories": cleaned_advisories,
        }
    source_hash = hashlib.sha256(payload).hexdigest()
    if type(data.get("jsonVersion")) is not int or not 0 < data["jsonVersion"] < 100:
        raise ValueError("jsonVersion Vuls invalido")
    sanitized = {
        "jsonVersion": data["jsonVersion"],
        "family": family,
        "release": release,
        "scannedAt": observed_at,
        "version": version,
        "boundHost": host,
        "packages": cleaned_packages,
        "SrcPackages": cleaned_sources,
        "scannedCves": cleaned_vulnerabilities,
        "errorCount": len(errors),
        "warningCount": len(warnings),
        "source_sha256": source_hash,
        "redaction_manifest": [
            "config",
            "unknown_fields",
            "errors_text",
            "warnings_text",
            "cve_contents_payload",
            "URI userinfo and credential-bearing strings",
        ],
    }
    sanitized_bytes = json.dumps(sanitized, sort_keys=True).encode()
    provenance = Provenance(
        "vuls",
        version,
        MODEL_VERSION,
        feeds=tuple((provider, "version_not_reported") for provider in sorted(providers)),
        imported=True,
        source=f"vuls-json:sha256:{source_hash}",
    )
    result_errors = (
        (f"El informe registra {len(errors)} errores y {len(warnings)} avisos; cobertura parcial",)
        if errors or warnings
        else ()
    )
    return EngineResult(
        "vuls",
        "partial" if errors or warnings else "complete",
        provenance,
        tuple(observations),
        sanitized_bytes,
        result_errors,
        observed_at,
        observed_at,
    )


class VulsImportAdapter:
    name = "vuls"

    def __init__(self, payload: bytes, *, host: str):
        self.payload, self.host = payload, host

    def available(self):
        return True, "Importacion JSON Vuls preparada; no se ejecuta configuracion externa"

    def plan(self, scope: ScanScope, *, timeout=120.0):
        endpoint = next(
            (x for x in scope.endpoints if x.host == self.host and x.protocol == "host"), None
        )
        if endpoint is None:
            raise ValueError("Vuls necesita autorizacion host explicita")
        result = parse_vuls(self.payload, host=self.host, scope=scope)
        rules = tuple(dict.fromkeys(x.rule_id for x in result.observations)) or ("vuls:inventory",)
        return EnginePlan(
            self.name,
            scope,
            (endpoint,),
            rules,
            timeout,
            8_000_000,
            (("payload_sha256", hashlib.sha256(self.payload).hexdigest()),),
        )

    def execute(self, plan: EnginePlan, *, cancel=None):
        if plan.engine != self.name or not plan.scope.contains(self.host, None, "host"):
            raise ValueError("Plan Vuls invalido")
        if dict(plan.options).get("payload_sha256") != hashlib.sha256(self.payload).hexdigest():
            raise ValueError("El informe Vuls cambio desde el plan")
        if cancel and cancel.is_set():
            return EngineResult(
                self.name,
                "cancelled",
                Provenance(self.name, "not_executed", MODEL_VERSION, imported=True),
            )
        return parse_vuls(self.payload, host=self.host, scope=plan.scope)
