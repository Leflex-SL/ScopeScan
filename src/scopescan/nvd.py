"""Enriquecimiento optativo de CPE con NVD. Una coincidencia nunca confirma una CVE."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from . import db

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = timedelta(days=7)
SAFE_PART = re.compile(r"^[a-zA-Z0-9._-]+$")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
NUMERIC_VERSION = re.compile(r"^\d+(?:\.\d+)*$")
MATCH_ORDER = {"exact": 0, "range": 1, "all_versions": 2, "unresolved": 3}


class NvdError(RuntimeError):
    """No se pudo obtener un resultado completo y fiable de NVD."""


def normalize_cpe(raw: str) -> str | None:
    """Convierte los CPE 2.2 simples de nmap a 2.3; descarta los ambiguos."""
    if raw.startswith("cpe:/"):
        parts = raw[5:].split(":")
        if len(parts) < 4 or len(parts) > 11:
            return None
        part, vendor, product, version = parts[:4]
        if part not in ("a", "o", "h") or not all(
            SAFE_PART.fullmatch(value) for value in (vendor, product, version)
        ):
            return None
        tail = parts[4:]
        if any(not SAFE_PART.fullmatch(value) for value in tail):
            return None
        return ":".join(["cpe", "2.3", *parts, *(["*"] * (7 - len(tail)))])
    if raw.startswith("cpe:2.3:"):
        parts = raw.split(":")
        if len(parts) != 13 or parts[2] not in ("a", "o", "h"):
            return None
        if not all(value in ("*", "-") or SAFE_PART.fullmatch(value) for value in parts[3:]):
            return None
        return raw
    return None


def _is_exact_version(cpe: str) -> bool:
    version = cpe.split(":")[5]
    return version not in ("*", "-")


def _compare_numeric(left: str, right: str) -> int | None:
    if not NUMERIC_VERSION.fullmatch(left) or not NUMERIC_VERSION.fullmatch(right):
        return None
    a = [int(part) for part in left.split(".")]
    b = [int(part) for part in right.split(".")]
    length = max(len(a), len(b))
    a.extend([0] * (length - len(a)))
    b.extend([0] * (length - len(b)))
    return (a > b) - (a < b)


def _criteria_match(query: str, match: dict) -> str | None:
    """Clasifica el criterio sin suponer que un CPE prueba toda la configuracion."""
    if match.get("vulnerable") is not True:
        return None
    criteria = match.get("criteria", "")
    asked, recorded = query.split(":"), criteria.split(":")
    if len(asked) != 13 or len(recorded) != 13 or recorded[:2] != ["cpe", "2.3"]:
        return None
    uncertain = False
    for index, (actual, expected) in enumerate(zip(asked[2:], recorded[2:], strict=True), 2):
        if index == 5:
            continue
        if expected == "*":
            continue
        if actual == "*":
            uncertain = True
        elif actual != expected:
            return None
    actual_version, expected_version = asked[5], recorded[5]
    if expected_version not in ("*", actual_version):
        return None
    bounds = (
        ("versionStartIncluding", False, True),
        ("versionStartExcluding", False, False),
        ("versionEndIncluding", True, True),
        ("versionEndExcluding", True, False),
    )
    has_range = False
    for key, is_end, inclusive in bounds:
        boundary = match.get(key)
        if not boundary:
            continue
        has_range = True
        comparison = _compare_numeric(actual_version, boundary)
        if comparison is None:
            uncertain = True
        elif (
            (is_end and comparison > 0)
            or (not is_end and comparison < 0)
            or (comparison == 0 and not inclusive)
        ):
            return None
    if uncertain:
        return "unresolved"
    if has_range:
        return "range"
    return "all_versions" if expected_version == "*" else "exact"


def _matching_paths(node: dict, query: str, conditional: bool = False) -> list[tuple[str, bool, str]]:
    if node.get("negate") is True:
        return []
    children = node.get("nodes") or []
    matches = node.get("cpeMatch") or []
    additional = conditional or (node.get("operator") == "AND" and len(children) + len(matches) > 1)
    found = [
        (kind, additional, match["criteria"])
        for match in matches
        if (kind := _criteria_match(query, match)) is not None
    ]
    for child in children:
        found.extend(_matching_paths(child, query, additional))
    return found


def _applicability(cve: dict, query: str) -> tuple[str, bool, str]:
    paths = [
        path
        for configuration in cve.get("configurations") or []
        for path in _matching_paths(configuration, query)
    ]
    if not paths:
        return "not_applicable", False, ""
    return min(paths, key=lambda path: (path[1], MATCH_ORDER[path[0]]))


def match_note(match_type: str, requires_other_cpe: bool) -> str:
    notes = {
        "exact": "Version exacta en el criterio NVD",
        "range": "Version dentro de un intervalo NVD",
        "all_versions": "NVD enumera todas las versiones del producto",
        "unresolved": "Criterio NVD no comprobado localmente",
        "not_applicable": "La version detectada queda fuera del criterio NVD",
    }
    result = notes.get(match_type, notes["unresolved"])
    if requires_other_cpe:
        result += "; exige otra plataforma o componente"
    return result


def _extract(item: dict, query: str) -> dict | None:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not CVE_ID.fullmatch(cve_id) or cve.get("vulnStatus") == "Rejected":
        return None
    metrics = cve.get("metrics", {})
    score = None
    source = ""
    vector = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        entries = metrics.get(key) or []
        if entries:
            preferred = next((x for x in entries if x.get("type") == "Primary"), entries[0])
            cvss_data = preferred.get("cvssData", {})
            score = cvss_data.get("baseScore")
            source = preferred.get("source", "")
            vector = cvss_data.get("vectorString", "")
            break
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "es"), "")
    if not description:
        description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    match_type, requires_other_cpe, criteria = _applicability(cve, query)
    advisory = next(
        (reference["url"] for reference in cve.get("references") or []
         if reference.get("url", "").startswith("https://")
         and "Vendor Advisory" in reference.get("tags", [])),
        "",
    )
    return {
        "cve_id": cve_id, "cvss": score, "summary": description[:500],
        "match_type": match_type, "requires_other_cpe": requires_other_cpe,
        "matched_criteria": criteria, "cvss_source": source,
        "cvss_vector": vector, "vendor_advisory": advisory,
    }


class NvdClient:
    def __init__(self, *, api_key: str | None = None):
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
        self._last_request = 0.0

    def _page(self, cpe: str, start: int) -> dict:
        interval = 0.7 if self.api_key else 6.1
        remaining = interval - (time.monotonic() - self._last_request)
        if self._last_request and remaining > 0:
            time.sleep(remaining)
        query = urlencode({
            "cpeName": cpe, "isVulnerable": "", "resultsPerPage": 2000,
            "startIndex": start,
        })
        headers = {"User-Agent": "ScopeScan/0.2 (CPE candidate enrichment)"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        request = Request(f"{API_URL}?{query}", headers=headers)
        self._last_request = time.monotonic()
        try:
            with urlopen(request, timeout=20) as response:
                payload = response.read(16_000_001)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise NvdError(f"NVD no disponible: {exc}") from exc
        if len(payload) > 16_000_000:
            raise NvdError("Respuesta de NVD demasiado grande")
        try:
            data = json.loads(payload)
        except (ValueError, UnicodeDecodeError) as exc:
            raise NvdError("Respuesta JSON de NVD no valida") from exc
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise NvdError("Respuesta de NVD incompleta")
        return data

    def candidates(self, cpe: str) -> list[dict]:
        cache = db.get_nvd_cache(cpe)
        if cache:
            fetched = datetime.fromisoformat(cache["fetched_at"])
            if datetime.now(UTC) - fetched < CACHE_TTL:
                cached = json.loads(cache["candidates"])
                if all("match_type" in item for item in cached):
                    return cached
        output: dict[str, dict] = {}
        start = 0
        while True:
            data = self._page(cpe, start)
            items = data["vulnerabilities"]
            for item in items:
                candidate = _extract(item, cpe)
                if candidate and candidate["match_type"] != "not_applicable":
                    output[candidate["cve_id"]] = candidate
            start += len(items)
            total = data.get("totalResults", 0)
            if start >= total:
                break
            if not items or start > 10_000:
                raise NvdError("Paginacion incompleta de NVD")
        candidates = list(output.values())
        db.put_nvd_cache(cpe, candidates)
        return candidates


def enrich_scan(
    scan_id: int, *, client: NvdClient | None = None, include_firmware: bool = False,
    intel_enricher=None,
) -> int:
    """Consulta CPE exactos; el firmware autenticado exige una elección explícita."""
    if db.get_scan(scan_id) is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    client = client or NvdClient()
    inventories = db.get_host_inventories(scan_id)
    rows: list[dict] = []
    for host, ports in db.hosts_with_ports(scan_id):
        if host["state"] != "up":
            continue
        for port in ports:
            detected = db.row_list(port["cpes"])
            pairs: list[tuple[str, str]] = []
            for raw in detected:
                cpe = normalize_cpe(raw)
                if cpe and _is_exact_version(cpe):
                    # El CPE de hardware AMT de nmap no es la version de firmware.
                    if cpe.startswith("cpe:2.3:h:intel:active_management_technology:"):
                        continue
                    pairs.append((raw, cpe))
            firmware = inventories.get(host["address"], {}).get("intel_me_firmware")
            if include_firmware and firmware and SAFE_PART.fullmatch(firmware) and any(
                "active_management_technology" in cpe for cpe in detected
            ):
                pairs.append((
                    f"WMI Intel ME_System.FWVersion={firmware}",
                    f"cpe:2.3:o:intel:active_management_technology_firmware:{firmware}:*:*:*:*:*:*:*",
                ))
            for evidence, cpe in pairs:
                for candidate in client.candidates(cpe):
                    rows.append({
                        "host": host["address"], "port": port["portid"],
                        "protocol": port["protocol"], "detected_cpe": evidence,
                        "queried_cpe": cpe, **candidate,
                    })
    from . import threat_intel

    rows, intel_errors = (intel_enricher or threat_intel.enrich_candidates)(rows)
    db.replace_cve_candidates(scan_id, rows)
    db.set_enrichment_status(
        scan_id, "threat_intel", "partial" if intel_errors else "done",
        "; ".join(intel_errors),
    )
    return len(rows)
