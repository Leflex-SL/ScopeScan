"""Enriquecimiento optativo de CPE con NVD. Una coincidencia nunca confirma una CVE."""

from __future__ import annotations

import json
import math
import os
import re
import time
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from . import db
from .feed_budget import (
    FeedInterrupted,
    SharedFeedBudget,
    check_interrupt,
    claim_refresh,
    interruptible_wait,
    last_refresh,
    record_refresh,
    release_refresh,
)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = timedelta(days=7)
SAFE_PART = re.compile(r"^[a-zA-Z0-9._-]+$")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
NUMERIC_VERSION = re.compile(r"^\d+(?:\.\d+)*$")
MATCH_ORDER = {"exact": 0, "range": 1, "all_versions": 2, "unresolved": 3}


class NvdError(RuntimeError):
    """No se pudo obtener un resultado completo y fiable de NVD."""


class NvdCancelled(NvdError):
    """Cancellation/deadline is never converted into stale success."""


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


def _matching_paths(
    node: dict, query: str, conditional: bool = False
) -> list[tuple[str, bool, str]]:
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
    if not cve.get("configurations"):
        return "unresolved", False, ""
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
    _validate_cve(cve)
    cve_id = cve.get("id", "")
    if not CVE_ID.fullmatch(cve_id) or cve.get("vulnStatus") == "Rejected":
        return None
    metrics = cve.get("metrics", {})
    score = None
    source = ""
    vector = ""
    all_metrics = []
    selected_version = ""
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        valid = []
        for entry in entries:
            value = entry.get("cvssData", {}).get("baseScore")
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 <= value <= 10
            ):
                continue
            normalized = {
                "version": version,
                "source": entry.get("source", ""),
                "type": entry.get("type", ""),
                "score": value,
                "vector": entry.get("cvssData", {}).get("vectorString", ""),
            }
            all_metrics.append(normalized)
            valid.append(entry)
        if valid and score is None:
            preferred = next((x for x in valid if x.get("type") == "Primary"), valid[0])
            cvss_data = preferred.get("cvssData", {})
            score = cvss_data.get("baseScore")
            source = preferred.get("source", "")
            vector = cvss_data.get("vectorString", "")
            selected_version = version
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "es"), "")
    if not description:
        description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    match_type, requires_other_cpe, criteria = _applicability(cve, query)
    advisory = next(
        (
            reference["url"]
            for reference in cve.get("references") or []
            if reference.get("url", "").startswith("https://")
            and "Vendor Advisory" in reference.get("tags", [])
        ),
        "",
    )
    return {
        "cve_id": cve_id,
        "cvss": score,
        "summary": description[:500],
        "match_type": match_type,
        "requires_other_cpe": requires_other_cpe,
        "matched_criteria": criteria,
        "cvss_source": source,
        "cvss_vector": vector,
        "vendor_advisory": advisory,
        "cvss_version": selected_version,
        "cvss_metrics": all_metrics,
        "cvss_policy": "highest-version-primary-first",
    }


def _validate_cve(cve):
    if not isinstance(cve, dict) or not isinstance(cve.get("id", ""), str):
        raise NvdError("Registro CVE NVD invalido")
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        raise NvdError("Metricas CVSS NVD invalidas")
    for entries in metrics.values():
        if not isinstance(entries, list) or len(entries) > 100:
            raise NvdError("Metricas CVSS NVD invalidas")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("cvssData", {}), dict):
                raise NvdError("Metrica CVSS NVD invalida")
            if not all(
                isinstance(entry.get(key, ""), str) for key in ("source", "type")
            ) or not isinstance(entry.get("cvssData", {}).get("vectorString", ""), str):
                raise NvdError("Proveedor/vector CVSS NVD invalido")
    for key in ("descriptions", "references", "configurations"):
        if not isinstance(cve.get(key, []), list):
            raise NvdError("Coleccion NVD invalida")
    for description in cve.get("descriptions", []):
        if not isinstance(description, dict) or not all(
            isinstance(description.get(key, ""), str) for key in ("lang", "value")
        ):
            raise NvdError("Descripcion NVD invalida")
    for reference in cve.get("references", []):
        if (
            not isinstance(reference, dict)
            or not isinstance(reference.get("url", ""), str)
            or not isinstance(reference.get("tags", []), list)
        ):
            raise NvdError("Referencia NVD invalida")

    def node(value, depth=0):
        if depth > 32 or not isinstance(value, dict):
            raise NvdError("Configuracion NVD invalida")
        children, matches = value.get("nodes", []), value.get("cpeMatch", [])
        if not isinstance(children, list) or not isinstance(matches, list):
            raise NvdError("Configuracion NVD invalida")
        for match in matches:
            if (
                not isinstance(match, dict)
                or not isinstance(match.get("criteria", ""), str)
                or not all(
                    isinstance(match.get(key, ""), str)
                    for key in (
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    )
                )
            ):
                raise NvdError("Criterio NVD invalido")
        for child in children:
            node(child, depth + 1)

    for configuration in cve.get("configurations", []):
        node(configuration)


class NvdClient:
    """Conservative shared quota, refresh lease and explicit stale cache metadata."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        cancel=None,
        deadline=None,
        timeout=120.0,
        budget=None,
        transport=None,
    ):
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
        self.cancel = cancel
        self.deadline = deadline
        self.timeout = timeout
        self.budget = budget or SharedFeedBudget()
        self.transport = transport or urlopen
        self.last_status = {}
        self._query_deadline = None

    def _check(self):
        check_interrupt(self.cancel, self._query_deadline)

    def _page(self, cpe: str, start: int) -> dict:
        query = urlencode(
            {"cpeName": cpe, "isVulnerable": "", "resultsPerPage": 2000, "startIndex": start}
        )
        headers = {"User-Agent": "ScopeScan/0.2 (CPE candidate enrichment)"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        request = Request(f"{API_URL}?{query}", headers=headers)
        for attempt in range(3):
            self.budget.reserve(cancel=self.cancel, deadline=self._query_deadline)
            self._check()
            remaining = self._query_deadline - time.monotonic()
            try:
                with self.transport(request, timeout=min(20.0, remaining)) as response:
                    payload = response.read(16_000_001)
                self._check()
                break
            except HTTPError as exc:
                if exc.code not in (429, 500, 502, 503, 504):
                    raise NvdError(f"NVD devolvio HTTP {exc.code}") from None
                retry = exc.headers.get("Retry-After", "") if exc.headers else ""
                try:
                    delay = float(retry)
                except ValueError:
                    from email.utils import parsedate_to_datetime

                    try:
                        delay = (parsedate_to_datetime(retry) - datetime.now(UTC)).total_seconds()
                    except (TypeError, ValueError, OverflowError):
                        delay = 2.0**attempt
                self.budget.defer(delay if math.isfinite(delay) else 2.0**attempt)
                if attempt == 2:
                    raise NvdError(f"NVD devolvio HTTP {exc.code}") from None
            except (URLError, TimeoutError, OSError):
                if attempt == 2:
                    raise NvdError("NVD no disponible tras tres intentos") from None
                self.budget.defer(2.0**attempt)
        if len(payload) > 16_000_000:
            raise NvdError("Respuesta de NVD demasiado grande")
        try:
            data = json.loads(payload)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise NvdError("Respuesta JSON de NVD no valida") from None
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise NvdError("Respuesta de NVD incompleta")
        return data

    def _cached(self, cpe):
        cache = db.get_nvd_cache(cpe)
        if not cache:
            return None
        try:
            fetched = datetime.fromisoformat(cache["fetched_at"])
            if fetched.tzinfo is None:
                return None
            rows = json.loads(cache["candidates"])
            if not isinstance(rows, list) or not all(
                isinstance(x, dict) and "match_type" in x for x in rows
            ):
                return None
        except (ValueError, TypeError):
            return None
        return cache, rows, datetime.now(UTC) - fetched >= CACHE_TTL

    def _decorate(self, cpe, rows, fetched_at, *, stale=False, error=""):
        status = {
            "feed_provider": "NVD",
            "feed_schema": "2.2.4",
            "feed_fetched_at": fetched_at,
            "feed_stale": stale,
            "feed_error": error,
        }
        self.last_status[cpe] = status
        return [dict(row, **status) for row in rows]

    def candidates(self, cpe: str) -> list[dict]:
        if normalize_cpe(cpe) != cpe or not _is_exact_version(cpe):
            raise NvdError("La consulta NVD requiere CPE 2.3 y version concreta")
        self._query_deadline = min(self.deadline or float("inf"), time.monotonic() + self.timeout)
        key = "nvd:" + cpe
        owner = None
        try:
            while owner is None:
                self._check()
                cached = self._cached(cpe)
                if cached and not cached[2]:
                    return self._decorate(cpe, cached[1], cached[0]["fetched_at"])
                refresh = last_refresh(key)
                if refresh and refresh["error"] and time.time() - refresh["attempted_at"] < 30:
                    if cached:
                        return self._decorate(
                            cpe,
                            cached[1],
                            cached[0]["fetched_at"],
                            stale=True,
                            error=refresh["error"],
                        )
                    raise NvdError(refresh["error"])
                owner = claim_refresh(key, ttl=max(180.0, self.timeout + 30.0))
                if owner is None:
                    interruptible_wait(0.1, cancel=self.cancel, deadline=self._query_deadline)
            # Another worker can finish between our first cache read and lease acquisition.
            cached = self._cached(cpe)
            if cached and not cached[2]:
                return self._decorate(cpe, cached[1], cached[0]["fetched_at"])
            output = {}
            start = 0
            expected_total = None
            for _ in range(6):
                self._check()
                data = self._page(cpe, start)
                items = data["vulnerabilities"]
                total = data.get("totalResults")
                if (
                    type(total) is not int
                    or not 0 <= total <= 10000
                    or len(items) > 2000
                    or start + len(items) > total
                ):
                    raise NvdError("Limite o total de paginacion NVD invalido")
                if expected_total is not None and total != expected_total:
                    raise NvdError("El total NVD cambio durante la paginacion")
                expected_total = total
                if "startIndex" in data and (type(data["startIndex"]) is not int or data["startIndex"] != start):
                    raise NvdError("NVD devolvio una pagina fuera de secuencia")
                if "resultsPerPage" in data and (type(data["resultsPerPage"]) is not int or not 0 <= data["resultsPerPage"] <= 2000 or len(items) > data["resultsPerPage"]):
                    raise NvdError("Tamano declarado de pagina NVD invalido")
                for item in items:
                    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
                        raise NvdError("Registro NVD invalido")
                    candidate = _extract(item, cpe)
                    if candidate and candidate["match_type"] != "not_applicable":
                        output[candidate["cve_id"]] = candidate
                start += len(items)
                if start >= total:
                    break
                if not items:
                    raise NvdError("Paginacion incompleta de NVD")
            else:
                raise NvdError("Demasiadas paginas NVD")
            self._check()
            db.put_nvd_cache(cpe, list(output.values()))
            record_refresh(key)
            cached = self._cached(cpe)
            return self._decorate(cpe, list(output.values()), cached[0]["fetched_at"])
        except FeedInterrupted as exc:
            raise NvdCancelled(str(exc)) from None
        except NvdError as exc:
            if owner:
                record_refresh(key, str(exc))
            cached = self._cached(cpe)
            if cached:
                return self._decorate(
                    cpe, cached[1], cached[0]["fetched_at"], stale=True, error=str(exc)
                )
            self.last_status[cpe] = {
                "feed_provider": "NVD",
                "feed_stale": True,
                "feed_fetched_at": None,
                "feed_error": str(exc),
            }
            raise
        finally:
            if owner:
                release_refresh(key, owner)


def enrich_scan(
    scan_id: int,
    *,
    client: NvdClient | None = None,
    include_firmware: bool = False,
    intel_enricher=None,
) -> int:
    """Consulta CPE exactos; el firmware autenticado exige una elección explícita."""
    if db.get_scan(scan_id) is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    client = client or NvdClient()
    inventories = db.get_host_inventories(scan_id)
    rows: list[dict] = []
    queried: dict[str, list[dict]] = {}
    query_errors: list[str] = []
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
            if (
                include_firmware
                and firmware
                and SAFE_PART.fullmatch(firmware)
                and any("active_management_technology" in cpe for cpe in detected)
            ):
                pairs.append(
                    (
                        f"WMI Intel ME_System.FWVersion={firmware}",
                        f"cpe:2.3:o:intel:active_management_technology_firmware:{firmware}:*:*:*:*:*:*:*",
                    )
                )
            for evidence, cpe in pairs:
                if cpe not in queried:
                    try:
                        queried[cpe] = client.candidates(cpe)
                    except NvdCancelled:
                        raise
                    except NvdError as exc:
                        query_errors.append(str(exc))
                        queried[cpe] = []
                for candidate in queried[cpe]:
                    rows.append(
                        {
                            "host": host["address"],
                            "port": port["portid"],
                            "protocol": port["protocol"],
                            "detected_cpe": evidence,
                            "queried_cpe": cpe,
                            **candidate,
                        }
                    )
    from . import threat_intel

    rows, intel_errors = (intel_enricher or threat_intel.enrich_candidates)(rows)
    feed_errors = query_errors + list(
        dict.fromkeys(
            status.get("feed_error", "")
            for status in getattr(client, "last_status", {}).values()
            if status.get("feed_stale") or status.get("feed_error")
        )
    )
    db.set_enrichment_status(
        scan_id,
        "nvd",
        "partial" if feed_errors else "done",
        "; ".join(dict.fromkeys(feed_errors)) or ("Cache NVD vencida" if feed_errors else ""),
    )
    db.replace_cve_candidates(scan_id, rows)
    db.set_enrichment_status(
        scan_id,
        "threat_intel",
        "partial" if intel_errors else "done",
        "; ".join(intel_errors),
    )
    return len(rows)
