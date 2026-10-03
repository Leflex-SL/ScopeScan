"""Aplicabilidad de actualizaciones acumulativas Windows con datos oficiales MSRC."""

from __future__ import annotations

import calendar
import json
import re
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import db

BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
API_VERSION = "2023-11-01"
CACHE_TTL = timedelta(hours=20)


class MsrcError(RuntimeError):
    """No se pudo determinar de forma fiable el nivel de parche Windows."""


def _fetch_json(url: str, *, limit: int = 80_000_000) -> dict:
    request = Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "ScopeScan/0.2 Windows patch assessment",
    })
    try:
        with urlopen(request, timeout=60) as response:
            payload = response.read(limit + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise MsrcError(f"MSRC no disponible: {exc}") from exc
    if len(payload) > limit:
        raise MsrcError("Documento MSRC demasiado grande")
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MsrcError("MSRC no devolvio JSON valido") from exc
    if not isinstance(data, dict):
        raise MsrcError("Formato MSRC inesperado")
    return data


def _fresh(key: str) -> object | None:
    row = db.get_feed_cache(key)
    if not row:
        return None
    if datetime.now(UTC) - datetime.fromisoformat(row["fetched_at"]) >= CACHE_TTL:
        return None
    return json.loads(row["payload"])


def _release_for(moment: datetime) -> str:
    return f"{moment.year}-{calendar.month_abbr[moment.month]}"


def _previous_month(moment: datetime) -> datetime:
    return datetime(moment.year - (moment.month == 1), 12 if moment.month == 1 else moment.month - 1,
                    1, tzinfo=UTC)


def _product_map(tree: object) -> dict[str, str]:
    products: dict[str, str] = {}

    def walk(value: object) -> None:
        if isinstance(value, dict):
            product_id = value.get("ProductID")
            name = value.get("Value")
            if isinstance(product_id, str) and isinstance(name, str):
                products[product_id] = name
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(tree)
    return products


def _architecture(inventory: dict) -> str:
    raw = str(inventory.get("os_architecture") or "").lower()
    if "arm64" in raw:
        return "ARM64-based Systems"
    if "64" in raw or "amd64" in raw:
        return "x64-based Systems"
    return "32-bit Systems"


def match_product(inventory: dict, products: dict[str, str]) -> tuple[str, str]:
    display = str(inventory.get("display_version") or "").strip()
    os_name = str(inventory.get("os_name") or "")
    build = int(str(inventory.get("os_build") or "0").split(".")[0] or 0)
    candidates: list[str] = []
    if "server" in os_name.lower():
        year = next((item for item in ("2025", "2022", "2019", "2016") if item in os_name), "")
        if year:
            suffix = " (Server Core installation)" \
                if str(inventory.get("installation_type") or "").lower() == "server core" else ""
            candidates.append(f"Windows Server {year}{suffix}")
    elif display:
        family = "Windows 11" if build >= 22000 else "Windows 10"
        candidates.append(f"{family} Version {display} for {_architecture(inventory)}")
    normalized = {name.casefold(): (product_id, name) for product_id, name in products.items()}
    for candidate in candidates:
        if candidate.casefold() in normalized:
            return normalized[candidate.casefold()]
    expected = candidates[0] if candidates else "producto Windows sin version util"
    raise MsrcError(f"MSRC no contiene una coincidencia exacta para: {expected}")


def _version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value))


def _catalog(document: dict, product_id: str) -> tuple[list[dict], int]:
    rows: list[dict] = []
    unresolved = 0
    for vulnerability in document.get("Vulnerability") or []:
        if not isinstance(vulnerability, dict):
            continue
        affected = any(
            item.get("Type") == 3 and product_id in (item.get("ProductID") or [])
            for item in vulnerability.get("ProductStatuses") or []
            if isinstance(item, dict)
        )
        if not affected:
            continue
        remediations = [
            item for item in vulnerability.get("Remediations") or []
            if isinstance(item, dict) and item.get("Type") == 2
            and product_id in (item.get("ProductID") or []) and item.get("FixedBuild")
        ]
        if not remediations:
            unresolved += 1
            continue
        scores = [
            item for item in vulnerability.get("CVSSScoreSets") or []
            if isinstance(item, dict) and product_id in (item.get("ProductID") or [])
        ]
        score = max(scores, key=lambda item: float(item.get("BaseScore") or 0), default={})
        remediation = max(remediations, key=lambda item: _version(str(item["FixedBuild"])))
        rows.append({
            "cve_id": str(vulnerability.get("CVE") or ""),
            "title": str((vulnerability.get("Title") or {}).get("Value") or ""),
            "cvss": float(score["BaseScore"]) if score.get("BaseScore") is not None else None,
            "cvss_vector": str(score.get("Vector") or ""),
            "kb": str((remediation.get("Description") or {}).get("Value") or ""),
            "fixed_build": str(remediation["FixedBuild"]),
            "url": str(remediation.get("URL") or ""),
        })
    return rows, unresolved


def assess_inventory(
    inventory: dict, *, release_id: str | None = None, fetch_json=_fetch_json,
) -> tuple[dict, list[dict]]:
    # os_version suele incluir una revision ficticia .0; el build real es Build.UBR.
    installed = f"10.0.{inventory.get('os_build')}.{inventory.get('ubr')}"
    if inventory.get("ubr") is None or not inventory.get("os_build"):
        raise MsrcError("El inventario no contiene build y UBR de Windows")
    releases = [release_id] if release_id else [
        _release_for(datetime.now(UTC)), _release_for(_previous_month(datetime.now(UTC)))
    ]
    last_error: MsrcError | None = None
    document: dict | None = None
    chosen = ""
    products: dict[str, str] = {}
    for release in releases:
        assert release is not None
        product_cache = _fresh(f"msrc-products:{release}")
        if isinstance(product_cache, dict):
            products = {str(key): str(value) for key, value in product_cache.items()}
            chosen = release
            break
        try:
            document = fetch_json(f"{BASE_URL}/{release}?api-version={API_VERSION}")
        except MsrcError as exc:
            last_error = exc
            continue
        products = _product_map(document.get("ProductTree"))
        if not products:
            last_error = MsrcError("Documento MSRC sin arbol de productos")
            continue
        db.put_feed_cache(f"msrc-products:{release}", products)
        chosen = release
        break
    if not chosen:
        raise last_error or MsrcError("No se encontro un boletin MSRC mensual")
    product_id, product_name = match_product(inventory, products)
    cache_key = f"msrc-catalog:{chosen}:{product_id}"
    cached = _fresh(cache_key)
    if isinstance(cached, dict) and isinstance(cached.get("rows"), list):
        catalog = cached["rows"]
        unresolved = int(cached.get("unresolved", 0))
    else:
        if document is None:
            document = fetch_json(f"{BASE_URL}/{chosen}?api-version={API_VERSION}")
        catalog, unresolved = _catalog(document, product_id)
        db.put_feed_cache(cache_key, {"rows": catalog, "unresolved": unresolved})
    if not catalog:
        raise MsrcError(f"MSRC no publico builds corregidos para {product_name} en {chosen}")
    relevant = [row for row in catalog if _version(row["fixed_build"])[0:3] == _version(installed)[0:3]]
    if not relevant:
        raise MsrcError("Los builds corregidos de MSRC no coinciden con la rama instalada")
    latest = max(relevant, key=lambda row: _version(row["fixed_build"]))
    missing = [dict(row, installed_build=installed) for row in relevant
               if _version(installed) < _version(row["fixed_build"])]
    status_name = "outdated" if missing else "partial" if unresolved else "current"
    status = {
        "release_id": chosen, "product_id": product_id, "product_name": product_name,
        "installed_build": installed, "required_build": latest["fixed_build"],
        "required_kb": latest["kb"], "status": status_name, "unresolved": unresolved,
    }
    return status, missing


def assess_scan(scan_id: int, *, release_id: str | None = None) -> int:
    if db.get_scan(scan_id) is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    inventories = db.get_host_inventories(scan_id)
    windows = [(host, data) for host, data in inventories.items()
               if data.get("platform", "windows") == "windows"]
    if not windows:
        raise MsrcError("El escaneo no tiene inventario Windows autenticado")
    db.set_enrichment_status(scan_id, "msrc", "running")
    total = 0
    errors: list[str] = []
    for host, inventory in windows:
        try:
            status, missing = assess_inventory(inventory, release_id=release_id)
        except MsrcError as exc:
            errors.append(f"{host}: {exc}")
            continue
        db.replace_windows_patch_assessment(scan_id, host, status, missing)
        total += len(missing)
    if errors:
        db.set_enrichment_status(scan_id, "msrc", "partial" if len(errors) < len(windows) else "failed",
                                 "; ".join(errors))
        if len(errors) == len(windows):
            raise MsrcError("; ".join(errors))
    else:
        db.set_enrichment_status(scan_id, "msrc", "done")
    return total
