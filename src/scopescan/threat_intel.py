"""Priorizacion de CVE candidatas con CISA KEV y FIRST EPSS."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from . import db

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_TTL = timedelta(hours=20)


class ThreatIntelError(RuntimeError):
    """Un feed de priorizacion no estuvo disponible o devolvio datos invalidos."""


def _fetch_json(url: str, *, limit: int = 12_000_000) -> dict:
    request = Request(url, headers={"User-Agent": "ScopeScan/0.2 threat prioritization"})
    try:
        with urlopen(request, timeout=25) as response:
            payload = response.read(limit + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ThreatIntelError(f"Feed no disponible: {exc}") from exc
    if len(payload) > limit:
        raise ThreatIntelError("Respuesta del feed demasiado grande")
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ThreatIntelError("El feed no devolvio JSON valido") from exc
    if not isinstance(data, dict):
        raise ThreatIntelError("Formato inesperado en el feed")
    return data


def _fresh(cache_key: str) -> object | None:
    row = db.get_feed_cache(cache_key)
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"])
    if datetime.now(UTC) - fetched >= CACHE_TTL:
        return None
    return json.loads(row["payload"])


def kev_catalog(*, fetch_json=_fetch_json) -> dict[str, dict]:
    cached = _fresh("cisa-kev")
    if isinstance(cached, dict):
        return cached
    data = fetch_json(CISA_KEV_URL)
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ThreatIntelError("Catalogo KEV sin lista de vulnerabilidades")
    catalog = {
        item["cveID"]: {
            "due_date": item.get("dueDate", ""),
            "action": item.get("requiredAction", ""),
        }
        for item in vulnerabilities
        if isinstance(item, dict) and isinstance(item.get("cveID"), str)
    }
    db.put_feed_cache("cisa-kev", catalog)
    return catalog


def epss_scores(cve_ids: set[str], *, fetch_json=_fetch_json) -> dict[str, dict]:
    scores: dict[str, dict] = {}
    missing: list[str] = []
    for cve_id in sorted(cve_ids):
        cached = _fresh(f"epss:{cve_id}")
        if isinstance(cached, dict):
            scores[cve_id] = cached
        else:
            missing.append(cve_id)
    while missing:
        batch: list[str] = []
        length = 0
        while missing and length + len(missing[0]) + bool(batch) <= 1900:
            value = missing.pop(0)
            batch.append(value)
            length += len(value) + bool(batch)
        data = fetch_json(f"{EPSS_URL}?{urlencode({'cve': ','.join(batch)})}", limit=2_000_000)
        returned = data.get("data")
        if not isinstance(returned, list):
            raise ThreatIntelError("Respuesta EPSS sin datos")
        found: set[str] = set()
        for item in returned:
            try:
                record = {
                    "epss": float(item["epss"]),
                    "percentile": float(item["percentile"]),
                    "date": str(item.get("date", "")),
                }
                cve_id = str(item["cve"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ThreatIntelError("Registro EPSS invalido") from exc
            scores[cve_id] = record
            db.put_feed_cache(f"epss:{cve_id}", record)
            found.add(cve_id)
        for cve_id in set(batch) - found:
            db.put_feed_cache(f"epss:{cve_id}", {})
    return scores


def enrich_candidates(rows: list[dict]) -> tuple[list[dict], list[str]]:
    """Añade señales independientes; un fallo de feed no elimina resultados NVD."""
    errors: list[str] = []
    cve_ids = {row["cve_id"] for row in rows}
    try:
        kev = kev_catalog()
        kev_assessed = True
    except ThreatIntelError as exc:
        kev = {}
        kev_assessed = False
        errors.append(f"CISA KEV: {exc}")
    try:
        epss = epss_scores(cve_ids)
    except ThreatIntelError as exc:
        epss = {}
        errors.append(f"EPSS: {exc}")
    for row in rows:
        score = epss.get(row["cve_id"], {})
        known = kev.get(row["cve_id"], {})
        row.update(
            epss=score.get("epss"), epss_percentile=score.get("percentile"),
            epss_date=score.get("date", ""), known_exploited=bool(known),
            kev_assessed=kev_assessed, kev_checked_at=db.now() if kev_assessed else None,
            kev_due_date=known.get("due_date", ""), kev_action=known.get("action", ""),
        )
    return rows, errors
