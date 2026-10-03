"""Versioned local prioritisation model, never an exploitability verdict."""

from __future__ import annotations

import ipaddress
import math
from datetime import UTC, datetime
from typing import Any

MODEL_VERSION = "local-v1"


def asset_risk(findings: list[dict[str, Any]], *, address: str, criticality: int,
               candidates: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    factors = []
    total = 0.0
    candidate_count = 0
    public_counts = {"public": 0, "non_public": 0, "unknown": 0}
    feed = candidates or []
    for item in findings:
        if item.get("lifecycle") in {"resolved", "evidence_unavailable"} or item.get("status") == "closed":
            continue
        endpoint_address = item.get("host")
        try:
            public = ipaddress.ip_address(endpoint_address).is_global
        except (ValueError, TypeError):
            public = None
        public_counts["public" if public else "non_public" if public is False else "unknown"] += 1
        exposure = 1.25 if public else 1.0
        assessment = item.get("assessment", "exposure")
        evidence_weight = {"confirmed": 1.0, "exposure": 0.7, "candidate": 0.35}[assessment]
        candidate_count += assessment == "candidate"
        matched = [r for r in feed if r.get("cve_id") in item.get("cve_ids", [])
                   and r.get("host") == item.get("host")
                   and r.get("port") == item.get("port")
                   and r.get("protocol") == item.get("protocol")]
        kev = (True if any(r.get("known_exploited") for r in matched) else
               False if matched and all(r.get("kev_assessed") for r in matched) else None)
        epss_values = []
        for match in matched:
            if match.get("epss") is not None:
                value = float(match["epss"])
                if math.isfinite(value) and 0 <= value <= 1:
                    epss_values.append(value)
        epss = max(epss_values, default=None)
        severity_weight = [0, 2, 8, 20, 40][int(item["severity"])]
        threat = 1 + (0.5 if kev else 0) + (0.5 * min(1, max(0, epss)) if epss is not None else 0)
        value = severity_weight * evidence_weight * exposure * threat * (0.75 + criticality * 0.25)
        total += value
        factors.append({"finding_id": item["id"], "severity": int(item["severity"]),
                        "severity_weight": severity_weight, "assessment": assessment,
                        "evidence_weight": evidence_weight, "exposure_weight": exposure,
                        "endpoint_address": endpoint_address, "public_address": public,
                        "known_exploited": kev, "epss": epss, "threat_weight": threat,
                        "feed_assessed": bool(matched),
                        "feed_dates": sorted({r.get("epss_date", "") for r in matched}),
                        "kev_assessed": any(r.get("kev_assessed") for r in matched),
                        "kev_checked_at": sorted({r.get("kev_checked_at") for r in matched if r.get("kev_checked_at")}),
                        "epss_assessed": epss is not None,
                        "feed_freshness": _feed_freshness(matched),
                        "contribution": round(value, 3)})
    return {"score": round(100 * (1 - math.exp(-total / 60))), "model": MODEL_VERSION,
            "criticality": criticality, "public_address": True if public_counts["public"] else False if public_counts["non_public"] else None,
            "endpoint_exposure": public_counts,
            "exposure_basis": "Each finding endpoint address; reachability not established",
            "candidate_count": candidate_count, "factors": factors,
            "formula": "100*(1-exp(-sum(severity*evidence*exposure*threat*(0.75+criticality*0.25))/60))",
            "limitations": "Local prioritisation; missing KEV/EPSS is unknown; candidates remain unconfirmed."}


def _feed_freshness(rows: list[dict]) -> dict:
    dates = {}
    for feed, field in (("kev", "kev_checked_at"), ("epss", "epss_date")):
        valid = []
        for row in rows:
            value = row.get(field)
            if not value:
                continue
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            valid.append(parsed.astimezone(UTC))
        latest = max(valid, default=None)
        age = max(0, (datetime.now(UTC) - latest).total_seconds() / 86400) if latest else None
        dates[feed] = {"as_of": latest.isoformat() if latest else None,
                       "age_days": round(age, 2) if age is not None else None,
                       "stale": age > 2 if age is not None else None,
                       "stale_after_days": 2}
    return dates
