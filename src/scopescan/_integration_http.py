"""Bounded worker HTTP transport with explicit trust and cancellation."""
from __future__ import annotations

import json
import time

import requests


class ConnectorError(ValueError):
    pass


class Cancelled(ConnectorError):
    pass


def redact_known(value, *secrets):
    """Remove worker credentials even when a server echoes them in free text."""
    if isinstance(value, dict):
        return {redact_known(key, *secrets): redact_known(item, *secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_known(item, *secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[redacted]")
    return value


def check(cancel, deadline):
    if cancel is not None and cancel.is_set():
        raise Cancelled("Integration cancelled; a pending remote write may need reconciliation")
    if time.monotonic() >= deadline:
        raise ConnectorError("Integration deadline exceeded; inspect delivery state before retry")


def session():
    client = requests.Session()
    client.trust_env = False
    client.verify = True
    return client


def request_json(client, method, url, *, cancel=None, deadline, max_bytes=8_000_000, **kwargs):
    check(cancel, deadline)
    remaining = deadline - time.monotonic()
    try:
        with client.request(method, url, timeout=(min(5, remaining), min(1, remaining)), stream=True, allow_redirects=False, **kwargs) as response:
            if 300 <= response.status_code < 400:
                raise ConnectorError("Connector redirects are refused; configure the final HTTPS base URL")
            if not 200 <= response.status_code < 300:
                raise ConnectorError(f"Connector HTTP {response.status_code}; check destination credentials and remote API compatibility")
            length = response.headers.get("Content-Length")
            if length and (not length.isdecimal() or int(length) > max_bytes):
                raise ConnectorError("Connector response exceeds the configured byte limit")
            raw = bytearray()
            for chunk in response.iter_content(chunk_size=16_384):
                check(cancel, deadline)
                raw.extend(chunk)
                if len(raw) > max_bytes:
                    raise ConnectorError("Connector response exceeds the configured byte limit")
        check(cancel, deadline)
        def reject_constant(value):
            raise ValueError("Non-finite JSON values are forbidden")
        value = json.loads(raw, parse_constant=reject_constant)
        if not isinstance(value, (dict, list)):
            raise TypeError
        return value
    except ConnectorError:
        raise
    except (requests.RequestException, ValueError, TypeError, RecursionError) as exc:
        # Remote error bodies and exception URLs may contain secrets; never persist them.
        raise ConnectorError("Connector transport or JSON response failed; verify service availability and API contract") from exc


def pause(seconds, *, cancel, deadline):
    until = min(time.monotonic() + seconds, deadline)
    while time.monotonic() < until:
        check(cancel, deadline)
        interval = min(.1, until - time.monotonic())
        if cancel is not None:
            cancel.wait(interval)
        else:
            time.sleep(interval)
    check(cancel, deadline)
