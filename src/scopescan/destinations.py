"""Validated connector configuration; credentials are resolved only by workers."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit, urlunsplit

KINDS = {"defectdojo", "faraday", "greenbone"}


def validate(kind, url, settings):
    if kind not in KINDS or not isinstance(settings, dict):
        raise ValueError("Choose defectdojo, faraday or greenbone and an options object")
    if not isinstance(url, str) or len(url) > 2048 or any(c.isspace() for c in url):
        raise ValueError("Destination URL is invalid")
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment or "%" in parts.netloc:
        raise ValueError("Destination URLs cannot contain credentials, query parameters or fragments")
    allowed = {"timeout", "token_env", "username_env", "password_env", "workspace", "allow_http_loopback"}
    if set(settings) - allowed:
        raise ValueError("Unknown destination option; use environment references for credentials")
    settings = dict(settings)
    timeout = settings.get("timeout", 120)
    if type(timeout) not in (int, float) or not 1 <= timeout <= 600:
        raise ValueError("Destination timeout must be 1..600 seconds")
    settings["timeout"] = timeout
    for key in ("token_env", "username_env", "password_env"):
        if key in settings and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", str(settings[key])):
            raise ValueError("Credential settings must name environment variables")
    if kind == "greenbone":
        if parts.scheme == "unix":
            if parts.netloc or not parts.path.startswith("/") or ".." in parts.path.split("/"):
                raise ValueError("GMP Unix socket requires an absolute socket path")
        elif parts.scheme != "tls" or not parts.hostname or parts.path not in ("", "/"):
            raise ValueError("GMP requires tls://host:port or unix:///absolute/socket")
        else:
            try:
                if not 1 <= (parts.port or 9390) <= 65535:
                    raise ValueError
            except ValueError as exc:
                raise ValueError("Invalid GMP port") from exc
    else:
        if not parts.hostname or parts.scheme not in {"https", "http"}:
            raise ValueError("HTTP connectors require HTTPS")
        if parts.scheme == "http":
            try:
                local = ipaddress.ip_address(parts.hostname).is_loopback
            except ValueError:
                local = parts.hostname == "localhost"
            if not local or settings.get("allow_http_loopback") is not True:
                raise ValueError("HTTP requires an explicit loopback development destination")
        if type(settings.get("allow_http_loopback", False)) is not bool:
            raise ValueError("allow_http_loopback must be a boolean")
        try:
            _ = parts.port
        except ValueError as exc:
            raise ValueError("Invalid destination port") from exc
    required = ("token_env",) if kind == "defectdojo" else ("username_env", "password_env")
    if any(not settings.get(key) for key in required):
        raise ValueError("Configure " + ", ".join(required) + " on the worker")
    if kind == "faraday" and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", str(settings.get("workspace", ""))):
        raise ValueError("Faraday requires a workspace name")
    canonical = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), "", ""))
    return canonical, settings


def fingerprint(destination):
    encoded = json.dumps({key: destination[key] for key in ("kind", "url", "settings")}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def credential(destination, key):
    name = destination["settings"].get(key, "")
    value = os.environ.get(name, "")
    if not value or len(value) > 16384 or "\r" in value or "\n" in value:
        raise ValueError(f"Worker credential environment variable {name or key} is missing or invalid")
    return value
