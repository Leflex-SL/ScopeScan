"""Native Debian and RPM ordering; unsupported formats remain unevaluated."""

from __future__ import annotations

import re


def _epoch(raw):
    if not isinstance(raw, str) or not raw or len(raw) > 300 or not raw.isascii():
        raise ValueError("Version de paquete invalida")
    if ":" in raw:
        epoch, raw = raw.split(":", 1)
        if not epoch.isdigit():
            raise ValueError("Epoch invalido")
        return int(epoch), raw
    return 0, raw


def _debian_part(a, b):
    def order(ch):
        if ch == "~":
            return -1
        if not ch or ch.isdigit():
            return 0
        return ord(ch) if ch.isalpha() else ord(ch) + 256

    while a or b:
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            x, y = order(a[:1]), order(b[:1])
            if x != y:
                return (x > y) - (x < y)
            a, b = a[1:] if a else "", b[1:] if b else ""
        a, b = a.lstrip("0"), b.lstrip("0")
        ax = re.match(r"\d*", a)[0]
        bx = re.match(r"\d*", b)[0]
        if len(ax) != len(bx):
            return (len(ax) > len(bx)) - (len(ax) < len(bx))
        if ax != bx:
            return (ax > bx) - (ax < bx)
        a, b = a[len(ax) :], b[len(bx) :]
    return 0


def debian_compare(left, right):
    ae, a = _epoch(left)
    be, b = _epoch(right)
    for value in (a, b):
        if not re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", value):
            raise ValueError("Version Debian invalida")
    if ae != be:
        return (ae > be) - (ae < be)
    au, ar = a.rsplit("-", 1) if "-" in a else (a, "0")
    bu, br = b.rsplit("-", 1) if "-" in b else (b, "0")
    return _debian_part(au, bu) or _debian_part(ar, br)


def _rpm_part(a, b):
    while a or b:
        a = re.sub(r"^[^A-Za-z0-9~^]+", "", a)
        b = re.sub(r"^[^A-Za-z0-9~^]+", "", b)
        if a.startswith("~") or b.startswith("~"):
            if not a.startswith("~"):
                return 1
            if not b.startswith("~"):
                return -1
            a, b = a[1:], b[1:]
            continue
        if a.startswith("^") or b.startswith("^"):
            if not a:
                return -1
            if not b:
                return 1
            if not a.startswith("^"):
                return 1
            if not b.startswith("^"):
                return -1
            a, b = a[1:], b[1:]
            continue
        if not a or not b:
            return (bool(a) > bool(b)) - (bool(a) < bool(b))
        numeric = a[0].isdigit()
        if numeric != b[0].isdigit():
            return 1 if numeric else -1
        pattern = r"^[0-9]+" if numeric else r"^[A-Za-z]+"
        ax, bx = re.match(pattern, a)[0], re.match(pattern, b)[0]
        a, b = a[len(ax) :], b[len(bx) :]
        if numeric:
            ax, bx = ax.lstrip("0"), bx.lstrip("0")
            if len(ax) != len(bx):
                return (len(ax) > len(bx)) - (len(ax) < len(bx))
        if ax != bx:
            return (ax > bx) - (ax < bx)
    return 0


def rpm_compare(left, right):
    ae, a = _epoch(left)
    be, b = _epoch(right)
    if not all(re.fullmatch(r"[A-Za-z0-9._+~^\-]+", x) for x in (a, b)):
        raise ValueError("Version RPM invalida")
    if ae != be:
        return (ae > be) - (ae < be)
    av, ar = a.rsplit("-", 1) if "-" in a else (a, "")
    bv, br = b.rsplit("-", 1) if "-" in b else (b, "")
    return _rpm_part(av, bv) or _rpm_part(ar, br)


def compare_versions(left, right, manager):
    comparator = {"dpkg": debian_compare, "rpm": rpm_compare}.get(manager)
    if comparator is None:
        return None
    try:
        return comparator(left, right)
    except ValueError:
        return None
