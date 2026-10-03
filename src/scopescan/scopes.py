"""Validated, bounded scopes. DNS answers become immutable execution targets."""

from __future__ import annotations

import ipaddress
import itertools
import socket
from dataclasses import dataclass

from . import db
from .config import MAX_HOSTS_DEFAULT
from .profiles import DEFAULT_PROFILE, get_profile
from .targets import InvalidTarget, TargetSet, parse_targets

HARD_HOST_LIMIT = 65536


@dataclass(frozen=True)
class PinnedScope:
    target_set: TargetSet
    resolutions: dict[str, list[str]]
    excluded: tuple[str, ...]


def _expand(raw: str, limit: int) -> tuple[set[str], dict[str, list[str]]]:
    if len(raw) > 1024 * 1024:
        raise InvalidTarget("La especificacion del alcance supera 1 MiB")
    parsed = parse_targets(raw, max_hosts=limit)
    addresses: set[str] = set()
    resolutions: dict[str, list[str]] = {}
    for target in parsed.targets:
        if target.kind == "ip":
            values = [str(ipaddress.ip_address(target.raw))]
        elif target.kind == "cidr":
            values = [str(addr) for addr in ipaddress.ip_network(target.raw, strict=False)]
        elif target.kind == "range":
            octets = []
            for part in target.raw.split("."):
                low, _, high = part.partition("-")
                octets.append(range(int(low), int(high or low) + 1))
            values = [".".join(map(str, parts)) for parts in itertools.product(*octets)]
        else:
            try:
                answers = socket.getaddrinfo(target.raw, None, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise InvalidTarget(f"No se pudo resolver {target.raw}: {exc}") from exc
            values = sorted({str(ipaddress.ip_address(answer[4][0])) for answer in answers})
            if not values:
                raise InvalidTarget(f"{target.raw} no resolvio a ninguna IP")
            resolutions[target.raw] = values
        addresses.update(values)
        if len(addresses) > limit:
            raise InvalidTarget(f"El alcance resuelto supera el limite de {limit} hosts")
    return addresses, resolutions


def pin_targets(targets: str, exclusions: str = "", *,
                max_hosts: int = MAX_HOSTS_DEFAULT, force: bool = False) -> PinnedScope:
    if not 1 <= max_hosts <= HARD_HOST_LIMIT:
        raise InvalidTarget(f"max_hosts debe estar entre 1 y {HARD_HOST_LIMIT}")
    limit = HARD_HOST_LIMIT if force else max_hosts
    included, resolutions = _expand(targets, limit)
    excluded, excluded_dns = _expand(exclusions, limit) if exclusions.strip() else (set(), {})
    included -= excluded
    if not included:
        raise InvalidTarget("Las exclusiones dejan el alcance sin objetivos")
    families = {ipaddress.ip_address(addr).version for addr in included}
    if len(families) != 1:
        raise InvalidTarget("El alcance mezcla IPv4 e IPv6; guarda un alcance por familia")
    ordered = sorted(included, key=lambda addr: int(ipaddress.ip_address(addr)))
    return PinnedScope(parse_targets(" ".join(ordered), max_hosts=limit),
                       {**resolutions, **{f"exclude:{k}": v for k, v in excluded_dns.items()}},
                       tuple(sorted(excluded)))


def create_scope(*, name: str, targets: str, exclusions: str = "",
                 profile: str = DEFAULT_PROFILE, authorized_by: str = "", notes: str = "",
                 max_hosts: int = MAX_HOSTS_DEFAULT) -> int:
    if not name.strip() or not authorized_by.strip():
        raise ValueError("El alcance necesita nombre y responsable de autorizacion")
    get_profile(profile)
    pinned = pin_targets(targets, exclusions, max_hosts=max_hosts)
    return db.create_scope(name=name.strip(), targets=targets, exclusions=exclusions,
                           profile=profile, authorized_by=authorized_by.strip(), notes=notes,
                           pinned_targets=pinned.target_set.argv,
                           resolutions=pinned.resolutions, max_hosts=max_hosts)


def get_scope(scope_id: int):
    row = db.get_scope(scope_id)
    if row is None:
        raise ValueError(f"No existe el alcance {scope_id}")
    return row


def list_scopes(*, search: str = "", limit: int = 100, offset: int = 0):
    return db.list_scopes(search=search, limit=limit, offset=offset)


def update_scope(scope_id: int, *, name: str, targets: str, exclusions: str = "",
                 profile: str = DEFAULT_PROFILE, authorized_by: str = "", notes: str = "",
                 max_hosts: int = MAX_HOSTS_DEFAULT) -> None:
    get_scope(scope_id)
    if not name.strip() or not authorized_by.strip():
        raise ValueError("El alcance necesita nombre y responsable de autorizacion")
    get_profile(profile)
    pinned = pin_targets(targets, exclusions, max_hosts=max_hosts)
    db.update_scope(scope_id, name=name.strip(), targets=targets, exclusions=exclusions,
                    profile=profile, authorized_by=authorized_by.strip(), notes=notes,
                    max_hosts=max_hosts, pinned_targets=pinned.target_set.argv,
                    resolutions=pinned.resolutions)


def request_for_scope(scope_id: int):
    from .service import ScanRequest
    row = get_scope(scope_id)
    pinned = row["pinned_targets"]
    return ScanRequest(targets=" ".join(pinned), profile=row["profile"], name=row["name"],
                       authorized_by=row["authorized_by"], notes=row["notes"],
                       max_hosts=row["max_hosts"], scope_id=scope_id)


def preview_scope(scope_id: int):
    from .service import prepare
    return prepare(request_for_scope(scope_id))


def queue_scope(scope_id: int, *, prepared=None) -> int:
    from .service import queue_scan
    return queue_scan(request_for_scope(scope_id), prepared=prepared)
