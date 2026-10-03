"""Serializable, exact grants for operations that contact assessment targets."""
from __future__ import annotations

import ipaddress
import json

from . import db
from .targets import parse_targets

ACTIVE_KINDS = frozenset({"linux", "windows", "metasploit", "metasploit-exploit"})
SCOPE_KEYS = ("profile", "authorized_by", "pinned_targets", "resolutions", "exclusions", "max_hosts")


def _address(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError) as exc:
        raise ValueError("Active operations require concrete pinned IP addresses") from exc


def _contains(target, host, resolutions, *, excluded=False):
    address = ipaddress.ip_address(_address(host))
    if target.kind in {"ip","cidr"}:
        return address in ipaddress.ip_network(target.raw,strict=False)
    if target.kind == "range":
        if address.version != 4:
            return False
        for value,part in zip(str(address).split("."),target.raw.split("."),strict=True):
            low,_,high = part.partition("-")
            if not int(low) <= int(value) <= int(high or low):
                return False
        return True
    key = f"exclude:{target.raw}" if excluded else target.raw
    if key not in resolutions:
        raise ValueError("Hostname has no pinned grant; create or refresh a saved scope")
    return str(address) in {_address(value) for value in resolutions[key]}


def capture(conn, scan_id, kind, options):
    if kind not in ACTIVE_KINDS:
        return None
    scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if scan is None or scan["deletion_pending"]:
        raise ValueError("Scan missing or pending deletion")
    context = json.loads(scan["execution_context"] or "{}")
    hosts = [row[0] for row in conn.execute("SELECT address FROM hosts WHERE scan_id=? AND state='up' ORDER BY address", (scan_id,))]
    selected = options.get("host")
    if kind in {"linux", "windows"}:
        if selected is not None and selected not in hosts:
            raise ValueError("Selected inventory host is not an up host in the scan")
        targets = [selected] if selected is not None else hosts
        if type(options.get("local", False)) is not bool:
            raise ValueError("Local inventory selection must be a boolean")
        if options.get("local"):
            if len(targets) != 1 or not ipaddress.ip_address(_address(targets[0])).is_loopback:
                raise ValueError("Local inventory requires one explicit loopback target")
            return {"mode":"local", "kind":kind, "targets":targets}
        port = options.get("port", 22) if kind == "linux" else 5985
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid inventory listener port")
        endpoints = [{"host":_address(host), "port":port, "protocol":"tcp"} for host in targets]
    elif kind == "metasploit":
        from . import msf
        with db.read_from_connection(conn):
            plan = msf.plan_scan(scan_id)
        endpoints = sorted([{"host":_address(host),"port":port,"protocol":"tcp","module":module.path,"action":module.action}
                            for host,port,_service,module in plan], key=lambda item: (item["host"],item["port"],item["module"],item["action"]))
        targets = sorted({item["host"] for item in endpoints})
    else:
        from . import msf
        with db.read_from_connection(conn):
            _scan,module,port = msf._validated_exploit_context(scan_id,host=options.get("host"),
                port=options.get("port"),module_path=options.get("module_path"),allow_public=options.get("allow_public",False))
        targets = [_address(options["host"])]
        endpoints = [{"host":targets[0],"port":port,"protocol":"tcp","module":module.path,"action":"exploit"}]
    if scan["scope_id"] is not None:
        saved_row = conn.execute("SELECT specification FROM saved_scopes WHERE id=?", (scan["scope_id"],)).fetchone()
        if saved_row is None:
            raise ValueError("Saved scope deleted; review and enqueue the active operation again")
        saved = json.loads(saved_row[0])
        if not isinstance(saved.get("authorized_by"), str) or not saved["authorized_by"].strip():
            raise ValueError("Saved scope authorization revoked; review and enqueue again")
        snapshot = {key:saved[key] for key in SCOPE_KEYS}
        allowed = {_address(host) for host in saved["pinned_targets"]}
        if any(_address(host) not in allowed for host in targets):
            raise ValueError("Selected target is excluded from the current saved scope")
        if saved["exclusions"].strip():
            excluded = parse_targets(saved["exclusions"],force=True).targets
            if any(_contains(target,host,saved["resolutions"],excluded=True) for target in excluded for host in targets):
                raise ValueError("Selected target matches an explicit scope exclusion")
        grant = {"mode":"saved_scope","scope_id":scan["scope_id"],"scope_snapshot":snapshot}
    else:
        if scan["profile"] == "imported" or context.get("provenance", {}).get("imported"):
            raise ValueError("Imported evidence needs an authorized saved scope before remote operations")
        # Historical ad-hoc IP/CIDR requests remain usable; never infer a grant
        # from imported/up host rows or resolve a hostname again in the worker.
        pinned = context.get("pinned_targets")
        selectors = parse_targets(" ".join(pinned) if pinned else scan["targets"], force=True).targets
        if any(not any(_contains(target,host,context.get("resolutions",{})) for target in selectors) for host in targets):
            raise ValueError("Selected target is outside the original ad-hoc scan grant")
        grant = {"mode":"ad_hoc","scan_snapshot":{"targets":scan["targets"],"profile":scan["profile"],
            "authorized_by":scan["authorized_by"],"pinned_targets":pinned}}
    return dict(grant, kind=kind, targets=targets, endpoints=endpoints)


def validate(scan_id, kind, options, grant):
    if kind not in ACTIVE_KINDS:
        return
    if not isinstance(grant,dict):
        raise ValueError("Active operation grant missing; review and enqueue again")  # noqa: TRY004 - malformed external operation JSON
    with db.connect() as conn:
        current = capture(conn, scan_id, kind, options)
    if current != grant:
        raise ValueError("Active operation scope, authorization, limits or endpoints changed; review and enqueue again")
