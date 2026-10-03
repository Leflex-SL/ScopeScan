"""Optional engine discovery, immutable plans, and evidence persistence."""
from __future__ import annotations

import importlib
import threading
from dataclasses import asdict

from . import db
from .engine_contracts import Endpoint, EnginePlan, EngineResult, Provenance, ScanScope
from .engine_store import persist

ADAPTERS = {"nuclei": ("scopescan.nuclei", "NucleiAdapter"), "sslyze": ("scopescan.sslyze_adapter", "SSLyzeAdapter")}


def adapter(name: str):
    if name not in ADAPTERS:
        raise ValueError(f"Unknown engine {name}; choose {', '.join(ADAPTERS)}")
    module, cls = ADAPTERS[name]
    try:
        return getattr(importlib.import_module(module), cls)()
    except (ImportError, AttributeError) as exc:
        raise ValueError(f"Engine {name} adapter is unavailable: {exc}") from exc


def catalog():
    items = []
    for name in ADAPTERS:
        try:
            engine = adapter(name)
            available, message = engine.available()
        except (ValueError, OSError) as exc:
            available, message = False, str(exc)
        items.append({"name": name, "available": available, "message": message})
    return items


def scope_from_saved(scope_id: int, *, ports: tuple[int, ...] = (), service: str = "") -> ScanScope:
    row = db.get_scope(scope_id)
    if row is None:
        raise ValueError("Saved scope does not exist")
    if len(ports) > 100 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("Specify up to 100 TCP ports between 1 and 65535")
    if service not in {"", "http", "https", "tls"} or (service and not ports):
        raise ValueError("Explicit service must be http/https/tls and requires explicit TCP ports")
    endpoints = []
    known = {}
    asset_offset = 0
    while True:
        assets,total = db.list_assets(scope_id=scope_id, limit=100,offset=asset_offset)
        for asset in assets:
            port_offset = 0
            while True:
                asset_ports,port_total = db.list_asset_ports(asset["id"], limit=100,offset=port_offset)
                for port in asset_ports:
                    host = port.get("address", asset["address"])
                    if port.get("state") == "open" and port.get("protocol") == "tcp":
                        label = port.get("service_name", "")
                        if label == "http" and port.get("tunnel") == "ssl":
                            label = "https"
                        known[(host, port["portid"])] = label
                        if len(known)>65536:
                            raise ValueError("Scope exceeds 65536 observed services; narrow the saved scope or specify explicit ports")
                port_offset += len(asset_ports)
                if port_offset>=port_total or not asset_ports:
                    break
        asset_offset += len(assets)
        if asset_offset>=total or not assets:
            break
    resolutions = tuple((name, tuple(addresses)) for name, addresses in row["resolutions"].items() if not name.startswith("exclude:"))
    for host in row["pinned_targets"]:
        hostnames = [name for name, addresses in resolutions if host in addresses]
        selected = ports or tuple(port for address, port in known if address == host)
        for port in selected:
            endpoints.append(Endpoint(host, port, service=service or known.get((host, port), ""), hostname=hostnames[0] if hostnames else ""))
    if not endpoints:
        raise ValueError("No observed TCP services. Specify explicit ports in the authorized scope preview.")
    return ScanScope(f"scope:{scope_id}", row["authorized_by"], tuple(endpoints), scope_id, resolutions)


def preview(name: str, scope_id: int, *, ports: tuple[int, ...] = (), timeout: float = 120, service: str = "") -> EnginePlan:
    return adapter(name).plan(scope_from_saved(scope_id, ports=ports,service=service), timeout=timeout)


def create_execution(plan: EnginePlan) -> int:
    return db.create_scan(name=f"{plan.engine} assessment", targets=" ".join(sorted({e.host for e in plan.endpoints})),
        profile=plan.engine, authorized_by=plan.scope.authorized_by, scope_id=plan.scope.scope_id,
        execution_context={"namespace":plan.scope.namespace,"engine_plan":asdict(plan)}, reserve_job=True)


def execute(plan: EnginePlan, *, scan_id: int | None = None, cancel: threading.Event | None = None) -> int:
    validate_scope(plan)
    engine = adapter(plan.engine)
    available, message = engine.available()
    if not available:
        raise ValueError(message)
    scan_id = scan_id or create_execution(plan)
    try:
        result = engine.execute(plan, cancel=cancel)
        return persist(plan,result,scan_id=scan_id)
    except Exception as exc:
        result = EngineResult(plan.engine,"cancelled" if cancel and cancel.is_set() else "failed",
            Provenance(plan.engine,"unknown","unknown"),errors=(str(exc)[:4096],))
        persist(plan,result,scan_id=scan_id)
        raise


def validate_scope(plan: EnginePlan) -> None:
    if plan.scope.scope_id is None:
        return
    scope = db.get_scope(plan.scope.scope_id)
    if scope is None or scope["authorized_by"] != plan.scope.authorized_by or any(e.host not in scope["pinned_targets"] for e in plan.endpoints):
        raise ValueError("Engine scope authorization changed; preview again")
    if any(e.hostname and e.host not in scope["resolutions"].get(e.hostname,[]) for e in plan.endpoints):
        raise ValueError("Engine hostname binding changed; preview again")


def decode_plan(value: dict) -> EnginePlan:
    data = dict(value)
    scope_data = dict(data.pop("scope"))
    scope_data["endpoints"] = tuple(Endpoint(**endpoint) for endpoint in scope_data["endpoints"])
    scope_data["resolutions"] = tuple((name,tuple(addresses)) for name,addresses in scope_data.get("resolutions",[]))
    data["scope"] = ScanScope(**scope_data)
    data["endpoints"] = tuple(Endpoint(**endpoint) for endpoint in data["endpoints"])
    data["rules"] = tuple(data["rules"])
    data["options"] = tuple(tuple(pair) for pair in data.get("options",[]))
    return EnginePlan(**data)


def import_evidence(kind: str, payload: bytes, *, scope_id: int, host: str, inventory_scan_id: int | None = None) -> int:
    if len(payload) > 8_000_000:
        raise ValueError("Engine import exceeds 8 MB")
    saved = db.get_scope(scope_id)
    if saved is None or host not in saved["pinned_targets"]:
        raise ValueError("Imported host must be an exact pinned address in the saved scope")
    scope = ScanScope(f"scope:{scope_id}",saved["authorized_by"],(Endpoint(host,None,"host"),),scope_id)
    if kind == "vuls":
        from .vuls_import import VulsImportAdapter
        engine = VulsImportAdapter(payload,host=host)
    elif kind == "linux-advisories":
        from .linux_advisories import LinuxAdvisoryAdapter
        if inventory_scan_id is None:
            raise ValueError("Linux advisories require an inventory scan ID")
        inventory = db.get_host_inventories(inventory_scan_id).get(host)
        if inventory is None:
            raise ValueError("No authenticated Linux inventory exists for this host and scan")
        if not inventory.get("observed_at"):
            with db.connect() as conn:
                inventory_row = conn.execute("SELECT collected_at FROM host_inventory WHERE scan_id=? AND host=?",(inventory_scan_id,host)).fetchone()
            inventory = dict(inventory,observed_at=inventory_row["collected_at"])
        engine = LinuxAdvisoryAdapter(inventory,payload,host=host)
    else:
        raise ValueError("Supported engine imports: vuls, linux-advisories")
    plan = engine.plan(scope)
    result = engine.execute(plan)
    if not result.provenance.imported:
        raise ValueError("Imported evidence adapter did not declare external provenance")
    return persist(plan,result)


def executions(*, limit: int = 50, offset: int = 0):
    with db.connect() as conn:
        rows = conn.execute("SELECT id,name,profile,status,error,created_at,scope_id FROM scans WHERE json_type(execution_context,'$.engine_plan') IS NOT NULL ORDER BY id DESC LIMIT ? OFFSET ?",(max(1,min(limit,100)),max(0,offset))).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM scans WHERE json_type(execution_context,'$.engine_plan') IS NOT NULL").fetchone()[0]
    return [dict(row) for row in rows],total
