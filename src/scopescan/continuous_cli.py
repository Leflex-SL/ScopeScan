"""CLI operations for assets, remediation, scopes, imports and verification."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from . import db
from .config import MAX_HOSTS_DEFAULT
from .profiles import DEFAULT_PROFILE, PROFILES


def _json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def cmd_continuous(args: argparse.Namespace) -> int:
    db.init_db()
    try:
        if hasattr(args, "limit") and not 1 <= args.limit <= 1000:
            raise ValueError("--limit debe estar entre 1 y 1000")
        if hasattr(args, "offset") and args.offset < 0:
            raise ValueError("--offset debe ser cero o positivo")
        return _run(args)
    except (ValueError, KeyError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    if args.command == "assets":
        items, total = db.list_assets(search=args.search, scope_id=args.scope_id,
                                     limit=args.limit, offset=args.offset)
        _json({"items": items, "total": total, "summary": db.current_summary()})
    elif args.command == "asset":
        item = db.get_asset(args.asset_id)
        if item is None:
            raise ValueError("Activo inexistente")
        if args.criticality is not None:
            db.update_asset_metadata(args.asset_id, args.criticality,
                                     alias=args.alias or "", actor=args.actor)
        elif args.alias:
            db.add_asset_alias(args.asset_id, args.alias, actor=args.actor)
        _json(db.get_asset(args.asset_id))
    elif args.command == "current-findings":
        items, total = db.list_current_findings(search=args.search, scope_id=args.scope_id,
                                              asset_id=args.asset_id, status=args.status,
                                              min_severity=args.min_severity,
                                              assessment=args.assessment, lifecycle=args.lifecycle,
                                              limit=args.limit, offset=args.offset)
        _json({"items": items, "total": total})
    elif args.command == "delta":
        if db.get_scan(args.scan_id) is None:
            raise ValueError("Escaneo inexistente")
        _json(db.scan_delta(args.scan_id))
    elif args.command == "asset-history":
        if db.get_asset(args.asset_id) is None:
            raise ValueError("Activo inexistente")
        items, total = db.list_asset_observations(args.asset_id, limit=args.limit,
                                                 offset=args.offset)
        _json({"items": items, "total": total})
    elif args.command == "historical-findings":
        items = db.recent_findings(limit=args.limit + 1, offset=args.offset,
                                   min_severity=args.min_severity, search=args.search)
        _json({"items": [dict(row) for row in items[:args.limit]],
               "has_next": len(items) > args.limit, "offset": args.offset})
    elif args.command == "remediate":
        if args.history:
            _json(db.remediation_history(args.finding_id))
        else:
            values = {key: getattr(args, key) for key in ("owner", "status", "due_at",
                      "exception_until", "evidence", "verification_scan_id")
                      if getattr(args, key) is not None}
            if values:
                _json(db.update_remediation(args.finding_id, actor=args.actor, **values))
            else:
                item = db.get_current_finding(args.finding_id)
                if item is None:
                    raise ValueError("Hallazgo inexistente")
                _json(item)
    elif args.command == "scope":
        from . import scopes
        action = args.scope_action
        if action == "list":
            items, total = scopes.list_scopes(search=args.search, limit=args.limit,
                                              offset=args.offset)
            _json({"items": items, "total": total})
        elif action in {"create", "update"}:
            values = {"name": args.name, "targets": " ".join(args.targets),
                      "exclusions": args.exclusions, "profile": args.profile,
                      "authorized_by": args.authorized_by, "notes": args.notes}
            values["max_hosts"] = args.max_hosts
            if action == "create":
                scope_id = scopes.create_scope(**values)
            else:
                scope_id = args.scope_id
                scopes.update_scope(scope_id, **values)
            _json(scopes.get_scope(scope_id))
        elif action == "show":
            item = scopes.get_scope(args.scope_id)
            if item is None:
                raise ValueError("Alcance inexistente")
            _json(item)
        elif action == "preview":
            prepared = scopes.preview_scope(args.scope_id)
            _json({"command": prepared.argv_preview, "warnings": prepared.warnings,
                   "targets": prepared.target_set.raw, "hosts": prepared.target_set.hosts})
        elif action == "run":
            if not args.yes:
                raise ValueError("Revisa scope preview y usa --yes para ejecutar el alcance autorizado")
            scan_id = scopes.queue_scope(args.scope_id)
            from .jobs import QUEUE
            from .worker import execute_now
            execute_now(QUEUE.submit(scan_id))
            scan = dict(db.get_scan(scan_id))
            _json(scan)
            return 0 if scan["status"] == "done" else 1
    elif args.command == "import":
        from . import importers
        importer = importers.import_nmap if args.kind == "nmap" else importers.import_external_json
        scan_id = importer(Path(args.path), name=args.name, namespace=args.namespace,
                           authorized_by=args.authorized_by)
        _json({"scan_id": scan_id, "scan": dict(db.get_scan(scan_id)),
               "delta": db.scan_delta(scan_id)})
    elif args.command == "verify":
        from . import verification
        plan = verification.plan_verification(args.finding_ids, authorized_by=args.authorized_by)
        if args.run:
            if not args.yes:
                raise ValueError("Usa --yes para ejecutar la verificacion autorizada")
            scan_ids = verification.queue_verification(plan)
            statuses = []
            from .jobs import QUEUE
            from .worker import execute_now
            for scan_id in scan_ids:
                execute_now(QUEUE.submit(scan_id))
                statuses.append(dict(db.get_scan(scan_id)))
            _json({"plan": dataclasses.asdict(plan), "scans": statuses,
                   "partial": bool(plan.missing_controls)})
            return (0 if statuses and not plan.missing_controls
                    and all(row["status"] == "done" for row in statuses) else 1)
        _json(dataclasses.asdict(plan))
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    assets = sub.add_parser("assets", help="Activos vigentes, alias y riesgo explicable (JSON)")
    findings = sub.add_parser("current-findings", help="Hallazgos vigentes sin duplicar reescaneos")
    for parser in (assets, findings):
        parser.add_argument("--search", default="")
        parser.add_argument("--scope-id", type=int)
        parser.add_argument("--limit", type=int, default=50)
        parser.add_argument("--offset", type=int, default=0)
        parser.set_defaults(func=cmd_continuous)
    findings.add_argument("--asset-id")
    findings.add_argument("--status", choices=("open", "in_progress", "exception", "closed"))
    findings.add_argument("--min-severity", type=int, choices=range(5), default=0)
    findings.add_argument("--assessment", choices=("candidate", "exposure", "confirmed"))
    findings.add_argument("--lifecycle", choices=("observed", "resolved", "not_assessed"))
    asset = sub.add_parser("asset", help="Detalle, alias y criticidad de un activo")
    asset.add_argument("asset_id")
    asset.add_argument("--criticality", type=int, choices=range(1, 6))
    asset.add_argument("--alias")
    asset.add_argument("--actor", default="cli")
    asset.set_defaults(func=cmd_continuous)
    delta = sub.add_parser("delta", help="Deltas y advertencias de cobertura")
    delta.add_argument("scan_id", type=int)
    delta.set_defaults(func=cmd_continuous)
    remediation = sub.add_parser("remediate", help="Responsable, excepcion, cierre y acciones")
    remediation.add_argument("finding_id")
    remediation.add_argument("--actor", default="cli")
    remediation.add_argument("--owner")
    remediation.add_argument("--status", choices=("open", "in_progress", "exception", "closed"))
    remediation.add_argument("--due-at")
    remediation.add_argument("--exception-until")
    remediation.add_argument("--evidence")
    remediation.add_argument("--verification-scan-id", type=int)
    remediation.add_argument("--history", action="store_true")
    remediation.set_defaults(func=cmd_continuous)
    scope = sub.add_parser("scope", help="Gestionar alcances guardados")
    actions = scope.add_subparsers(dest="scope_action", required=True)
    scope_list = actions.add_parser("list")
    scope_list.add_argument("--search", default="")
    scope_list.add_argument("--limit", type=int, default=50)
    scope_list.add_argument("--offset", type=int, default=0)
    scope_list.set_defaults(func=cmd_continuous)
    for action in ("create", "update"):
        parser = actions.add_parser(action)
        if action == "update":
            parser.add_argument("scope_id", type=int)
        parser.add_argument("--name", required=True)
        parser.add_argument("--targets", nargs="+", required=True)
        parser.add_argument("--exclusions", default="")
        parser.add_argument("--profile", choices=list(PROFILES), default=DEFAULT_PROFILE)
        parser.add_argument("--authorized-by", required=True)
        parser.add_argument("--notes", default="")
        parser.add_argument("--max-hosts", type=int, default=MAX_HOSTS_DEFAULT)
        parser.set_defaults(func=cmd_continuous)
    for action in ("show", "preview", "run"):
        parser = actions.add_parser(action)
        parser.add_argument("scope_id", type=int)
        if action == "run":
            parser.add_argument("-y", "--yes", action="store_true")
        parser.set_defaults(func=cmd_continuous)
    imports = sub.add_parser("import", help="Importar Nmap XML o scopescan.external.v1 JSON")
    imports.add_argument("kind", choices=("nmap", "external"))
    imports.add_argument("path")
    imports.add_argument("--name", default="")
    imports.add_argument("--namespace", default="")
    imports.add_argument("--authorized-by", default="")
    imports.set_defaults(func=cmd_continuous)
    verify = sub.add_parser("verify", help="Preview y ejecucion dirigida de controles afectados")
    verify.add_argument("finding_ids", nargs="+")
    verify.add_argument("--authorized-by", required=True)
    verify.add_argument("--run", action="store_true")
    verify.add_argument("-y", "--yes", action="store_true")
    verify.set_defaults(func=cmd_continuous)
    history = sub.add_parser("asset-history", help="Observaciones historicas de un activo")
    history.add_argument("asset_id")
    historical = sub.add_parser("historical-findings", help="Buscar hallazgos de todos los escaneos")
    historical.add_argument("--search", default="")
    historical.add_argument("--min-severity", type=int, choices=range(5), default=0)
    for parser in (history, historical):
        parser.add_argument("--limit", type=int, default=50)
        parser.add_argument("--offset", type=int, default=0)
        parser.set_defaults(func=cmd_continuous)
