"""Configure references, import evidence, export reports and enqueue connectors."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import db, defectdojo, integrations_service, integrations_store


def command(args):
    db.init_db()
    try:
        operation = args.integration_operation
        if operation == "add":
            value = {"destination_id": integrations_store.create_destination(args.name, args.kind, args.url, json.loads(args.options))}
        elif operation == "destinations":
            items, total = integrations_store.page("integration_destinations", limit=args.limit, offset=args.offset)
            value = {"items": items, "total": total}
        elif operation in {"imports", "deliveries"}:
            items, total = integrations_store.page("integration_" + operation, limit=args.limit, offset=args.offset)
            value = {"items": items, "total": total}
        elif operation in {"detail", "raw"}:
            value = integrations_store.get_import(args.import_id, include_raw=operation == "raw")
        elif operation == "delivery":
            value = integrations_store.get_delivery(args.delivery_id)
        elif operation == "history":
            items, total = integrations_store.delivery_history(args.delivery_id, limit=args.limit, offset=args.offset)
            value = {"items": items, "total": total}
        elif operation == "export":
            print(defectdojo.generic_findings(args.scan_id).decode())
            return 0
        elif operation == "import":
            with Path(args.path).open("rb") as stream:
                payload = stream.read(8_000_001)
            value = integrations_service.import_evidence(args.kind, payload, scope_id=args.scope_id)
        elif operation == "deliver":
            if not args.yes:
                raise ValueError("Review the export and destination; --yes authorizes enqueueing this remote import")
            value = integrations_service.enqueue_delivery(args.destination_id, args.scan_id, engagement_id=args.engagement_id, test_id=args.test_id)
        elif operation == "poll":
            value = integrations_service.enqueue_poll(args.delivery_id, remote_test_id=args.remote_test_id)
        else:
            value = integrations_service.enqueue_pull(args.destination_id, args.scope_id, report_id=args.report_id)
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


def register_cli(subparsers):
    parser = subparsers.add_parser("integration", help="Destinations, external reports and queued connector operations")
    children = parser.add_subparsers(dest="integration_operation", required=True)
    child = children.add_parser("add")
    child.add_argument("name")
    child.add_argument("kind", choices=("defectdojo", "faraday", "greenbone"))
    child.add_argument("url")
    child.add_argument("--options", required=True, help="JSON options with *_env references; never actual credentials")
    child.set_defaults(func=command)
    for action in ("destinations", "imports", "deliveries"):
        child = children.add_parser(action)
        child.add_argument("--limit", type=int, default=50)
        child.add_argument("--offset", type=int, default=0)
        child.set_defaults(func=command)
    for action in ("detail", "raw"):
        child = children.add_parser(action)
        child.add_argument("import_id", type=int)
        child.set_defaults(func=command)
    child = children.add_parser("delivery")
    child.add_argument("delivery_id", type=int)
    child.set_defaults(func=command)
    child = children.add_parser("history")
    child.add_argument("delivery_id", type=int)
    child.add_argument("--limit", type=int, default=50)
    child.add_argument("--offset", type=int, default=0)
    child.set_defaults(func=command)
    child = children.add_parser("export")
    child.add_argument("scan_id", type=int)
    child.set_defaults(func=command)
    child = children.add_parser("import")
    child.add_argument("kind", choices=("faraday", "greenbone"))
    child.add_argument("path")
    child.add_argument("--scope-id", type=int, required=True)
    child.set_defaults(func=command)
    child = children.add_parser("deliver")
    child.add_argument("destination_id", type=int)
    child.add_argument("scan_id", type=int)
    child.add_argument("--engagement-id", type=int)
    child.add_argument("--test-id", type=int)
    child.add_argument("--yes", action="store_true")
    child.set_defaults(func=command)
    child = children.add_parser("poll")
    child.add_argument("delivery_id", type=int)
    child.add_argument("--remote-test-id", type=int)
    child.set_defaults(func=command)
    child = children.add_parser("pull")
    child.add_argument("destination_id", type=int)
    child.add_argument("scope_id", type=int)
    child.add_argument("--report-id", default="")
    child.set_defaults(func=command)
