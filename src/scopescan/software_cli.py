"""Software evidence imports/exports and authorized durable operations."""
import json
import sys
from pathlib import Path

from . import db, software_service, software_store
from .sbom import MAX_BYTES


def command(args):
    db.init_db()
    try:
        if args.operation == "import":
            with Path(args.path).open("rb") as stream:
                payload = stream.read(MAX_BYTES + 1)
            value = {"document_id": software_service.import_evidence(args.kind, payload, namespace=args.namespace, resource_kind=args.resource_kind, resource_name=args.resource)}
        elif args.operation == "export":
            sys.stdout.buffer.write(software_service.export_document(args.document_id, args.format))
            return 0
        elif args.operation == "list":
            items, total = software_store.page("documents", search=args.search, limit=args.limit, offset=args.offset)
            value = {"items": items, "total": total}
        elif args.operation in {"components", "observations"}:
            items, total = software_store.page(args.operation, document_id=args.document_id, limit=args.limit, offset=args.offset)
            value = {"items": items, "total": total}
        elif args.operation == "detail":
            value = software_store.get(args.document_id)
        else:
            payload = {"namespace": args.namespace, "resource_kind": args.resource_kind, "resource_name": args.resource,
                       "source": args.source, "document_id": args.document_id, "allow_registry": args.allow_registry, "timeout": args.timeout}
            plan = software_service.preview("software." + args.engine, payload, authorized_by=args.authorized_by)
            if args.operation == "run":
                if not args.yes:
                    raise ValueError("Review software preview, then pass --yes to queue its authorized source")
                value = {"job_id": software_service.enqueue(plan["kind"], plan["payload"], authorized_by=args.authorized_by)}
            else:
                value = plan
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


def register_cli(sub):
    parser = sub.add_parser("software", help="SBOM, package candidates and SCAP evidence")
    children = parser.add_subparsers(dest="operation", required=True)
    child = children.add_parser("import")
    child.add_argument("kind", choices=("sbom", "scap", "grype"))
    child.add_argument("path")
    for action in ("list", "components", "observations"):
        child = children.add_parser(action)
        child.add_argument("--limit", type=int, default=50)
        child.add_argument("--offset", type=int, default=0)
        if action == "list":
            child.add_argument("--search", default="")
        else:
            child.add_argument("document_id", type=int)
    child = children.add_parser("detail")
    child.add_argument("document_id", type=int)
    child = children.add_parser("export")
    child.add_argument("document_id", type=int)
    child.add_argument("--format", choices=("cyclonedx", "spdx"), required=True)
    for action in ("preview", "run"):
        child = children.add_parser(action)
        child.add_argument("engine", choices=("syft", "grype"))
        child.add_argument("--source", default="")
        child.add_argument("--document-id", type=int)
        child.add_argument("--allow-registry", action="store_true")
        child.add_argument("--timeout", type=float, default=120)
        child.add_argument("--authorized-by", required=True)
        child.add_argument("--yes", action="store_true")
    for child in children.choices.values():
        if child.prog.rsplit(" ", 1)[-1] in {"import", "preview", "run"}:
            child.add_argument("--namespace", required=True)
            child.add_argument("--resource-kind", choices=("image", "directory", "file", "software", "host-compliance"), default="software")
            child.add_argument("--resource", required=True)
        child.set_defaults(func=command)
