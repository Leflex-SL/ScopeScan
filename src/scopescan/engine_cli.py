"""Engine planning/execution and bounded imports for the command line."""
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import db, engine_service, engine_store


def parse_ports(value: str) -> tuple[int, ...]:
    try:
        values = tuple(sorted({int(part.strip()) for part in value.split(",") if part.strip()}))
    except ValueError as exc:
        raise ValueError("Ports must be comma-separated integers") from exc
    if len(values)>100 or any(not 1<=port<=65535 for port in values):
        raise ValueError("Specify up to 100 ports between 1 and 65535")
    return values


def command(args):
    db.init_db()
    try:
        if args.operation == "list":
            value = engine_service.catalog()
        elif args.operation in {"preview","run"}:
            plan = engine_service.preview(args.engine,args.scope_id,ports=parse_ports(args.ports),timeout=args.timeout,service=args.service)
            if args.operation == "preview":
                value = {"plan":asdict(plan),"fingerprint":plan.fingerprint}
            else:
                if not args.yes:
                    raise ValueError("Review engine preview, then pass --yes to execute its authorized scope")
                from .jobs import QUEUE
                from .worker import execute_now
                scan_id = engine_service.create_execution(plan)
                execute_now(QUEUE.submit(scan_id))
                value = {"scan_id":scan_id}
        elif args.operation == "import":
            with Path(args.path).open("rb") as stream:
                payload=stream.read(8_000_001)
            value={"scan_id":engine_service.import_evidence(args.kind,payload,scope_id=args.scope_id,host=args.host,inventory_scan_id=args.inventory_scan_id)}
        elif args.operation == "results":
            items,total=engine_store.list_results(scan_id=args.scan_id,limit=args.limit,offset=args.offset)
            value={"items":items,"total":total}
        else:
            value=engine_store.get_result(args.result_id,include_raw=args.operation=="raw")
        print(json.dumps(value,ensure_ascii=False,indent=2))
        return 0
    except (ValueError,OSError) as exc:
        print(str(exc),file=sys.stderr)
        return 2


def register(sub):
    parser=sub.add_parser("engine",help="Plan/execution/import of optional engines")
    children=parser.add_subparsers(dest="operation",required=True)
    children.add_parser("list").set_defaults(func=command)
    for action in ("preview","run"):
        child=children.add_parser(action)
        child.add_argument("engine",choices=tuple(engine_service.ADAPTERS))
        child.add_argument("scope_id",type=int)
        child.add_argument("--ports",default="")
        child.add_argument("--service",choices=("http","https","tls"),default="")
        child.add_argument("--timeout",type=float,default=120)
        child.add_argument("--yes",action="store_true")
        child.set_defaults(func=command)
    child=children.add_parser("import")
    child.add_argument("kind",choices=("vuls","linux-advisories"))
    child.add_argument("path")
    child.add_argument("--scope-id",type=int,required=True)
    child.add_argument("--host",required=True)
    child.add_argument("--inventory-scan-id",type=int)
    child.set_defaults(func=command)
    child=children.add_parser("results")
    child.add_argument("--scan-id",type=int)
    child.add_argument("--limit",type=int,default=50)
    child.add_argument("--offset",type=int,default=0)
    child.set_defaults(func=command)
    for action in ("detail","raw"):
        child=children.add_parser(action)
        child.add_argument("result_id",type=int)
        child.set_defaults(func=command)
