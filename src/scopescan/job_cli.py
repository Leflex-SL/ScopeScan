"""Worker, queue control and UTC scheduling commands."""
import json
import sys

from . import db, durable_jobs, scheduler, worker


def command(args):
    db.init_db()
    try:
        if args.command == "worker":
            if args.job_id is not None and not args.once:
                raise ValueError("--job-id requires --once")
            if args.once:
                value = worker.run_once(job_id=args.job_id)
            else:
                worker.run_forever()
                return 0
        elif args.command == "jobs":
            if args.action == "list":
                value = durable_jobs.list_jobs(limit=args.limit, offset=args.offset)
            elif args.action == "show":
                value = durable_jobs.get(args.job_id)
            elif args.action == "cancel":
                value = {"cancelled": durable_jobs.cancel(args.job_id)}
            else:
                value = {"job_id": durable_jobs.retry(args.job_id, acknowledge_uncertain=args.acknowledge_uncertain)}
        elif args.action == "list":
            value = scheduler.list_schedules()
        elif args.action == "events":
            value = scheduler.events()
        elif args.action == "tick":
            value = {"jobs": scheduler.tick()}
        elif args.action in {"enable", "disable"}:
            scheduler.set_enabled(args.schedule_id, args.action == "enable")
            value = {"schedule_id": args.schedule_id, "enabled": args.action == "enable"}
        else:
            value = {"schedule_id": scheduler.create(name=args.name, scope_id=args.scope_id,
                interval_seconds=args.interval, starts_at=args.starts_at, ends_at=args.ends_at,
                window_start=args.window_start, window_end=args.window_end, max_running=args.max_running)}
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


def register_cli(sub):
    parser = sub.add_parser("worker", help="Execute persisted jobs in this worker process")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--job-id", type=int)
    parser.set_defaults(func=command)
    children = sub.add_parser("jobs", help="Inspect, cancel and retry persisted jobs").add_subparsers(dest="action", required=True)
    child = children.add_parser("list")
    child.add_argument("--limit", type=int, default=100)
    child.add_argument("--offset", type=int, default=0)
    child.set_defaults(func=command)
    for action in ("show", "cancel", "retry"):
        child = children.add_parser(action)
        child.add_argument("job_id", type=int)
        if action == "retry":
            child.add_argument("--acknowledge-uncertain", action="store_true", help="Reconciled external side effects before retry")
        child.set_defaults(func=command)
    children = sub.add_parser("schedule", help="Explicit saved-scope UTC schedules").add_subparsers(dest="action", required=True)
    for action in ("list", "tick", "events"):
        children.add_parser(action).set_defaults(func=command)
    for action in ("enable", "disable"):
        child = children.add_parser(action)
        child.add_argument("schedule_id", type=int)
        child.set_defaults(func=command)
    child = children.add_parser("create")
    child.add_argument("scope_id", type=int)
    child.add_argument("--name", default="Scheduled assessment")
    child.add_argument("--starts-at", required=True)
    child.add_argument("--ends-at")
    child.add_argument("--interval", type=int, default=86400)
    child.add_argument("--window-start", default="00:00")
    child.add_argument("--window-end", default="00:00")
    child.add_argument("--max-running", type=int, default=1)
    child.set_defaults(func=command)
