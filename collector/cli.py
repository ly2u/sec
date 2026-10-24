import argparse
import json
import logging
import shutil
import signal
import sys
import time

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.server.db import engine_for
from apps.server.models import (
    EPSSScore,
    IngestionState,
    KEVEntry,
    Vulnerability,
    VulnerabilityEvent,
)
from collector.adapters.cvelist import CVEAdapter
from collector.adapters.epss import EPSSAdapter
from collector.adapters.kev import KEVAdapter
from collector.http import FeedHTTP
from collector.store import kev_vulnerabilities, visible_events


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(description="SecWatch bounded, resumable public-feed importer")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("idle", help="Phase 1 worker: wait, do not automatically ingest")
    commands.add_parser("status")
    commands.add_parser("worker", help="Run the PostgreSQL-locked persistent scheduler")
    commands.add_parser("bundles", help="Publish changed signed distro bundles")
    commands.add_parser("nodejs", help="Import the Node.js security-wg core database")
    commands.add_parser("golang", help="Import the Go vulnerability database (OSV export)")
    commands.add_parser("release", help="Record the latest scanner release for update notices")
    commands.add_parser(
        "upstream-backfill", help="Derive L2 product ranges from all stored CVE records once"
    )
    commands.add_parser(
        "upstream-coverage", help="Report per-product conversion coverage (read-only)"
    )
    explain = commands.add_parser(
        "upstream-explain", help="Show one CVE's affected[] and its L2 ranges (read-only)"
    )
    explain.add_argument("cve_id")
    for name in ("cve-baseline", "cve-delta", "kev", "epss", "osv-baseline", "osv-delta"):
        command = commands.add_parser(name)
        size = command.add_mutually_exclusive_group()
        size.add_argument("--limit", type=int, default=1000)
        size.add_argument("--all", action="store_true", help="Explicitly permit a full import")
        command.add_argument(
            "--restart", action="store_true", help="Replay the snapshot from record zero"
        )
        if name in ("cve-baseline", "epss"):
            command.add_argument("--url", help="Override an approved official source URL")
        if name == "cve-delta":
            command.add_argument("--since", help="Explicit initial delta watermark (ISO UTC)")
        if name.startswith("osv-"):
            from collector.distros import BASES

            command.add_argument("--ecosystem", required=True, choices=list(BASES))
    args = parser.parse_args()
    if args.command == "idle":
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        print("Stage 1 worker ready; imports require an explicit command.", flush=True)
        while True:
            time.sleep(30)
    engine = engine_for()
    if args.command == "worker":
        from collector.scheduler import run

        run(engine)
        return
    if args.command == "bundles":
        from collector.bundles import generate

        print(json.dumps(generate(engine)))
        return
    if args.command == "nodejs":
        from collector.adapters.nodejs import NodejsAdapter

        http = FeedHTTP()
        try:
            print(json.dumps(NodejsAdapter(http).run(engine)))
        finally:
            http.close()
        return
    if args.command == "release":
        from collector.release import check

        http = FeedHTTP()
        try:
            print(json.dumps(check(http, engine)))
        finally:
            http.close()
        return
    if args.command == "golang":
        from collector.adapters.golang import GoAdapter

        http = FeedHTTP()
        try:
            print(json.dumps(GoAdapter(http).run(engine)))
        finally:
            http.close()
        return
    if args.command == "upstream-backfill":
        from collector.upstream import backfill

        print(json.dumps(backfill(engine)))
        return
    if args.command == "upstream-coverage":
        from collector.upstream import coverage

        print(json.dumps(coverage(engine), ensure_ascii=False, indent=1))
        return
    if args.command == "upstream-explain":
        from collector.upstream import explain

        print(json.dumps(explain(engine, args.cve_id), ensure_ascii=False, indent=1))
        return
    if args.command == "status":
        with Session(engine) as session:
            counts = {
                model.__tablename__: session.scalar(select(func.count()).select_from(model))
                for model in (Vulnerability, KEVEntry, EPSSScore, VulnerabilityEvent)
            }
            counts["kev_active"] = session.scalar(
                kev_vulnerabilities().with_only_columns(func.count())
            )
            counts["baseline_events"] = session.scalar(
                select(func.count())
                .select_from(VulnerabilityEvent)
                .where(VulnerabilityEvent.is_baseline.is_(True))
            )
            counts["non_baseline_events"] = session.scalar(
                visible_events().with_only_columns(func.count())
            )
            states = [
                {
                    "source": state.source,
                    "processed": state.records_processed,
                    "completed": state.completed,
                    "has_completed": state.has_completed,
                    "last_error": state.last_error,
                }
                for state in session.scalars(select(IngestionState))
            ]
            print(json.dumps({"counts": counts, "ingestion": states}))
        return
    if args.limit < 1:
        parser.error("--limit must be positive")
    if shutil.disk_usage(".").free < 1024**3:
        parser.error("Less than 1 GiB of available disk; import not started")
    http = FeedHTTP()
    kwargs = {"limit": None if args.all else args.limit, "restart": args.restart}
    try:
        if args.command == "cve-baseline":
            result = CVEAdapter(http).baseline(engine, url=args.url, **kwargs)
        elif args.command == "cve-delta":
            result = CVEAdapter(http).delta(engine, since=args.since, **kwargs)
        elif args.command == "kev":
            result = KEVAdapter(http).run(engine, **kwargs)
        elif args.command.startswith("osv-"):
            from collector.adapters.osv import OSVAdapter

            adapter = OSVAdapter(http)
            if args.command == "osv-baseline":
                result = adapter.baseline(engine, args.ecosystem, **kwargs)
            else:
                result = adapter.delta(engine, args.ecosystem, limit=kwargs["limit"])
        else:
            result = EPSSAdapter(http).run(engine, url=args.url, **kwargs)
        print(json.dumps(result), flush=True)
    finally:
        http.close()
        engine.dispose()


if __name__ == "__main__":
    main()
