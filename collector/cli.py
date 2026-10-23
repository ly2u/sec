import argparse
import json
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


def main():
    parser = argparse.ArgumentParser(description="SecWatch bounded, resumable public-feed importer")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("idle", help="Phase 1 worker: wait, do not automatically ingest")
    commands.add_parser("status")
    for name in ("cve-baseline", "cve-delta", "kev", "epss"):
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
    args = parser.parse_args()
    if args.command == "idle":
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        print("Stage 1 worker ready; imports require an explicit command.", flush=True)
        while True:
            time.sleep(30)
    engine = engine_for()
    if args.command == "status":
        with Session(engine) as session:
            counts = {
                model.__tablename__: session.scalar(select(func.count()).select_from(model))
                for model in (Vulnerability, KEVEntry, EPSSScore, VulnerabilityEvent)
            }
            states = [
                {
                    "source": state.source,
                    "processed": state.records_processed,
                    "completed": state.completed,
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
        else:
            result = EPSSAdapter(http).run(engine, url=args.url, **kwargs)
        print(json.dumps(result), flush=True)
    finally:
        http.close()
        engine.dispose()


if __name__ == "__main__":
    main()
