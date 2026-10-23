"""Single PostgreSQL leader, staggered durable jobs and bounded task retries."""

import logging
import signal
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from apps.server.models import ScheduledTask, TaskRun
from collector.adapters.cvelist import CVEAdapter
from collector.adapters.epss import EPSSAdapter
from collector.adapters.kev import KEVAdapter
from collector.adapters.nodejs import NodejsAdapter
from collector.adapters.osv import OSVAdapter
from collector.bundles import generate
from collector.distros import BASES, RELEASES
from collector.http import FeedHTTP
from collector.store import upsert
from collector.telegram import broadcast

logger = logging.getLogger(__name__)
LOCK_ID = 0x5345435741544348
TASKS = {
    "kev": 3600,
    "cve:delta": 3600,
    "osv": 3600,
    "epss": 86400,
    "nodejs": 21600,
    "telegram": 300,
}


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@contextmanager
def leader(engine):
    if engine.dialect.name != "postgresql":
        raise RuntimeError("Worker requires PostgreSQL advisory locks")
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        locked = connection.scalar(text("SELECT pg_try_advisory_lock(:id)"), {"id": LOCK_ID})
        try:
            yield connection if locked else None
        finally:
            if locked and not connection.invalidated:
                connection.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": LOCK_ID})


def initialize(engine, now):
    first = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
    with Session(engine) as session, session.begin():
        for offset, task in enumerate(TASKS):
            upsert(
                session,
                ScheduledTask,
                [{"name": task, "next_run_at": first + timedelta(minutes=offset * 2)}],
                ["name"],
                do_nothing=True,
            )
        # A lost process cannot retain a leader lock; incomplete runs are explicit recovery evidence.
        for run in session.scalars(select(TaskRun).where(TaskRun.status == "running")):
            run.status = "interrupted"
            run.finished_at = now
            run.error = "WorkerInterrupted"
            task = session.get(ScheduledTask, run.task)
            task.next_run_at = first + timedelta(minutes=list(TASKS).index(run.task) * 2)


def perform(engine, task):
    if task == "telegram":
        return {"feed": broadcast(engine)}
    http = FeedHTTP()
    try:
        if task == "kev":
            result = KEVAdapter(http).run(engine, limit=None)
        elif task == "epss":
            result = EPSSAdapter(http).run(engine, limit=None)
        elif task == "cve:delta":
            result = CVEAdapter(http).delta(engine, limit=None)
        elif task == "nodejs":
            result = NodejsAdapter(http).run(engine)
        else:
            result = {base: OSVAdapter(http).delta(engine, base, limit=None) for base in BASES}
        changed = (
            any(row.get("processed", 0) > 0 for row in result.values())
            if task == "osv"
            else result.get("processed", 0) > 0
        )
        bundles = (
            generate(engine)
            if changed
            else {
                "rebuilt": [],
                "bundles": sum(len(releases) for releases in RELEASES.values()) + 1,
                "skipped": "feed-unchanged",
            }
        )
        return {"feed": result, "bundles": bundles, "http_retries": http.retry_count}
    finally:
        http.close()


def tick(engine, now, perform_task=perform):
    """At most one start per UTC minute, including failures and retry attempts."""
    with Session(engine) as session, session.begin():
        last = session.scalar(select(TaskRun).order_by(TaskRun.id.desc()).limit(1))
        if last and utc(last.started_at).replace(second=0, microsecond=0) >= now.replace(
            second=0, microsecond=0
        ):
            return None
        task = session.scalar(
            select(ScheduledTask)
            .where(ScheduledTask.next_run_at <= now)
            .order_by(ScheduledTask.next_run_at, ScheduledTask.name)
            .limit(1)
        )
        if not task:
            return None
        previous = session.scalar(
            select(TaskRun).where(TaskRun.task == task.name).order_by(TaskRun.id.desc()).limit(1)
        )
        attempt = (
            previous.attempt + 1
            if previous and previous.status in ("failed", "interrupted") and previous.attempt < 3
            else 1
        )
        run = TaskRun(task=task.name, started_at=now, attempt=attempt, status="running", result={})
        session.add(run)
        session.flush()
        run_id = run.id
        name = task.name
        # Persist the next regular slot before executing; crash recovery is handled by initialize.
        task.next_run_at = now + timedelta(seconds=TASKS[name])
    clock = time.monotonic()
    logger.info("task=%s run=%s attempt=%s started", name, run_id, attempt)
    try:
        result = perform_task(engine, name)
        if name == "osv":
            if any(not row.get("completed", False) for row in result.get("feed", {}).values()):
                raise RuntimeError("OSVIncomplete")
        elif not result.get("feed", {}).get("completed", False):
            raise RuntimeError("FeedIncomplete")
        status, error = "success", None
    except Exception as failure:
        logger.exception("task=%s run=%s failed", name, run_id)
        result = {}
        status, error = "failed", type(failure).__name__
    elapsed = time.monotonic() - clock
    finished = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        run = session.get(TaskRun, run_id)
        run.status = status
        run.error = error
        run.result = result
        run.finished_at = finished
        run.elapsed_seconds = elapsed
        task = session.get(ScheduledTask, name)
        task.last_finished_at = finished
        if status == "failed" and attempt < 3:
            task.next_run_at = finished + timedelta(seconds=60 * 2 ** (attempt - 1))
    logger.info(
        "task=%s run=%s status=%s elapsed=%.3f attempts=%s", name, run_id, status, elapsed, attempt
    )
    return run_id


def run(engine):
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    with leader(engine) as connection:
        if connection is None:
            logger.warning("Another SecWatch worker owns the advisory lock; exiting")
            return
        initialize(engine, datetime.now(UTC))
        logger.info("Scheduler leader ready; hourly KEV/CVE/OSV and daily EPSS; starts staggered")
        while not stop.is_set():
            connection.execute(
                text("SELECT 1")
            )  # Lost lock/session means fail closed, not a second leader.
            tick(engine, datetime.now(UTC))
            stop.wait(5)
