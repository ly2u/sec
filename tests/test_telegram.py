from datetime import UTC, datetime

import httpx
from sqlalchemy.orm import Session

from apps.server.models import IngestionState, Vulnerability, VulnerabilityEvent
from collector.telegram import broadcast


def add_event(session, key, priority="P0", baseline=False, vid="CVE-2024-4577"):
    if session.get(Vulnerability, vid) is None:
        session.add(Vulnerability(id=vid, status="PUBLISHED", title="PHP-CGI argument injection"))
        session.flush()
    session.add(
        VulnerabilityEvent(
            vulnerability_id=vid,
            event_type="added_to_kev",
            dedup_key=key,
            source="kev",
            happened_at=datetime.now(UTC),
            priority=priority,
            is_baseline=baseline,
            payload={},
        )
    )


def client(sent, status=200):
    def handler(request):
        sent.append(request)
        return httpx.Response(status, json={"ok": status == 200})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_not_configured_does_nothing(db):
    assert broadcast(db, token="", chat="")["skipped"] == "not-configured"


def test_scheduler_records_unconfigured_and_first_runs_as_success(db, monkeypatch):
    """The scheduler fails any task whose feed is not completed (deployment found
    this): an unconfigured or freshly initialised channel is a normal run."""
    from datetime import timedelta

    from sqlalchemy import select

    from apps.server.models import ScheduledTask, TaskRun
    from collector.scheduler import initialize, perform, tick

    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    now = datetime.now(UTC)
    initialize(db, now)
    with Session(db) as session, session.begin():
        for task in session.scalars(select(ScheduledTask)):
            task.next_run_at = now + timedelta(days=1)
        session.get(ScheduledTask, "telegram").next_run_at = now
    assert tick(db, now, perform)
    with Session(db) as session:
        runs = list(session.scalars(select(TaskRun)))
    assert [(r.task, r.status) for r in runs] == [("telegram", "success")]


def test_first_run_never_floods_then_sends_only_new_public_p0_p1(db):
    with Session(db) as session, session.begin():
        add_event(session, "old")
    sent = []
    first = broadcast(db, token="T0KEN", chat="@chan", client=client(sent))
    assert first["processed"] == 0 and not sent
    with Session(db) as session, session.begin():
        add_event(session, "new-p0")
        add_event(session, "new-p2", priority="P2")
        add_event(session, "bootstrap", baseline=True)
    result = broadcast(db, token="T0KEN", chat="@chan", client=client(sent))
    assert result == {"processed": 1, "pending": 0, "completed": True}
    body = sent[0].read().decode()
    assert "CVE-2024-4577" in body and "https://sec.ly2u.com/cve/CVE-2024-4577" in body
    assert sent[0].url.host == "api.telegram.org"
    # Nothing new: nothing sent.
    assert broadcast(db, token="T0KEN", chat="@chan", client=client(sent))["processed"] == 0
    assert len(sent) == 1


def test_failure_keeps_the_event_for_the_next_run(db):
    with Session(db) as session, session.begin():
        session.add(IngestionState(source="telegram", cursor={"last_event_id": 0}))
        add_event(session, "e1")
    sent = []
    failed = broadcast(db, token="T", chat="c", client=client(sent, status=500))
    assert failed["pending"] == 1 and failed["completed"] is False
    assert broadcast(db, token="T", chat="c", client=client(sent))["processed"] == 1
