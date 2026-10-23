import copy
import gzip
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from apps.server.db import Base
from apps.server.models import IngestionState, KEVEntry, Vulnerability, VulnerabilityEvent
from collector.adapters.cvelist import DELTA_LOG, CVEAdapter, normalize
from collector.adapters.epss import EPSSAdapter
from collector.adapters.kev import KEVAdapter
from collector.http import FeedHTTP
from collector.ingestion import ingest
from collector.store import event, kev_vulnerabilities, telegram_events, visible_events

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]


def mock_http(handler):
    return FeedHTTP(httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)


def kev_feed(count, revision="test-1", start=10000):
    fixture = json.loads((FIXTURES / "kev.json").read_text())
    prototype = fixture["vulnerabilities"][0]
    return {
        **fixture,
        "catalogVersion": revision,
        "count": count,
        "vulnerabilities": [{**prototype, "cveID": f"CVE-2020-{start + i}"} for i in range(count)],
    }


def event_counts(db):
    with Session(db) as session:
        total = session.scalar(select(func.count()).select_from(VulnerabilityEvent))
        live = len(list(session.scalars(visible_events())))
        return total - live, live


def test_first_full_kev_is_baseline_then_only_new_entry_is_live(db):
    feed = kev_feed(2)
    adapter = KEVAdapter(mock_http(lambda _: httpx.Response(200, json=feed)))
    assert adapter.run(db, limit=None)["completed"]
    assert event_counts(db) == (2, 0)
    feed = kev_feed(3, revision="test-2")
    assert adapter.run(db, limit=None)["completed"]
    assert event_counts(db) == (2, 1)
    with Session(db) as session:
        assert len(list(session.scalars(telegram_events()))) == 1
        state = session.get(IngestionState, "kev")
        assert state.has_completed and not state.cursor["is_baseline"]


def test_kev_revision_change_restarts_incomplete_first_snapshot(db, caplog):
    feed = kev_feed(3)
    adapter = KEVAdapter(mock_http(lambda _: httpx.Response(200, json=feed)))
    assert not adapter.run(db, limit=1)["completed"]
    feed = kev_feed(4, revision="test-2")
    with caplog.at_level(logging.WARNING):
        result = adapter.run(db, limit=None)
    assert result["completed"] and result["offset"] == 4
    assert "automatically restarting" in caplog.text
    assert event_counts(db) == (4, 0)


def test_ever_completed_survives_interruption_and_revision_restart(db):
    feed = kev_feed(1)
    adapter = KEVAdapter(mock_http(lambda _: httpx.Response(200, json=feed)))
    adapter.run(db, limit=None)
    feed = kev_feed(3, revision="test-2")
    adapter.run(db, limit=1)
    with Session(db) as session:
        state = session.get(IngestionState, "kev")
        assert state.has_completed and not state.completed
    feed = kev_feed(4, revision="test-3")
    adapter.run(db, limit=None)
    assert event_counts(db) == (1, 3)


def test_epss_revision_change_restarts_incomplete_snapshot(db, caplog):
    csv = (FIXTURES / "epss.csv").read_bytes()
    url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    adapter = EPSSAdapter(mock_http(lambda _: httpx.Response(200, content=gzip.compress(csv))))
    assert not adapter.run(db, url=url, limit=1)["completed"]
    csv = csv.replace(b"2026-10-22", b"2026-10-23")
    with caplog.at_level(logging.WARNING):
        assert adapter.run(db, url=url, limit=None)["completed"]
    assert "automatically restarting" in caplog.text
    with Session(db) as session:
        state = session.get(IngestionState, "epss")
        assert state.records_processed == 2 and "2026-10-23" in state.source_revision


def test_pinned_cve_revision_change_still_requires_explicit_restart(db):
    def apply(session, records):
        pass

    args = (db, "cve:baseline", "pinned-v1", lambda: iter([1, 2]), apply)
    ingest(*args, limit=1)
    with pytest.raises(ValueError, match="Incomplete snapshot changed"):
        ingest(db, "cve:baseline", "pinned-v2", lambda: iter([1, 2]), apply, limit=None)


def test_delta_errors_are_warned_and_persisted_while_valid_records_import(db, published, caplog):
    error_entry = {
        "fetchTime": "2026-10-23T01:00:00Z",
        "new": [{"cveId": "CVE-2024-3094"}],
        "updated": [],
        "error": [{"cveId": "CVE-2024-3999", "message": "upstream failed"}],
    }
    log = [
        error_entry,
        {"fetchTime": "2026-10-23T00:00:00Z", "new": [], "updated": [], "error": []},
    ]
    adapter = CVEAdapter(
        mock_http(
            lambda request: httpx.Response(
                200, json=log if str(request.url) == DELTA_LOG else published
            )
        )
    )
    with caplog.at_level(logging.WARNING):
        result = adapter.delta(db, since="2026-10-23T00:00:00Z", limit=None)
    assert result["completed"] and result["processed"] == 1
    assert "processing its remaining records" in caplog.text
    with Session(db) as session:
        assert session.get(Vulnerability, "CVE-2024-3094")
        assert session.get(IngestionState, "cve:delta").cursor["warnings"] == [error_entry]


@pytest.mark.parametrize(
    "versions, expected",
    [
        ([("cna", "3.1"), ("cisa-adp", "3.1"), ("cna", "4.0")], ("cna", "3.1")),
        ([("cisa-adp", "3.1"), ("cna", "4.0")], ("cisa-adp", "3.1")),
        ([("cna", "4.0"), ("cisa-adp", "4.0"), ("cna", "3.0")], ("cna", "4.0")),
        ([("cisa-adp", "4.0"), ("cna", "3.0")], ("cisa-adp", "4.0")),
        ([("cisa-adp", "3.0"), ("cna", "2.0")], ("cisa-adp", "3.0")),
        ([("cna", "2.0")], ("cna", "2.0")),
    ],
)
def test_cvss_primary_order_vectors_and_all_assessments(published, versions, expected):
    record = copy.deepcopy(published)
    cna = record["containers"]["cna"]
    cisa = record["containers"]["adp"][0]
    cna["metrics"], cisa["metrics"] = [], []
    keys = {"3.1": "cvssV3_1", "4.0": "cvssV4_0", "3.0": "cvssV3_0", "2.0": "cvssV2_0"}
    for source, version in versions:
        (cna if source == "cna" else cisa)["metrics"].append(
            {
                keys[version]: {
                    "baseScore": 9.8,
                    "baseSeverity": "LOW",
                    "vectorString": f"CVSS:{version}/TEST",
                }
            }
        )
    normalized = normalize(record)
    assert (normalized["cvss_source"], normalized["cvss_version"]) == expected
    assert normalized["cvss_vector"] == f"CVSS:{expected[1]}/TEST"
    assert normalized["severity"] == ("HIGH" if expected[1] == "2.0" else "CRITICAL")
    assert len(normalized["cvss_metrics"]) == len(versions)
    assert all(item["metrics"]["baseScore"] == 9.8 for item in normalized["cvss_metrics"])


def test_adp_kev_flag_is_not_catalog_membership(db, published):
    from collector.adapters.cvelist import apply_records

    record = copy.deepcopy(published)
    record["containers"]["adp"][0].setdefault("metrics", []).append({"other": {"type": "kev"}})
    with Session(db) as session, session.begin():
        apply_records(session, [record])
    with Session(db) as session:
        assert session.get(Vulnerability, "CVE-2024-3094").adp_kev_flag
        assert list(session.scalars(kev_vulnerabilities())) == []


def test_kev_removal_only_after_complete_snapshot_retains_history_and_is_p2(db):
    feed = kev_feed(2)
    adapter = KEVAdapter(mock_http(lambda _: httpx.Response(200, json=feed)))
    adapter.run(db, limit=None)
    feed = kev_feed(2, revision="test-2", start=10001)
    adapter.run(db, limit=1)
    with Session(db) as session:
        assert session.get(KEVEntry, "CVE-2020-10000").is_active
    adapter.run(db, limit=None)
    with Session(db) as session:
        removed = session.get(KEVEntry, "CVE-2020-10000")
        assert removed is not None and not removed.is_active and removed.removed_at
        assert {row.id for row in session.scalars(kev_vulnerabilities())} == {
            "CVE-2020-10001",
            "CVE-2020-10002",
        }
        removals = list(
            session.scalars(
                select(VulnerabilityEvent).where(
                    VulnerabilityEvent.event_type == "removed_from_kev"
                )
            )
        )
        assert len(removals) == 1 and removals[0].priority == "P2" and not removals[0].is_baseline
        assert all(
            row.event_type != "removed_from_kev" for row in session.scalars(telegram_events())
        )
    adapter.run(db, limit=None, restart=True)
    assert event_counts(db) == (2, 2)


def test_migration_0002_preserves_data_and_backfills_baseline(db, monkeypatch):
    Base.metadata.drop_all(db)
    monkeypatch.setenv("DATABASE_URL", db.url.render_as_string(hide_password=False))
    config = Config(str(ROOT / "alembic.ini"))
    command.upgrade(config, "0001")
    with db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO vulnerabilities (id,status,title,description,cwes,cisa_kev) VALUES ('CVE-2020-10000','PUBLISHED','','','[]',TRUE)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO vulnerability_events (vulnerability_id,event_type,dedup_key,source,happened_at,priority,payload) VALUES ('CVE-2020-10000','added_to_kev','test','kev',CURRENT_TIMESTAMP,'P0','{}')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO ingestion_state (source,cursor,records_processed,completed) VALUES ('kev','{}',1,FALSE),('epss','{}',1,TRUE)"
            )
        )
    command.upgrade(config, "0002")
    command.check(config)
    with Session(db) as session:
        assert session.get(Vulnerability, "CVE-2020-10000").adp_kev_flag
        assert session.scalar(select(VulnerabilityEvent)).is_baseline
        assert not session.get(IngestionState, "kev").has_completed
        assert session.get(IngestionState, "epss").has_completed


def test_transaction_context_marks_all_event_types_and_public_scope(db):
    def apply(session, records):
        for cve_id in records:
            session.add(Vulnerability(id=cve_id, status="PUBLISHED"))
            session.flush()
            event(session, cve_id, "test", cve_id, "test", datetime.now(UTC), {}, "P0")

    ingest(db, "test", "v1", lambda: iter(["CVE-2020-10000"]), apply, limit=None)
    assert event_counts(db) == (1, 0)
    ingest(db, "test", "v2", lambda: iter(["CVE-2020-10001"]), apply, limit=None)
    assert event_counts(db) == (1, 1)
