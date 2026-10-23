import copy
import gzip
import io
import json
import zipfile
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.server.models import (
    EPSSScore,
    IngestionState,
    KEVEntry,
    Vulnerability,
    VulnerabilityEvent,
)
from collector.adapters.cvelist import CVEAdapter, apply_records, normalize, record_url, zip_records
from collector.adapters.epss import DOCUMENTATION, EPSSAdapter, apply_scores, parse_csv
from collector.adapters.kev import KEVAdapter
from collector.http import FeedHTTP
from collector.ingestion import ingest
from collector.store import visible_vulnerabilities

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = "https://github.com/CVEProject/cvelistV5/releases/download/test/sample.zip"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def client_for(handler):
    return FeedHTTP(httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)


def archive(records, nested=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zipfile_:
        for row in records:
            zipfile_.writestr("cves/" + row["cveMetadata"]["cveId"] + ".json", json.dumps(row))
    if not nested:
        return buf.getvalue()
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as zipfile_:
        zipfile_.writestr("all_cves.zip", buf.getvalue())
    return outer.getvalue()


def count(db, model):
    with Session(db) as session:
        return session.scalar(select(func.count()).select_from(model))


@pytest.mark.parametrize("nested", [False, True])
def test_baseline_idempotence_rejected_and_reserved(db, published, nested):
    rejected = json.loads((FIXTURES / "CVE-2023-5129.json").read_text())
    reserved = {"cveMetadata": {"cveId": "CVE-2026-99999", "state": "RESERVED"}}
    content = archive([published, rejected, reserved], nested=nested)
    http = client_for(lambda _: httpx.Response(200, content=content))
    adapter = CVEAdapter(http)
    assert adapter.baseline(db, url=BASELINE, limit=1000)["processed"] == 3
    assert adapter.baseline(db, url=BASELINE, limit=1000)["processed"] == 0
    assert adapter.baseline(db, url=BASELINE, limit=1000, restart=True)["processed"] == 3
    assert count(db, Vulnerability) == 3
    with Session(db) as session:
        assert session.get(Vulnerability, "CVE-2023-5129").status == "REJECTED"
        assert session.get(Vulnerability, "CVE-2023-5129").description
        assert [row.id for row in session.scalars(visible_vulnerabilities())] == ["CVE-2024-3094"]


def test_cisa_adp_and_stale_record(published, db):
    actual = normalize(published)
    assert actual["ssvc"]["role"] == "CISA Coordinator"
    assert actual["cvss"] == 10
    variant = copy.deepcopy(published)
    cisa = variant["containers"]["adp"][0]
    cisa["metrics"] += [
        {"cvssV3_1": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}},
        {"other": {"type": "kev", "content": {}}},
    ]
    cisa["problemTypes"] = [
        {"descriptions": [{"cweId": "CWE-506", "description": "Embedded malicious code"}]}
    ]
    newer = normalize(variant)
    assert newer["cvss"] == 9.1 and newer["cisa_kev"] and "CWE-506" in newer["cwes"]
    with Session(db) as session, session.begin():
        apply_records(session, [variant])
    older = copy.deepcopy(published)
    older["cveMetadata"]["dateUpdated"] = "2020-01-01T00:00:00Z"
    with Session(db) as session, session.begin():
        apply_records(session, [older])
    with Session(db) as session:
        assert session.get(Vulnerability, "CVE-2024-3094").cvss == 9.1


def test_committed_cursor_retries_interrupted_stream(db, published):
    records = []
    for n in range(5):
        item = copy.deepcopy(published)
        item["cveMetadata"]["cveId"] = f"CVE-2026-{10000 + n}"
        records.append(item)
    attempts = 0

    def factory():
        nonlocal attempts
        attempts += 1
        for index, item in enumerate(records):
            if attempts == 1 and index == 3:
                raise httpx.ReadError("simulated disconnection")
            yield item

    result = ingest(db, "test:interrupt", "v1", factory, apply_records, limit=1000, batch_size=2)
    assert attempts == 2 and result["processed"] == 5 and result["completed"]
    assert count(db, Vulnerability) == 5
    with Session(db) as session:
        state = session.get(IngestionState, "test:interrupt")
        assert state.cursor["offset"] == 5 and state.last_error is None


def test_limit_and_resume_keep_data_cursor_atomic(db, published):
    records = []
    for n in range(5):
        item = copy.deepcopy(published)
        item["cveMetadata"]["cveId"] = f"CVE-2026-{20000 + n}"
        records.append(item)
    args = (db, "test:limit", "v1", lambda: iter(records), apply_records)
    assert ingest(*args, limit=2)["completed"] is False
    assert count(db, Vulnerability) == 2
    assert ingest(*args, limit=2)["offset"] == 4
    assert ingest(*args, limit=2)["completed"] is True
    assert count(db, Vulnerability) == 5
    with pytest.raises(ValueError, match="positive"):
        ingest(*args, limit=0)


def test_bad_record_rolls_back_batch_and_can_resume(db, published):
    bad = {"cveMetadata": {"cveId": "not-a-cve", "state": "PUBLISHED"}}
    with pytest.raises(ValueError):
        ingest(db, "test:atomic", "v1", lambda: iter([published, bad]), apply_records, limit=1000)
    assert count(db, Vulnerability) == 0
    with Session(db) as session:
        assert session.get(IngestionState, "test:atomic").cursor["offset"] == 0
    assert ingest(db, "test:atomic", "v1", lambda: iter([published]), apply_records)["completed"]


def test_old_cve_new_kev_generates_one_event(db):
    feed = json.loads((FIXTURES / "kev.json").read_text())
    adapter = KEVAdapter(client_for(lambda _: httpx.Response(200, json=feed)))
    with Session(db) as session, session.begin():
        session.add(
            Vulnerability(
                id="CVE-2021-44228",
                status="PUBLISHED",
                published_at=datetime(2021, 12, 10, tzinfo=UTC),
            )
        )
    assert adapter.run(db)["processed"] == 1
    assert adapter.run(db, restart=True)["processed"] == 1
    assert count(db, KEVEntry) == 1 and count(db, VulnerabilityEvent) == 1
    with Session(db) as session:
        row = session.scalar(select(VulnerabilityEvent))
        assert row.event_type == "added_to_kev" and row.priority == "P0"
        assert row.payload["date_added"] == feed["vulnerabilities"][0]["dateAdded"]


def test_kev_count_mismatch_fails_without_data(db):
    feed = json.loads((FIXTURES / "kev.json").read_text())
    feed["count"] += 1
    with pytest.raises(ValueError, match="count mismatch"):
        KEVAdapter(client_for(lambda _: httpx.Response(200, json=feed))).run(db)
    assert count(db, KEVEntry) == 0


def test_epss_discovery_daily_upsert_and_stubs(db):
    csv = (FIXTURES / "epss.csv").read_bytes()

    def handler(request):
        if str(request.url) == DOCUMENTATION:
            return httpx.Response(200, text=f'<a href="{EPSS_URL}">Daily CSV</a>')
        return httpx.Response(200, content=gzip.compress(csv))

    adapter = EPSSAdapter(client_for(handler))
    assert adapter.run(db)["processed"] == 2
    adapter.run(db, restart=True)
    assert count(db, EPSSScore) == 2
    with Session(db) as session:
        assert session.get(Vulnerability, "CVE-1999-0001").status == "UNKNOWN"
        assert list(session.scalars(visible_vulnerabilities())) == []
        row = session.get(EPSSScore, "CVE-1999-0001")
        assert float(row.epss) == 0.04753 and row.score_date == date(2026, 10, 22)


@pytest.mark.parametrize("score", ["NaN", "-0.1", "1.1", "Infinity"])
def test_epss_invalid_probabilities(score):
    text = (
        f"#model_version:v1,score_date:2026-10-22\ncve,epss,percentile\nCVE-1999-0001,{score},0.5\n"
    )
    with pytest.raises(ValueError):
        list(parse_csv(iter(text.splitlines())))


def test_delta_idempotence_and_watermark(db, published):
    from collector.adapters.cvelist import DELTA_LOG

    log = [
        {
            "fetchTime": "2026-10-23T01:00:00Z",
            "new": [{"cveId": "CVE-2024-3094"}],
            "updated": [],
            "error": [],
        },
        {"fetchTime": "2026-10-23T00:00:00Z", "new": [], "updated": [], "error": []},
    ]

    def handler(request):
        return httpx.Response(200, json=log if str(request.url) == DELTA_LOG else published)

    adapter = CVEAdapter(client_for(handler))
    assert adapter.delta(db, since="2026-10-23T00:00:00Z")["processed"] == 1
    assert adapter.delta(db)["processed"] == 0
    assert count(db, Vulnerability) == 1
    log[:] = [{"fetchTime": "2026-11-30T00:00:00Z", "new": [], "updated": [], "error": []}]
    with pytest.raises(ValueError, match="expired"):
        adapter.delta(db)


def test_unsafe_cve_id_and_nested_archive_limit():
    with pytest.raises(ValueError):
        record_url("../../etc/passwd")
    with pytest.raises(ValueError, match="nested ZIP"):
        list(zip_records(iter([]), depth=3))


def test_severity_score_change_is_deduplicated(db, published):
    changed = copy.deepcopy(published)
    changed["containers"]["cna"]["metrics"] = [
        {"cvssV3_1": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}
    ]
    with Session(db) as session, session.begin():
        apply_records(session, [published, changed, changed])
    with Session(db) as session:
        events = list(session.scalars(select(VulnerabilityEvent)))
        assert len(events) == 1
        assert events[0].event_type == "severity_changed"
        assert events[0].payload["before"]["cvss"] == 10
        assert events[0].payload["after"]["cvss"] == 9.1


def test_older_epss_snapshot_does_not_overwrite_latest(db):
    latest = list(parse_csv(iter((FIXTURES / "epss.csv").read_text().splitlines())))
    older = [{**row, "score_date": date(2026, 10, 21), "epss": 0} for row in latest]
    with Session(db) as session, session.begin():
        apply_scores(session, latest)
        apply_scores(session, older)
    with Session(db) as session:
        assert float(session.get(EPSSScore, "CVE-1999-0001").epss) == 0.04753


def test_delta_partial_snapshot_resumes_original_manifest(db, published):
    from collector.adapters.cvelist import DELTA_LOG

    log = [
        {
            "fetchTime": "2026-10-23T01:00:00Z",
            "new": [{"cveId": "CVE-2024-3094"}, {"cveId": "CVE-2024-3095"}],
            "updated": [],
            "error": [],
        },
        {"fetchTime": "2026-10-23T00:00:00Z", "new": [], "updated": [], "error": []},
    ]

    def handler(request):
        if str(request.url) == DELTA_LOG:
            return httpx.Response(200, json=log)
        row = copy.deepcopy(published)
        row["cveMetadata"]["cveId"] = request.url.path.rsplit("/", 1)[-1][:-5]
        return httpx.Response(200, json=row)

    adapter = CVEAdapter(client_for(handler))
    result = adapter.delta(db, since="2026-10-23T00:00:00Z", limit=1)
    assert not result["completed"] and count(db, Vulnerability) == 1
    log.insert(
        0,
        {
            "fetchTime": "2026-10-23T02:00:00Z",
            "new": [{"cveId": "CVE-2024-3096"}],
            "updated": [],
            "error": [],
        },
    )
    result = adapter.delta(db, limit=1)
    assert result["completed"] and count(db, Vulnerability) == 2
    assert adapter.delta(db, limit=1)["completed"]
    assert count(db, Vulnerability) == 3


def test_zip_limit_closes_download_before_full_archive(db, published):
    # ZIP_STORED keeps padding incompressible enough to prove the stream is cut short.
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive_:
        archive_.writestr("CVE-2024-3094.json", json.dumps(published))
        archive_.writestr(
            "CVE-2024-3095.json",
            json.dumps(
                {**published, "cveMetadata": {**published["cveMetadata"], "cveId": "CVE-2024-3095"}}
            ),
        )
        archive_.writestr("unused-padding", b"x" * 2_000_000)
    content = output.getvalue()
    received = 0

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            nonlocal received
            for offset in range(0, len(content), 4096):
                chunk = content[offset : offset + 4096]
                received += len(chunk)
                yield chunk

    adapter = CVEAdapter(client_for(lambda _: httpx.Response(200, stream=Stream())))
    assert adapter.baseline(db, url=BASELINE, limit=1)["processed"] == 1
    assert received < len(content) / 2
