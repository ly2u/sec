import copy
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
import zstandard
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.server.main import app
from apps.server.models import (
    AffectedPackage,
    IngestionState,
    ScheduledTask,
    TaskRun,
    VulnerabilityEvent,
)
from collector.adapters.osv import apply_records
from collector.bundles import generate, public_key_id, run_minisign
from collector.scheduler import initialize, leader, tick

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def signing(tmp_path):
    binary = shutil.which("minisign") or str(ROOT / "cache/minisign/usr/bin/minisign")
    if not Path(binary).is_file():
        pytest.fail("Install minisign for the real signing/tamper integration tests")
    secret = tmp_path / "test-only.key"
    public = tmp_path / "test-only.pub"
    run_minisign(["-G", "-W", "-s", str(secret), "-p", str(public)], binary)
    secret.chmod(0o600)
    return binary, secret, public


def seed(db):
    record = json.loads((ROOT / "tests/fixtures/osv/UBUNTU-CVE-2025-6491.json").read_text())
    with Session(db) as session, session.begin():
        apply_records(session, [record], "Ubuntu")
    return record


def test_real_signature_tamper_noop_changed_release_and_7_day_retention(db, tmp_path, signing):
    binary, secret, public = signing
    out = tmp_path / "bundles"
    record = seed(db)
    first = generate(db, out, secret, public, binary=binary)
    assert len(first["rebuilt"]) == 15  # 13 distro releases + upstream-1 + golang-1
    manifest = json.loads((out / "manifest.json").read_bytes())
    assert manifest["key_id"] == public_key_id(public)
    item = manifest["bundles"]["ubuntu-20.04"]
    path = out / item["file"]
    run_minisign(["-V", "-H", "-m", str(path), "-p", str(public)], binary)
    payload = json.loads(zstandard.ZstdDecompressor().decompress(path.read_bytes()))
    assert payload["package_key"] == "source"
    row = payload["source_packages"]["php7.4"][0]
    assert row["requires_subscription"] and all(v["requires_subscription"] for v in row["fixes"])
    assert row["ranges"] == next(
        a["ranges"]
        for a in record["affected"]
        if a["package"]["ecosystem"] == "Ubuntu:Pro:20.04:LTS"
    )
    assert manifest["bundles"]["debian-11"]["coverage"]["status"] == "unavailable"
    before = (out / "manifest.json").read_bytes()
    assert generate(db, out, secret, public, binary=binary)["rebuilt"] == []
    assert (out / "manifest.json").read_bytes() == before
    # Modify exactly one byte and keep the genuine signature.
    tampered = bytearray(path.read_bytes())
    tampered[len(tampered) // 2] ^= 1
    bad = tmp_path / "tampered.zst"
    bad.write_bytes(tampered)
    with pytest.raises(subprocess.CalledProcessError):
        run_minisign(
            ["-V", "-H", "-m", str(bad), "-x", str(path) + ".minisig", "-p", str(public)], binary
        )
    with Session(db) as session, session.begin():
        row = session.scalar(select(AffectedPackage).where(AffectedPackage.release == "22.04"))
        row.status = "unfixed"
        row.fixed_version = None
    changed = generate(db, out, secret, public, binary=binary)
    assert changed["rebuilt"] == ["ubuntu-22.04"]
    for v in json.loads((out / "manifest.json").read_bytes())["bundles"].values():
        assert (out / v["file"]).exists() and (out / v["signature"]).exists()
    orphan = out / "ubuntu-22.04.123456789abc.json.zst"
    orphan.write_bytes(b"old")
    os.utime(orphan, (1, 1))
    generate(db, out, secret, public, binary=binary)
    assert not orphan.exists() and path.exists()


def test_debian_urgency_reaches_bundle(db, tmp_path, signing):
    binary, secret, public = signing
    record = json.loads((ROOT / "tests/fixtures/osv/DEBIAN-CVE-2005-3120.json").read_text())
    with Session(db) as session, session.begin():
        apply_records(session, [record], "Debian")
    out = tmp_path / "bundles"
    generate(db, out, secret, public, binary=binary)
    manifest = json.loads((out / "manifest.json").read_bytes())
    path = out / manifest["bundles"]["debian-12"]["file"]
    payload = json.loads(zstandard.ZstdDecompressor().decompress(path.read_bytes()))
    assert payload["source_packages"]["lynx"][0]["urgency"] == "high"


def test_signature_failure_cannot_replace_manifest(db, tmp_path, signing, monkeypatch):
    import collector.bundles as bundles

    binary, secret, public = signing
    out = tmp_path / "bundles"
    seed(db)
    generate(db, out, secret, public, binary=binary)
    before = (out / "manifest.json").read_bytes()
    with Session(db) as session, session.begin():
        session.scalar(select(AffectedPackage)).status = "unfixed"

    def fail(*args, **kwargs):
        raise RuntimeError("simulated signing failure")

    monkeypatch.setattr(bundles, "run_minisign", fail)
    with pytest.raises(RuntimeError):
        generate(db, out, secret, public, binary=binary)
    assert (out / "manifest.json").read_bytes() == before


def test_bundle_cache_etag_and_path_protection(tmp_path, monkeypatch):
    monkeypatch.setenv("BUNDLES_DIR", str(tmp_path))
    (tmp_path / "manifest.json").write_text('{"schema":1}')
    hashed = "debian-12.abcdef123456.json.zst"
    (tmp_path / hashed).write_bytes(b"data")
    client = TestClient(app)
    first = client.get("/bundles/manifest.json")
    assert first.headers["cache-control"] == "public, max-age=60, must-revalidate"
    assert (
        client.get(
            "/bundles/manifest.json", headers={"If-None-Match": first.headers["etag"]}
        ).status_code
        == 304
    )
    assert (
        client.get("/bundles/" + hashed).headers["cache-control"]
        == "public, max-age=31536000, immutable"
    )
    assert client.get("/bundles/.pending-key").status_code == 404
    link = tmp_path / "debian-13.abcdef123456.json.zst"
    link.symlink_to("/etc/passwd")
    assert client.get("/bundles/" + link.name).status_code == 404
    assert client.get("/bundles/%2E%2E%2Fsecrets").status_code == 404


def test_cve_first_delta_after_completed_baseline_is_not_baseline(db):
    from collector.adapters.cvelist import apply_records as apply_cve

    record = json.loads((ROOT / "tests/fixtures/CVE-2024-3094.json").read_text())
    with Session(db) as session, session.begin():
        apply_cve(session, [record])
        session.add(
            IngestionState(
                source="cve:baseline",
                source_revision="pinned",
                cursor={},
                records_processed=1,
                completed=True,
                has_completed=True,
            )
        )
    changed = copy.deepcopy(record)
    changed["cveMetadata"]["dateUpdated"] = "2026-10-23T04:00:00Z"
    next(
        metric["cvssV3_1"]
        for metric in changed["containers"]["cna"]["metrics"]
        if "cvssV3_1" in metric
    )["baseScore"] = 7.5
    import httpx

    from collector.adapters.cvelist import DELTA_LOG, CVEAdapter
    from collector.http import FeedHTTP

    with Session(db) as session, session.begin():
        session.get(IngestionState, "cve:baseline").cursor = {
            "url": "https://github.com/CVEProject/cvelistV5/releases/download/test/2026-10-23_all_CVEs_at_midnight.zip.zip"
        }
    log = [
        {"fetchTime": "2026-10-23T04:00:00Z", "new": [], "updated": [{"cveId": "CVE-2024-3094"}]},
        {"fetchTime": "2026-10-23T00:00:00Z", "new": [], "updated": []},
    ]
    http = FeedHTTP(
        httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json=log if str(request.url) == DELTA_LOG else changed
                )
            )
        )
    )
    assert CVEAdapter(http).delta(db, limit=None)["completed"]
    with Session(db) as session:
        rows = list(session.scalars(select(VulnerabilityEvent)))
        assert len(rows) == 1 and not rows[0].is_baseline


def test_scheduler_staggers_persists_and_recovers_interrupted_tasks(db):
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    initialize(db, now)
    with Session(db) as session:
        times = list(
            session.scalars(select(ScheduledTask.next_run_at).order_by(ScheduledTask.next_run_at))
        )
        assert all((times[i + 1] - times[i]).total_seconds() == 120 for i in range(3))

    def success(*_):
        return {"feed": {"completed": True}, "bundles": {"rebuilt": []}}

    assert tick(db, now + timedelta(minutes=1), success)
    assert tick(db, now + timedelta(minutes=1, seconds=59), success) is None
    initialize(db, now + timedelta(minutes=2))
    with Session(db) as session, session.begin():
        assert session.scalar(select(func.count()).select_from(TaskRun)) == 1
        session.add(TaskRun(task="osv", started_at=now, status="running", attempt=1, result={}))
    initialize(db, now + timedelta(minutes=4))
    with Session(db) as session:
        assert session.scalar(select(TaskRun).where(TaskRun.task == "osv")).status == "interrupted"


def test_scheduler_bounded_retry_is_recorded(db):
    now = datetime.now(UTC)
    initialize(db, now)
    with Session(db) as session, session.begin():
        for task in session.scalars(select(ScheduledTask)):
            task.next_run_at = now + timedelta(days=1)
        session.get(ScheduledTask, "kev").next_run_at = now

    def failed(*_):
        raise TimeoutError("upstream")

    tick(db, now, failed)
    with Session(db) as session:
        retry = session.get(ScheduledTask, "kev").next_run_at
    retry = retry.replace(tzinfo=UTC) if retry.tzinfo is None else retry
    tick(db, retry + timedelta(seconds=1), lambda *_: {"feed": {"completed": True}})
    with Session(db) as session:
        runs = list(session.scalars(select(TaskRun).order_by(TaskRun.id)))
        assert [r.status for r in runs] == ["failed", "success"]
        assert [r.attempt for r in runs] == [1, 2]


def test_advisory_lock_rejects_second_leader_and_releases(db):
    if db.dialect.name != "postgresql":
        pytest.skip("Actual advisory lock is PostgreSQL-specific")
    with leader(db) as first:
        assert first is not None
        with leader(db) as second:
            assert second is None
    with leader(db) as after:
        assert after is not None


def test_bundles_volume_and_private_key_isolation():
    config = yaml.safe_load((ROOT / "deploy/compose.yaml").read_text())
    assert "bundles:/bundles:ro" in config["services"]["web"]["volumes"]
    assert "bundles:/bundles" in config["services"]["worker"]["volumes"]
    assert "../secrets:/run/secwatch-secrets:ro" in config["services"]["worker"]["volumes"]
    assert all("secrets" not in mount for mount in config["services"]["web"]["volumes"])
    assert config["services"]["worker"]["command"][-1] == "worker"
    assert "secrets" in (ROOT / ".dockerignore").read_text().splitlines()


def test_ransomware_flag_requires_active_known_kev():
    from types import SimpleNamespace as F

    from collector.bundles import ransomware

    assert ransomware([F(is_active=True, ransomware="Known")])
    assert not ransomware([F(is_active=True, ransomware="Unknown")])
    assert not ransomware([F(is_active=False, ransomware="Known")])  # removed from KEV
    assert not ransomware([F(is_active=None, ransomware=None)])  # not in KEV at all
