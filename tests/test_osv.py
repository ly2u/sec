import copy
import io
import json
import zipfile
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.server.models import AffectedPackage, IngestionState, OSVAdvisory, VulnerabilityEvent
from collector.adapters.osv import OSVAdapter, apply_records, package_rows
from collector.distros import coordinate
from collector.http import FeedHTTP

FIXTURES = Path(__file__).parent / "fixtures/osv"


def fixture(name):
    return json.loads((FIXTURES / (name + ".json")).read_text())


def http(handler):
    return FeedHTTP(httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)


@pytest.mark.parametrize(
    "name,base,key",
    [
        ("DEBIAN-CVE-2005-4349", "Debian", "source"),
        ("DEBIAN-CVE-2005-3660", "Debian", "source"),
        ("DEBIAN-CVE-2005-3120", "Debian", "source"),
        ("USN-8953-1", "Ubuntu", "source"),
        ("USN-8952-1", "Ubuntu", "source"),
        ("USN-8949-1", "Ubuntu", "source"),
        ("ALPINE-CVE-2006-20001", "Alpine", "origin"),
        ("ALPINE-CVE-2010-3846", "Alpine", "origin"),
        ("ALPINE-CVE-2026-97205", "Alpine", "origin"),
        ("RLSA-2024_9333", "Rocky Linux", "source"),
        ("RLSA-2022_2013", "Rocky Linux", "source"),
        ("RLSA-2022_0896", "Rocky Linux", "source"),
        ("ALSA-2026_87079", "AlmaLinux", "binary"),
        ("ALSA-2026_87072", "AlmaLinux", "binary"),
        ("ALSA-2026_87070", "AlmaLinux", "binary"),
    ],
)
def test_real_package_keys_and_unchanged_ecosystem_ranges(name, base, key):
    record = fixture(name)
    rows = package_rows(record, base)
    # Some minimal older Alpine/Alma10 slices are outside the supported releases.
    if not rows:
        assert all(coordinate(a["package"]["ecosystem"]) is None for a in record["affected"])
    for row in rows:
        assert row["package_key"] == key
        original = next(
            a
            for a in record["affected"]
            if a["package"]["name"] == row["package_name"]
            and a["package"]["ecosystem"] == row["ecosystem"]
            and a["ranges"] == row["ranges"]
        )
        assert row["ranges"] == original["ranges"]
        assert row["requires_subscription"] == (":Pro:" in row["ecosystem"])


def test_pro_is_preserved_and_empty_scoped_cve_map_is_not_expanded():
    record = fixture("USN-8952-1")
    rows = package_rows(record, "Ubuntu")
    row = next(r for r in rows if r["release"] == "20.04")
    assert row["requires_subscription"] and row["source_metadata"]["cve_ids"] == []
    assert row["vulnerability_id"] == "USN-8952-1"
    assert coordinate("Ubuntu:Pro:FIPS:20.04:LTS") is None
    assert coordinate("Ubuntu:Pro:22.04:LTS:Realtime:Kernel") is None


def test_debian_open_range_is_unfixed_not_inferred_ignored():
    row = package_rows(fixture("DEBIAN-CVE-2005-3660"), "Debian")[0]
    assert row["status"] == "unfixed" and row["fixed_version"] is None
    assert row["ranges"] == [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]


def test_osv_upsert_replay_stale_and_withdrawn_preserve_provenance(db):
    record = fixture("UBUNTU-CVE-2025-6491")

    def apply(r):
        with Session(db) as session, session.begin():
            apply_records(session, [r], "Ubuntu")

    apply(record)
    with Session(db) as session:
        count = session.scalar(select(func.count()).select_from(AffectedPackage))
        events = session.scalar(select(func.count()).select_from(VulnerabilityEvent))
    apply(record)
    old = copy.deepcopy(record)
    old["modified"] = "2000-01-01T00:00:00Z"
    old["affected"] = []
    apply(old)
    with Session(db) as session:
        assert session.scalar(select(func.count()).select_from(AffectedPackage)) == count
        assert session.scalar(select(func.count()).select_from(VulnerabilityEvent)) == events
    withdrawn = copy.deepcopy(record)
    withdrawn["modified"] = "2026-10-24T00:00:00Z"
    withdrawn["withdrawn"] = withdrawn["modified"]
    apply(withdrawn)
    with Session(db) as session:
        assert session.scalar(select(func.count()).select_from(AffectedPackage)) == 0
        assert session.get(OSVAdvisory, record["id"]).withdrawn_at


def test_pinned_osv_baseline_resumes_and_delta_reconciles_export_race(db):
    records = [fixture("DEBIAN-CVE-2005-4349"), fixture("DEBIAN-CVE-2005-3660")]
    csv = "".join(
        r["modified"] + "," + r["id"] + "\n"
        for r in sorted(records, key=lambda r: r["modified"], reverse=True)
    )
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(records[0]["id"] + ".json", json.dumps(records[0]))
        z.writestr(records[1]["id"] + ".json", json.dumps(records[1]))
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if request.method == "HEAD":
            return httpx.Response(200, headers={"x-goog-generation": "123"})
        if request.url.path.endswith("ecosystems.txt"):
            return httpx.Response(200, text="Debian\nUbuntu\n")
        if request.url.path.endswith("modified_id.csv"):
            return httpx.Response(200, text=csv)
        if request.url.path.endswith("all.zip"):
            return httpx.Response(200, content=archive.getvalue())
        r = next(r for r in records if request.url.path.endswith(r["id"] + ".json"))
        return httpx.Response(200, json=r)

    adapter = OSVAdapter(http(handler))
    assert not adapter.baseline(db, "Debian", limit=1)["completed"]
    assert adapter.baseline(db, "Debian", limit=None)["completed"]
    assert any("?generation=123" in u for u in calls)
    # A record that changed between separately exported ZIP/CSV must not be skipped.
    records[0]["modified"] = "2026-10-24T00:00:00Z"
    csv = records[0]["modified"] + "," + records[0]["id"] + "\n" + csv
    result = adapter.delta(db, "Debian")
    assert result["completed"] and result["processed"] == 1
    assert adapter.delta(db, "Debian")["processed"] == 0
    with Session(db) as session:
        assert session.get(IngestionState, "osv:delta:Debian").has_completed


def test_unsafe_package_and_versions_rejected():
    record = fixture("DEBIAN-CVE-2005-4349")
    record["affected"][0]["package"]["name"] = "evil;reboot"
    with pytest.raises(ValueError, match="Unsafe package"):
        package_rows(record, "Debian")
    record = fixture("DEBIAN-CVE-2005-4349")
    record["affected"][0]["ranges"][0]["events"][0]["introduced"] = "$(reboot)"
    with pytest.raises(ValueError, match="Invalid distro"):
        package_rows(record, "Debian")
