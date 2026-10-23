import io
import json
import shutil
import tarfile
from pathlib import Path

import httpx
import pytest
import zstandard
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.server.models import UpstreamAdvisory
from collector.adapters.cvelist import apply_records
from collector.adapters.nodejs import ARCHIVE, NodejsAdapter, entry_row
from collector.bundles import generate, run_minisign
from collector.http import FeedHTTP
from collector.upstream import backfill, cve_ranges, cve_rows, node_ranges

FIXTURES = Path(__file__).parent / "fixtures" / "upstream"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def signing(tmp_path):
    binary = shutil.which("minisign") or str(ROOT / "cache/minisign/usr/bin/minisign")
    if not Path(binary).is_file():
        pytest.fail("Install minisign for the real signing integration tests")
    secret, public = tmp_path / "test-only.key", tmp_path / "test-only.pub"
    run_minisign(["-G", "-W", "-s", str(secret), "-p", str(public)], binary)
    secret.chmod(0o600)
    return binary, secret, public


# Verbatim affected[] shapes from the live corpus (2026-10-23).
PHP = {
    "vendor": "PHP Group",
    "product": "PHP",
    "versions": [
        {"status": "affected", "version": "8.2.*", "lessThan": "8.2.35", "versionType": "semver"},
        {"status": "affected", "version": "8.3.*", "lessThan": "8.3.36", "versionType": "semver"},
        {"status": "affected", "version": "8.4.*", "lessThan": "8.4.27", "versionType": "semver"},
        {"status": "affected", "version": "8.5.*", "lessThan": "8.5.12", "versionType": "semver"},
    ],
    "defaultStatus": "unaffected",
}
NGINX_OSS = {
    "vendor": "F5",
    "product": "NGINX Open Source",
    "versions": [
        {"status": "affected", "version": "1.31.0", "lessThan": "1.31.7", "versionType": "custom"},
        {"status": "affected", "version": "1.30.0", "lessThan": "1.30.6", "versionType": "custom"},
        {"status": "affected", "version": "1.25.0", "lessThan": "*", "versionType": "custom"},
    ],
}
NGINX_PLUS = {
    "vendor": "F5",
    "product": "NGINX Plus",
    "versions": [
        {
            "status": "affected",
            "version": "37.1.0",
            "lessThan": "37.2.0.1",
            "versionType": "custom",
        },
        {"status": "affected", "version": "R36", "lessThan": "*", "versionType": "custom"},
    ],
}


def record(cve, *affected, state="PUBLISHED"):
    return {
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve, "state": state, "datePublished": "2026-10-20T00:00:00Z"},
        "containers": {
            "cna": {
                "affected": list(affected),
                "descriptions": [{"lang": "en", "value": "test"}],
                "metrics": [{"cvssV3_1": {"baseScore": 9.2, "baseSeverity": "CRITICAL"}}],
            }
        },
    }


def test_php_branches():
    ranges, skipped = cve_ranges(PHP["versions"])
    assert skipped == 0
    assert ranges[1] == {
        "type": "UPSTREAM",
        "events": [{"introduced": "8.3.0"}, {"fixed": "8.3.36"}],
    }


def test_nginx_open_ended_range_stops_at_next_listed_branch():
    ranges, _ = cve_ranges(NGINX_OSS["versions"])
    # Read literally, "1.25.0 <*" would also cover the fixed 1.30.6 and 1.31.7.
    assert {"type": "UPSTREAM", "events": [{"introduced": "1.25.0"}, {"limit": "1.30.0"}]} in ranges


def test_ambiguous_entries_are_skipped_not_guessed():
    assert cve_ranges([{"status": "affected", "version": "0"}]) == ([], 1)
    assert cve_ranges([{"status": "affected", "version": "R36", "lessThan": "*"}]) == ([], 1)
    assert cve_ranges([{"status": "affected", "version": "abc", "versionType": "git"}]) == ([], 1)
    # "Everything affected except ..." cannot be expressed safely.
    assert cve_ranges([{"status": "unaffected", "version": "2.0"}], "affected")[0] == []


def test_only_identified_products_match():
    rows = cve_rows(
        record(
            "CVE-2026-95101",
            NGINX_PLUS,
            NGINX_OSS,
            {"vendor": "0xJacky", "product": "nginx-ui", "versions": NGINX_OSS["versions"]},
        )
    )
    assert [r["product"] for r in rows] == ["nginx"]
    flat = [e for r in rows[0]["ranges"] for e in r["events"]]
    assert {"introduced": "37.1.0"} not in flat, "NGINX Plus numbering must never mix in"


def test_rejected_records_produce_nothing():
    assert cve_rows(record("CVE-2026-1", PHP, state="REJECTED")) == []


def test_node2shell_from_security_wg():
    entry = json.loads((FIXTURES / "nodejs-204.json").read_text())
    row = entry_row(204, entry)
    assert row["cve_ids"] == ["CVE-2026-111497"]
    assert {"type": "UPSTREAM", "events": [{"introduced": "24.0.0"}, {"fixed": "24.22.1"}]} in row[
        "ranges"
    ]
    assert row["ref"].startswith("https://nodejs.org/")


def test_node_semver_forms():
    assert node_ranges("<12.22.6 || >=14.0.0 <14.17.6", "^12.22.6 || ^14.17.6 || >=16.8.0")[0] == [
        {"type": "UPSTREAM", "events": [{"introduced": "0"}, {"fixed": "12.22.6"}]},
        {"type": "UPSTREAM", "events": [{"introduced": "14.0.0"}, {"fixed": "14.17.6"}]},
    ]
    # An end-of-life major with no patched release stays affected up to the next major.
    ranges, ok = node_ranges("21.x || 22.x", "^22.23.4")
    assert ok and ranges[0]["events"] == [{"introduced": "21.0.0"}, {"limit": "22.0.0"}]
    assert node_ranges("0.10.x", "^0.10.48") == ([], False)


def tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            raw = json.dumps(data).encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def node_http(payload):
    def handler(request):
        assert str(request.url) == ARCHIVE
        return httpx.Response(200, content=payload)

    return FeedHTTP(httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)


def test_nodejs_adapter_full_replace(db):
    node2shell = json.loads((FIXTURES / "nodejs-204.json").read_text())
    files = {
        "security-wg-main/vuln/core/204.json": node2shell,
        "security-wg-main/vuln/core/8.json": {"vulnerable": "0.10.x", "patched": "^0.10.48"},
        "security-wg-main/vuln/core/index.json": {"stale": True},
        "security-wg-main/vuln/npm/1.json": {"ignored": True},
    }
    result = NodejsAdapter(node_http(tarball(files))).run(db)
    assert result == {
        "source": "nodejs-security-wg",
        "entries": 1,
        "skipped": 1,
        "processed": 1,
    }
    assert NodejsAdapter(node_http(tarball(files))).run(db)["processed"] == 0
    with Session(db) as session:
        assert (
            session.get(UpstreamAdvisory, "nodejs:node:204").vulnerability_id == "CVE-2026-111497"
        )


def test_cve_ingest_syncs_and_rejection_removes(db):
    with Session(db) as session, session.begin():
        apply_records(session, [record("CVE-2026-109618", PHP)])
    with Session(db) as session:
        row = session.get(UpstreamAdvisory, "cve:php:CVE-2026-109618")
        assert row and row.product == "php"
    rejected = record("CVE-2026-109618", PHP, state="REJECTED")
    rejected["cveMetadata"]["dateUpdated"] = "2026-10-23T00:00:00Z"
    rejected["containers"]["cna"]["rejectedReasons"] = [{"lang": "en", "value": "dup"}]
    with Session(db) as session, session.begin():
        apply_records(session, [rejected])
    with Session(db) as session:
        assert session.get(UpstreamAdvisory, "cve:php:CVE-2026-109618") is None


def test_backfill_is_idempotent(db):
    with Session(db) as session, session.begin():
        apply_records(
            session, [record("CVE-2026-109618", PHP), record("CVE-2026-95101", NGINX_OSS)]
        )
        session.execute(UpstreamAdvisory.__table__.delete())
    assert backfill(db, batch=1) == {"records": 2, "upstream_rows": 2}
    assert backfill(db, batch=1)["upstream_rows"] == 2
    with Session(db) as session:
        assert len(session.scalars(select(UpstreamAdvisory)).all()) == 2


def test_upstream_bundle_is_signed_and_enriched(db, tmp_path, signing):
    binary, secret, public = signing
    with Session(db) as session, session.begin():
        apply_records(session, [record("CVE-2026-109618", PHP)])
    NodejsAdapter(
        node_http(
            tarball(
                {
                    "security-wg-main/vuln/core/204.json": json.loads(
                        (FIXTURES / "nodejs-204.json").read_text()
                    )
                }
            )
        )
    ).run(db)
    out = tmp_path / "bundles"
    generate(db, out, secret, public, binary=binary)
    manifest = json.loads((out / "manifest.json").read_bytes())
    item = manifest["bundles"]["upstream-1"]
    assert item["file"].startswith("upstream-1.")
    payload = json.loads(zstandard.ZstdDecompressor().decompress((out / item["file"]).read_bytes()))
    assert payload["package_key"] == "product" and payload["distro"] == "upstream"
    php = payload["source_packages"]["php"][0]
    assert php["id"] == "CVE-2026-109618" and php["cvss"] == 9.2 and php["status"] == "fixed"
    node = payload["source_packages"]["node"][0]
    assert node["id"] == "CVE-2026-111497" and node["source"] == "nodejs-security-wg"
    assert node["severity"] == "HIGH"
