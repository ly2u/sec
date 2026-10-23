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
from collector.upstream import backfill, coverage, cve_ranges, cve_rows, node_ranges

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


# GitHub's CNA (containerd, moby, redis …) writes ranges inside "version".
CONTAINERD = {
    "vendor": "containerd",
    "product": "containerd",
    "versions": [
        {"version": "< 1.6.38", "status": "affected"},
        {"version": ">= 1.7.0-beta.0, < 1.7.27", "status": "affected"},
        {"version": ">= 2.0.0, < 2.0.4", "status": "affected"},
        {"version": "= 2.1.0", "status": "affected"},
    ],
}


def test_github_cna_range_syntax():
    ranges, skipped = cve_ranges(CONTAINERD["versions"])
    assert skipped == 0
    assert [r["events"] for r in ranges] == [
        [{"introduced": "0"}, {"fixed": "1.6.38"}],
        [{"introduced": "1.7.0"}, {"fixed": "1.7.27"}],  # pre-release suffix dropped
        [{"introduced": "2.0.0"}, {"fixed": "2.0.4"}],
        [{"introduced": "2.1.0"}, {"last_affected": "2.1.0"}],
    ]
    assert [r["product"] for r in cve_rows(record("CVE-2026-2", CONTAINERD))] == ["containerd"]


def test_versions_never_carry_dashes_to_the_scanner():
    versions = [{"status": "affected", "version": "v3.0.0-rc1", "lessThan": "3.0.5+build7"}]
    assert cve_ranges(versions)[0] == [
        {"type": "UPSTREAM", "events": [{"introduced": "3.0.0"}, {"fixed": "3.0.5"}]}
    ]


def test_invalid_upstream_row_is_skipped_not_fatal(db, tmp_path, signing):
    binary, secret, public = signing
    with Session(db) as session, session.begin():
        apply_records(session, [record("CVE-2026-109618", PHP)])
        bad = session.get(UpstreamAdvisory, "cve:php:CVE-2026-109618")
        bad.ranges = [{"type": "UPSTREAM", "events": [{"introduced": "1.0-rc1"}]}]
    out = tmp_path / "bundles"
    generate(db, out, secret, public, binary=binary)
    manifest = json.loads((out / "manifest.json").read_bytes())
    payload = json.loads(
        zstandard.ZstdDecompressor().decompress(
            (out / manifest["bundles"]["upstream-1"]["file"]).read_bytes()
        )
    )
    assert "php" not in payload["source_packages"]
    assert "debian-12" in manifest["bundles"], "other bundles are still published"


def test_prose_ranges_from_older_records():
    def events(version):
        ranges, skipped = cve_ranges([{"status": "affected", "version": version}])
        return ranges[0]["events"] if ranges else None

    # Oracle's per-branch style: "5.7.43 and prior", "8.0.34 and prior".
    assert events("8.0.34 and prior") == [{"introduced": "0"}, {"last_affected": "8.0.34"}]
    assert events("2.4.48 and earlier") == [{"introduced": "0"}, {"last_affected": "2.4.48"}]
    assert events("before 2.4.49") == [{"introduced": "0"}, {"fixed": "2.4.49"}]
    assert events("versions prior to 8.0.35") == [{"introduced": "0"}, {"fixed": "8.0.35"}]
    assert events("through 3.0.7") == [{"introduced": "0"}, {"last_affected": "3.0.7"}]
    assert events("2.4.0 - 2.4.48") == [{"introduced": "2.4.0"}, {"last_affected": "2.4.48"}]
    assert events("2.4.0 to 2.4.48") == [{"introduced": "2.4.0"}, {"last_affected": "2.4.48"}]
    # Anything else stays unread rather than guessed.
    assert events("all supported versions") is None
    assert events("see advisory") is None


def test_per_branch_lists_do_not_overlap():
    versions = [
        {"status": "affected", "version": "before 7.4.33"},
        {"status": "affected", "version": "before 8.0.25"},
        {"status": "affected", "version": "before 8.1.12"},
    ]
    ranges, _ = cve_ranges(versions)
    assert [r["events"] for r in ranges] == [
        [{"introduced": "0"}, {"fixed": "7.4.33"}],
        [{"introduced": "8.0.0"}, {"fixed": "8.0.25"}],
        [{"introduced": "8.1.0"}, {"fixed": "8.1.12"}],
    ]
    # Oracle style.
    oracle = [
        {"status": "affected", "version": "8.0.39 and prior"},
        {"status": "affected", "version": "8.4.2 and prior"},
    ]
    assert cve_ranges(oracle)[0][1]["events"] == [
        {"introduced": "8.4.0"},
        {"last_affected": "8.4.2"},
    ]


def _events(version):
    return [r["events"] for r in cve_ranges([{"status": "affected", "version": version}])[0]]


def test_branch_scoped_and_combined_prose():
    # Strings exactly as found in PHP, PostgreSQL, Redis, MySQL and Apache records.
    assert _events("7.3.x below 7.3.8") == [[{"introduced": "7.3.0"}, {"fixed": "7.3.8"}]]
    assert _events("7.2.x < 7.2.19") == [[{"introduced": "7.2.0"}, {"fixed": "7.2.19"}]]
    assert _events("all 11.x before 11.5") == [[{"introduced": "11.0"}, {"fixed": "11.5"}]]
    assert _events("11.x prior to 11.3") == [[{"introduced": "11.0"}, {"fixed": "11.3"}]]
    assert _events("3.2.x prior to 3.2.4") == [[{"introduced": "3.2.0"}, {"fixed": "3.2.4"}]]
    assert _events("7.3.x below 7.3.17 and 7.4.x below 7.4.5") == [
        [{"introduced": "7.3.0"}, {"fixed": "7.3.17"}],
        [{"introduced": "7.4.0"}, {"fixed": "7.4.5"}],
    ]
    assert _events("2.2.0 to 2.2.31, 2.4.1 to 2.4.23") == [
        [{"introduced": "2.2.0"}, {"last_affected": "2.2.31"}],
        [{"introduced": "2.4.1"}, {"last_affected": "2.4.23"}],
    ]
    assert _events("5.5.57 and earlier  5.6.37 and earlier  5.7.19 and earlier") == [
        [{"introduced": "0"}, {"last_affected": "5.5.57"}],
        [{"introduced": "5.6.0"}, {"last_affected": "5.6.37"}],
        [{"introduced": "5.7.0"}, {"last_affected": "5.7.19"}],
    ]
    assert _events("Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27") == [
        [{"introduced": "0"}, {"last_affected": "2.2.34"}],
        [{"introduced": "2.4.0"}, {"last_affected": "2.4.27"}],
    ]
    # PostgreSQL 10+ versions are major.minor: 10.15 belongs to branch 10.
    pg = "All PostgreSQL versions before 13.1, before 12.5, before 11.10, before 10.15, before 9.6.20"
    assert _events(pg) == [
        [{"introduced": "13.0"}, {"fixed": "13.1"}],
        [{"introduced": "12.0"}, {"fixed": "12.5"}],
        [{"introduced": "11.0"}, {"fixed": "11.10"}],
        [{"introduced": "10.0"}, {"fixed": "10.15"}],
        [{"introduced": "0"}, {"fixed": "9.6.20"}],
    ]


def test_product_prefixes_and_fixed_in_form():
    assert _events("Apache HTTP Server 2.4.49") == [
        [{"introduced": "2.4.49"}, {"last_affected": "2.4.49"}]
    ]
    assert _events("Apache HTTP Server 2.4 2.4.17 to 2.4.48") == [
        [{"introduced": "2.4.17"}, {"last_affected": "2.4.48"}]
    ]
    assert _events("openssl-1.1.0a") == [[{"introduced": "1.1.0a"}, {"last_affected": "1.1.0a"}]]
    assert _events("Docker Engine < 29.5.1") == [[{"introduced": "0"}, {"fixed": "29.5.1"}]]
    assert _events("github.com/docker/docker/daemon <= 28.5.2") == [
        [{"introduced": "0"}, {"last_affected": "28.5.2"}]
    ]
    assert _events("Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c)") == [
        [{"introduced": "1.1.1"}, {"last_affected": "1.1.1c"}]
    ]
    assert _events("Fixed in Apache HTTP Server 2.4.34 (Affected 2.4.18-2.4.30,2.4.33)") == [
        [{"introduced": "2.4.18"}, {"last_affected": "2.4.30"}],
        [{"introduced": "2.4.33"}, {"last_affected": "2.4.33"}],
    ]


def test_unclear_prose_stays_skipped():
    for value in [
        "Apache HTTP Server 2.4",  # a whole branch named, no versions
        "Apache HTTP Server",
        "Affects v9.6 to v14",  # 14.5 would sort above "14"
        "PostgreSQL 15.3, PostgreSQL 14.8, PostgreSQL 13.11",  # these are the fixes
        "github.com/moby/moby/v2/daemon < 2.0.0-beta.14",  # module, not engine, versions
        "7.2.x below 8.0.1",
        "2.4.x to 2.4.9",
    ]:
        assert cve_ranges([{"status": "affected", "version": value}]) == ([], 1), value


def test_default_affected_reads_listed_ranges_only_without_exceptions():
    listed = [{"status": "affected", "version": "8.1.*", "lessThan": "8.1.29"}]
    assert cve_ranges(listed, "affected")[0][0]["events"] == [
        {"introduced": "8.1.0"},
        {"fixed": "8.1.29"},
    ]
    exceptions = [*listed, {"status": "unaffected", "version": "8.1.29"}]
    assert cve_ranges(exceptions, "affected") == ([], 2)


def test_coverage_reports_unread_strings(db):
    odd = {
        "vendor": "PHP Group",
        "product": "PHP",
        "versions": [{"status": "affected", "version": "see notes"}],
    }
    with Session(db) as session, session.begin():
        apply_records(session, [record("CVE-2026-109618", PHP), record("CVE-2026-0003", odd)])
    report = coverage(db, batch=1)
    assert report["php"]["cves"] == 2 and report["php"]["converted"] == 1
    assert report["php"]["top_unparsed"] == [("see notes", 1)]


def test_ambiguous_entries_are_skipped_not_guessed():
    assert cve_ranges([{"status": "affected", "version": "0"}]) == ([], 1)
    assert cve_ranges([{"status": "affected", "version": "R36", "lessThan": "*"}]) == ([], 1)
    assert cve_ranges([{"status": "affected", "version": "abc", "versionType": "git"}]) == ([], 1)
    assert cve_ranges([{"status": "affected", "version": "> latest"}]) == ([], 1)
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
