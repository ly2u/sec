"""Web pages and JSON API: facts shown, exact lookups, caching and page hygiene."""

import re
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from apps.server.deps import get_session
from apps.server.main import app
from apps.server.models import (
    AffectedPackage,
    EPSSScore,
    IngestionState,
    KEVEntry,
    UpstreamAdvisory,
    Vulnerability,
    VulnerabilityAlias,
    VulnerabilityEvent,
)

NOW = datetime.now(UTC)


def seed(session):
    """A small, realistic data set (PHP CVE-2024-4577 shape)."""
    session.add_all(
        [
            Vulnerability(
                id="CVE-2024-4577",
                status="PUBLISHED",
                title="PHP-CGI OS Command Injection Vulnerability",
                description="In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* "
                "before 8.3.8, when using Apache and PHP-CGI on Windows, ... <script>x</script>",
                published_at=NOW - timedelta(days=20),
                modified_at=NOW - timedelta(days=2),
                cvss=9.8,
                cvss_version="3.1",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_source="cisa-adp",
                cvss_metrics=[{"version": "3.1", "source": "cisa-adp", "score": 9.8}],
                severity="CRITICAL",
                cwes=["CWE-78 OS Command Injection"],
                raw_record={
                    "containers": {
                        "cna": {
                            "references": [
                                {"url": "https://github.com/php/php-src/security/advisories/x"},
                                {"url": "javascript:alert(1)"},
                            ]
                        }
                    }
                },
            ),
            Vulnerability(
                id="CVE-2026-0001",
                status="PUBLISHED",
                title="",
                description="A medium issue in nginx.",
                published_at=NOW - timedelta(days=400),
                cvss=5.3,
                cvss_version="3.1",
                severity="MEDIUM",
            ),
            Vulnerability(id="CVE-2020-9999", status="REJECTED", description="Duplicate."),
        ]
    )
    session.flush()
    session.add_all(
        [
            KEVEntry(
                vulnerability_id="CVE-2024-4577",
                date_added=date.today() - timedelta(days=5),
                vendor="PHP Group",
                product="PHP",
                name="PHP-CGI OS Command Injection Vulnerability",
                description="...",
                required_action="Apply mitigations per vendor instructions.",
                ransomware="Known",
                notes="",
                catalog_version="2026.10.20",
                record_hash="x",
            ),
            EPSSScore(
                vulnerability_id="CVE-2024-4577",
                score_date=date.today(),
                epss=Decimal("0.94"),
                percentile=Decimal("0.999"),
                model_version="v4",
            ),
            VulnerabilityAlias(
                vulnerability_id="CVE-2024-4577", alias="GHSA-3qgc-jrrr-25jv", source="osv"
            ),
            VulnerabilityAlias(vulnerability_id="CVE-2024-4577", alias="DSA-5713-1", source="osv"),
            AffectedPackage(
                vulnerability_id="CVE-2024-4577",
                ecosystem="Debian:12",
                distro="debian",
                release="12",
                package_name="php8.2",
                ranges=[],
                status="fixed",
                fixed_version="8.2.20-1~deb12u1",
                source="osv:Debian",
                source_url="https://security-tracker.debian.org/tracker/CVE-2024-4577",
                entry_hash="a",
            ),
            AffectedPackage(
                vulnerability_id="CVE-2024-4577",
                ecosystem="Ubuntu:24.04",
                distro="ubuntu",
                release="24.04",
                package_name="php8.3",
                ranges=[],
                status="unfixed",
                source="osv:Ubuntu",
                source_url="https://ubuntu.com/security/CVE-2024-4577",
                entry_hash="b",
            ),
            UpstreamAdvisory(
                id="cve:php:CVE-2024-4577",
                product="php",
                source="cve",
                vulnerability_id="CVE-2024-4577",
                cve_ids=["CVE-2024-4577"],
                ranges=[
                    {"type": "UPSTREAM", "events": [{"introduced": "8.1.0"}, {"fixed": "8.1.29"}]},
                    {
                        "type": "UPSTREAM",
                        "events": [{"introduced": "0"}, {"last_affected": "7.4.33"}],
                    },
                ],
                ref="https://www.cve.org/CVERecord?id=CVE-2024-4577",
                record_hash="h",
                updated_at=NOW,
            ),
            UpstreamAdvisory(
                id="cve:nginx:CVE-2026-0001",
                product="nginx",
                source="cve",
                vulnerability_id="CVE-2026-0001",
                cve_ids=["CVE-2026-0001"],
                ranges=[
                    {"type": "UPSTREAM", "events": [{"introduced": "1.25.0"}, {"limit": "1.30.0"}]}
                ],
                ref="https://www.cve.org/CVERecord?id=CVE-2026-0001",
                record_hash="h2",
                updated_at=NOW,
            ),
            VulnerabilityEvent(
                vulnerability_id="CVE-2024-4577",
                event_type="added_to_kev",
                dedup_key="k1",
                source="kev",
                happened_at=NOW - timedelta(days=5),
                priority="P0",
                is_baseline=False,
                payload={},
            ),
            VulnerabilityEvent(
                vulnerability_id="CVE-2026-0001",
                event_type="severity_changed",
                dedup_key="k2",
                source="cvelistV5",
                happened_at=NOW - timedelta(days=1),
                priority="P2",
                is_baseline=True,
                payload={},
            ),
            IngestionState(source="kev", last_success_at=NOW - timedelta(hours=1)),
            IngestionState(source="osv:Debian", last_success_at=NOW - timedelta(hours=2)),
            IngestionState(source="osv:Ubuntu", last_success_at=NOW - timedelta(hours=3)),
        ]
    )


@pytest.fixture
def client(db):
    with Session(db) as session, session.begin():
        seed(session)

    def session_override():
        with Session(db) as session:
            yield session

    app.dependency_overrides[get_session] = session_override
    yield TestClient(app, follow_redirects=False)
    app.dependency_overrides.clear()


PAGES = [
    "/",
    "/cve/CVE-2024-4577",
    "/products",
    "/product/php",
    "/product/nginx",
    "/scanner",
    "/about",
    "/privacy",
    "/security",
]


@pytest.mark.parametrize("path", PAGES)
def test_pages_are_light_static_and_cacheable(client, path):
    response = client.get(path)
    assert response.status_code == 200, response.text[:500]
    html = response.text
    assert response.headers["cache-control"] == "public, max-age=300"
    assert "script-src" not in response.headers["content-security-policy"]
    assert "default-src 'none'" in response.headers["content-security-policy"]
    # No JavaScript, no external resources, within the size budget.
    assert "<script" not in html.lower()
    assert not re.search(r'\ssrc="(?:https?:)?//', html)
    for tag in re.findall(r"<link\b[^>]*>", html):
        assert not re.search(r'href="(?:https?:)?//', tag), tag
    css = client.get("/static/site.css")
    assert len(html.encode()) + len(css.content) < 100_000


def test_cve_page_shows_facts_and_escapes_text(client):
    html = client.get("/cve/CVE-2024-4577").text
    assert "P0" in html and "已确认在野利用" in html
    assert "94.0%" in html  # EPSS
    assert "8.2.20-1~deb12u1" in html and "Debian 12" in html
    assert "未修复" in html and "Ubuntu 24.04" in html
    assert "8.1.0 ≤ 版本 &lt; 8.1.29" in html and "版本 ≤ 7.4.33" in html
    assert "已知被勒索软件利用" in html
    assert "GHSA-3qgc-jrrr-25jv" in html
    assert "<script>x</script>" not in html and "&lt;script&gt;x&lt;/script&gt;" in html
    assert "javascript:alert" not in html


def test_rejected_and_missing(client):
    assert "已被撤销" in client.get("/cve/CVE-2020-9999").text
    missing = client.get("/cve/CVE-2030-12345")
    assert missing.status_code == 404 and "没有找到" in missing.text
    assert missing.headers["cache-control"] == "public, max-age=60"
    assert client.get("/cve/..%2F..%2Fetc").status_code == 404
    # Lower-case IDs are redirected to the canonical page.
    lower = client.get("/cve/cve-2024-4577")
    assert lower.status_code == 301 and lower.headers["location"] == "/cve/CVE-2024-4577"


@pytest.mark.parametrize(
    ("query", "status", "location"),
    [
        (" cve-2024-4577 ", 302, "/cve/CVE-2024-4577"),
        ("GHSA-3QGC-JRRR-25JV", 302, "/cve/CVE-2024-4577"),
        ("dsa-5713-1", 302, "/cve/CVE-2024-4577"),
        ("CVE-2031-0001", 404, None),
        ("php", 400, None),
        ("CVE-2024-%", 400, None),
        ("' OR 1=1 --", 400, None),
        ("", 400, None),
    ],
)
def test_lookup_is_exact(client, query, status, location):
    response = client.get("/go", params={"id": query})
    assert response.status_code == status
    if location:
        assert response.headers["location"] == location
    else:
        assert "<script" not in response.text


def test_product_pages(client):
    php = client.get("/product/php").text
    assert "CVE-2024-4577" in php and "已被在野利用" in php
    nginx = client.get("/product/nginx").text
    assert "1.25.0 ≤ 版本 &lt; 1.30.0（该分支不再修复）" in nginx
    assert "近 90 天没有新公开的漏洞" in nginx
    assert client.get("/product/nginx-ui").status_code == 404
    assert client.get("/product/php?page=9999").status_code == 422


def test_home_lists_recent_kev_events_and_freshness(client):
    html = client.get("/").text
    assert "CVE-2024-4577" in html
    assert "发行版安全公告（OSV）" in html
    # Baseline (bootstrap) events are never public.
    assert "严重程度调整" not in html


def test_rss_and_static_files(client):
    rss = client.get("/rss.xml")
    assert rss.headers["content-type"].startswith("application/rss+xml")
    assert "CVE-2024-4577" in rss.text and "<item>" in rss.text
    css = client.get("/static/site.css")
    assert css.headers["cache-control"] == "public, max-age=31536000, immutable"
    install = client.get("/install.sh")
    assert install.text.startswith("#!/bin/sh") and "verify_signature" in install.text
    assert client.get("/keys/bundle-signing.pub").text.startswith("untrusted comment:")
    assert client.get("/keys/secret.pub").status_code == 404


def test_api(client):
    v = client.get("/api/v1/vulnerabilities/CVE-2024-4577")
    assert v.headers["cache-control"] == "public, max-age=60"
    body = v.json()
    assert body["kev"] is True and body["priority"] == "P0"
    assert body["distros"][0]["distro"] == "Debian"
    assert client.get("/api/v1/vulnerabilities/CVE-2030-1").status_code == 404
    assert client.get("/api/v1/resolve", params={"id": "dsa-5713-1"}).json() == {
        "state": "found",
        "id": "CVE-2024-4577",
    }
    assert client.get("/api/v1/kev").json()["items"][0]["id"] == "CVE-2024-4577"
    assert client.get("/api/v1/kev", params={"page": 10_000}).status_code == 422
    assert client.get("/api/v1/products/php").json()["total"] == 1
    events = client.get("/api/v1/events").json()["items"]
    assert [e["vulnerability_id"] for e in events] == ["CVE-2024-4577"]
    schema = client.get("/api/v1/openapi.json").json()
    assert "/api/v1/kev" in schema["paths"] and "/cve/{vid}" not in schema["paths"]
    error = client.get("/api/v1/vulnerabilities/CVE-2030-1")
    assert error.headers["cache-control"] == "no-store"


def test_head_requests_return_headers_without_body(client):
    for path in ["/", "/cve/CVE-2024-4577", "/static/site.css", "/api/v1/kev", "/install.sh"]:
        get = client.get(path)
        head = client.head(path)
        assert head.status_code == get.status_code == 200, path
        assert head.content == b""
        assert head.headers["cache-control"] == get.headers["cache-control"]
        assert head.headers["content-type"] == get.headers["content-type"]
    assert client.head("/cve/CVE-2030-12345").status_code == 404
    assert client.post("/").status_code == 405
