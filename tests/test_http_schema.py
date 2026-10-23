from pathlib import Path

import httpx
import pytest
import yaml
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from apps.server.db import Base
from apps.server.main import app
from collector.http import FeedHTTP

URL = "https://www.cisa.gov/test.json"
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_http_retry_after_and_success(status):
    calls = []
    sleeps = []

    def handler(request):
        calls.append(request)
        return (
            httpx.Response(status, headers={"Retry-After": "2"})
            if len(calls) == 1
            else httpx.Response(200, json={"ok": True})
        )

    http = FeedHTTP(httpx.Client(transport=httpx.MockTransport(handler)), sleep=sleeps.append)
    assert http.json(URL) == {"ok": True}
    assert len(calls) == 2 and sleeps == [2]


def test_http_bounded_retries_and_redirect_allowlist():
    calls = []

    def unavailable(request):
        calls.append(request)
        return httpx.Response(503)

    http = FeedHTTP(httpx.Client(transport=httpx.MockTransport(unavailable)), sleep=lambda _: None)
    with pytest.raises(httpx.HTTPStatusError):
        http.json(URL)
    assert len(calls) == 4
    redirect = FeedHTTP(
        httpx.Client(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(302, headers={"Location": "http://127.0.0.1/secrets"})
            )
        )
    )
    with pytest.raises(ValueError, match="Unapproved"):
        redirect.read(URL)


def test_http_size_limit():
    http = FeedHTTP(
        httpx.Client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 100))
        )
    )
    with pytest.raises(ValueError, match="size"):
        http.read(URL, max_bytes=10)


def test_migration_roundtrip_matches_models(db, monkeypatch):
    Base.metadata.drop_all(db)
    monkeypatch.setenv("DATABASE_URL", db.url.render_as_string(hide_password=False))
    config = Config(str(ROOT / "alembic.ini"))
    command.upgrade(config, "head")
    assert set(inspect(db).get_table_names()) == set(Base.metadata.tables) | {"alembic_version"}
    command.check(config)
    command.downgrade(config, "base")
    assert inspect(db).get_table_names() == ["alembic_version"]
    command.upgrade(config, "head")


def test_compose_resources_and_network_isolation():
    config = yaml.safe_load((ROOT / "deploy/compose.yaml").read_text())
    assert config["name"] == "secwatch-dev"
    assert config["networks"]["secwatch-edge"] == {"name": "secwatch-edge", "external": True}
    expected = {"postgres": ("4g", 2.0), "worker": ("2g", 1.5), "web": ("1g", 1.0)}
    for service, (memory, cpu) in expected.items():
        cfg = config["services"][service]
        assert (cfg["mem_limit"], cfg["cpus"]) == (memory, cpu)
        assert cfg["networks"] == ["private"]
        if service != "web":
            assert "ports" not in cfg
    assert config["services"]["web"]["ports"] == ["127.0.0.1:18080:8000"]
    edge = yaml.safe_load((ROOT / "deploy/compose.edge.yaml").read_text())
    assert list(edge["services"]) == ["web"]
    assert edge["services"]["web"]["networks"]["secwatch-edge"]["aliases"] == ["secwatch-web"]


def test_health_no_store_and_no_connection_details(db, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", db.url.render_as_string(hide_password=False))
    response = TestClient(app).get("/api/v1/health")
    assert response.status_code == 200 and response.json() == {"status": "ok"}
    assert response.headers["Cache-Control"] == "no-store"
    monkeypatch.setenv("DATABASE_URL", "sqlite:////nonexistent-directory/db")
    response = TestClient(app).get("/api/v1/health")
    assert response.status_code == 503 and response.json() == {"status": "unavailable"}
