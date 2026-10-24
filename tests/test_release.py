import json
import shutil
from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session

from collector.bundles import run_minisign
from collector.http import FeedHTTP
from collector.release import check, latest, latest_url

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


def http_for(body):
    def handler(request):
        assert str(request.url) == "https://api.github.com/repos/ly2u/sec/releases/latest"
        return httpx.Response(200, json=body)

    return FeedHTTP(httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)


def test_latest_release_is_recorded_once(db):
    assert check(http_for({"tag_name": "v0.1.4"}), db) == {
        "source": "scanner:release",
        "latest": "v0.1.4",
        "processed": 1,
    }
    assert check(http_for({"tag_name": "v0.1.4"}), db)["processed"] == 0
    with Session(db) as session:
        assert latest(session) == "v0.1.4"


@pytest.mark.parametrize(
    "body",
    [
        {"tag_name": "v0.1.4; rm -rf /"},
        {"tag_name": "latest"},
        {"tag_name": "v0.2.0", "prerelease": True},
        {"tag_name": "v0.2.0", "draft": True},
        ["v0.1.4"],
    ],
)
def test_unexpected_release_is_rejected(db, body):
    with pytest.raises(ValueError):
        check(http_for(body), db)
    with Session(db) as session:
        assert latest(session) is None


def test_repo_override_is_validated(monkeypatch):
    monkeypatch.setenv("SECWATCH_RELEASE_REPO", "ly2u/sec/../../x")
    with pytest.raises(ValueError):
        latest_url()


def test_manifest_carries_latest_without_rebuilding_bundles(db, tmp_path, signing):
    from collector.bundles import generate

    binary, secret, public = signing
    out = tmp_path / "bundles"
    first = generate(db, out, secret, public, binary=binary)
    assert first["rebuilt"]
    check(http_for({"tag_name": "v0.1.4"}), db)
    again = generate(db, out, secret, public, binary=binary)
    assert again["rebuilt"] == []  # a release is not a data change
    manifest = json.loads((out / "manifest.json").read_bytes())
    assert manifest["scanner"] == {"latest": "v0.1.4"}
