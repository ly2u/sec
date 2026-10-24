import copy
import io
import json
import zipfile
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from apps.server.models import GoAdvisory
from collector.adapters.golang import ARCHIVE, GoAdapter, ranges_of, record_rows
from collector.bundles import golang_entries, package_key
from collector.http import FeedHTTP

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "golang" / "GO-2023-2102.json").read_text()
)


def test_record_rows_one_per_module_and_toolchain_skipped():
    rows = {r["module"]: r for r in record_rows(FIXTURE)}
    assert set(rows) == {"stdlib", "golang.org/x/net"}
    std = rows["stdlib"]
    assert std["id"] == "GO-2023-2102:stdlib" and std["cve_ids"] == ["CVE-2023-39325"]
    assert std["ranges"][0]["events"][2] == {"introduced": "1.21.0-0"}
    assert std["ref"] == "https://pkg.go.dev/vuln/GO-2023-2102"


def test_unclear_or_unsafe_records_are_skipped():
    withdrawn = dict(FIXTURE, withdrawn="2024-01-01T00:00:00Z")
    assert record_rows(withdrawn) == []
    assert record_rows(dict(FIXTURE, id="../etc")) == []
    odd = copy.deepcopy(FIXTURE)
    odd["affected"][0]["package"]["name"] = "evil module; rm -rf /"
    odd["affected"][1]["ranges"][0]["events"][1] = {"fixed": "0.17.0; rm"}
    assert record_rows(odd) == []
    assert ranges_of({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}) is None


def archive(records):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(r["id"] + ".json", json.dumps(r))
        z.writestr("nested/ignored.json", "{}")
    return buf.getvalue()


def http_for(payload):
    def handler(request):
        assert str(request.url) == ARCHIVE
        return httpx.Response(200, content=payload)

    return FeedHTTP(httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)


def test_adapter_full_replace_and_bundle_entries(db):
    other = copy.deepcopy(FIXTURE)
    other["id"] = "GO-2024-0001"
    other["affected"] = [FIXTURE["affected"][1]]
    result = GoAdapter(http_for(archive([FIXTURE, other]))).run(db)
    assert result == {"source": "go-vulndb", "records": 2, "entries": 3, "processed": 3}
    assert GoAdapter(http_for(archive([FIXTURE, other]))).run(db)["processed"] == 0
    # The second advisory disappears upstream: its row is removed.
    assert GoAdapter(http_for(archive([FIXTURE]))).run(db)["processed"] == 1
    with Session(db) as session:
        assert session.get(GoAdvisory, "GO-2024-0001:golang.org/x/net") is None
        entries = list(golang_entries(session))
    assert [m for m, _ in entries] == ["golang.org/x/net", "stdlib"]
    module, entry = entries[1]
    assert entry["id"] == "CVE-2023-39325" and entry["advisory_id"] == "GO-2023-2102"
    assert entry["fixes"] == [
        {"version": "1.20.10", "requires_subscription": False},
        {"version": "1.21.3", "requires_subscription": False},
    ]
    assert entry["ranges"][0]["type"] == "SEMVER" and package_key("golang") == "module"
