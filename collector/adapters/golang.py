"""Go vulnerability database (OSV "Go" export) for scanning Go-compiled programs.

Go programs embed their module list and Go version (``go version -m``), so a
scanner can match them without any package manager. Each row is one advisory
for one module (``stdlib`` is the Go standard library). Ranges are Go semver
without the leading "v", exactly as the Go vulndb publishes them.

The data is CC-BY-4.0 (https://go.dev/security/vuln/database#license); the
reference URL of every entry points back to pkg.go.dev.
"""

import io
import json
import re
import zipfile
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from apps.server.models import GoAdvisory
from collector.adapters.cvelist import CVE_ID
from collector.store import digest, upsert

ARCHIVE = "https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip"
SOURCE = "go-vulndb"
GO_ID = re.compile(r"GO-\d{4}-\d{4,6}")
# Module paths as the Go toolchain allows them, plus the stdlib pseudo-module.
MODULE = re.compile(r"stdlib|[a-z0-9][A-Za-z0-9._~-]*(?:/[A-Za-z0-9._~+-]+)*")
SEMVER = re.compile(r"0|[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_FILE = 512 * 1024


def ranges_of(affected):
    """SEMVER ranges of one affected module, or None if anything is unclear."""
    out = []
    for r in affected.get("ranges") or []:
        if r.get("type") != "SEMVER":
            return None
        events = []
        for e in r.get("events") or []:
            if not isinstance(e, dict) or len(e) != 1:
                return None
            ((kind, value),) = e.items()
            if kind not in ("introduced", "fixed", "last_affected") or not (
                isinstance(value, str) and SEMVER.fullmatch(value)
            ):
                return None
            events.append({kind: value})
        if events:
            out.append({"type": "SEMVER", "events": events})
    return out or None


def record_rows(record):
    """upsert rows for one OSV Go record: one per affected module."""
    gid = record.get("id", "")
    if not GO_ID.fullmatch(gid) or record.get("withdrawn"):
        return []
    cves = sorted({a for a in record.get("aliases") or [] if CVE_ID.fullmatch(a)})
    ref = f"https://pkg.go.dev/vuln/{gid}"
    rows = []
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        module = package.get("name", "")
        # "toolchain" is the go command itself, not code inside compiled programs.
        if package.get("ecosystem") != "Go" or module == "toolchain":
            continue
        if not isinstance(module, str) or len(module) > 300 or not MODULE.fullmatch(module):
            continue
        ranges = ranges_of(affected)
        if ranges is None:
            continue
        body = {"module": module, "cve": cves, "ranges": ranges}
        rows.append(
            {
                "id": f"{gid}:{module}",
                "vuln_id": gid,
                "module": module,
                "cve_ids": cves,
                "ranges": ranges,
                "ref": ref,
                "record_hash": digest(body),
                "updated_at": datetime.now(UTC),
            }
        )
    return rows


def parse_archive(data):
    """Yield OSV records from the all.zip export."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.endswith(".json") or "/" in info.filename:
                continue
            if info.file_size > MAX_FILE:
                continue
            yield json.loads(archive.read(info))


class GoAdapter:
    def __init__(self, http):
        self.http = http

    def run(self, engine):
        data = self.http.read(ARCHIVE, max_bytes=MAX_ARCHIVE)
        rows = {}
        records = 0
        for record in parse_archive(data):
            records += 1
            for row in record_rows(record):
                rows[row["id"]] = row
        if not rows:
            raise ValueError("Go vulnerability archive contained no usable entries")
        with Session(engine) as session, session.begin():
            old = {r.id: r.record_hash for r in session.scalars(select(GoAdvisory))}
            changed = [r for r in rows.values() if old.get(r["id"]) != r["record_hash"]]
            gone = set(old) - set(rows)
            if gone:
                session.execute(delete(GoAdvisory).where(GoAdvisory.id.in_(gone)))
            for offset in range(0, len(changed), 1000):
                upsert(session, GoAdvisory, changed[offset : offset + 1000], ["id"])
        return {
            "source": SOURCE,
            "records": records,
            "entries": len(rows),
            "processed": len(changed) + len(gone),
        }
