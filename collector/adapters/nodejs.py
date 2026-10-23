"""Node.js security working group core vulnerability database.

Node.js bundles dependencies (OpenSSL, Brotli, llhttp, undici…) whose CVEs are
filed under other vendors and never name Node.js, so CVE records alone cannot
tell which Node.js releases are affected. The working group publishes one JSON
file per issue with semver 'vulnerable'/'patched' ranges. Its index.json lags
behind, so the individual files are read.
"""

import io
import json
import re
import tarfile
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from apps.server.models import UpstreamAdvisory
from collector.store import digest, upsert
from collector.upstream import node_ranges

ARCHIVE = "https://codeload.github.com/nodejs/security-wg/tar.gz/refs/heads/main"
SOURCE = "nodejs-security-wg"
MEMBER = re.compile(r"[^/]+/vuln/core/([0-9]{1,5})\.json")
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
SEVERITY = {"low", "medium", "high", "critical"}
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_FILE = 256 * 1024


def entry_row(number, entry):
    """One upstream_advisories row from a security-wg file, or None if unusable."""
    ranges, ok = node_ranges(entry.get("vulnerable"), entry.get("patched"))
    if not ok:
        return None
    cves = [c for c in entry.get("cve") or [] if isinstance(c, str) and CVE.fullmatch(c)]
    ref = entry.get("ref") or ""
    parsed = urlsplit(ref) if isinstance(ref, str) else None
    if not parsed or parsed.scheme != "https" or not parsed.hostname:
        ref = f"https://github.com/nodejs/security-wg/blob/main/vuln/core/{number}.json"
    severity = (entry.get("severity") or "").strip().lower()
    body = {"cve": cves, "ranges": ranges, "severity": severity, "ref": ref}
    return {
        "id": f"nodejs:node:{number}",
        "product": "node",
        "source": SOURCE,
        "vulnerability_id": cves[0] if cves else None,
        "cve_ids": cves,
        "ranges": ranges,
        "severity": severity if severity in SEVERITY else None,
        "ref": ref,
        "record_hash": digest(body),
        "updated_at": datetime.now(UTC),
    }


def parse_archive(data):
    """Yield (number, entry) for every core vulnerability file in the tarball."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            match = MEMBER.fullmatch(member.name)
            if not match or not member.isfile() or member.size > MAX_FILE:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            yield int(match.group(1)), json.loads(handle.read())


class NodejsAdapter:
    def __init__(self, http):
        self.http = http

    def run(self, engine, *, limit=None):
        data = self.http.read(ARCHIVE, max_bytes=MAX_ARCHIVE)
        rows, skipped = [], 0
        for number, entry in parse_archive(data):
            row = entry_row(number, entry)
            if row is None:
                skipped += 1
            else:
                rows.append(row)
        if not rows:
            raise ValueError("Node.js security-wg archive contained no usable entries")
        with Session(engine) as session, session.begin():
            old = {
                r.id: r.record_hash
                for r in session.scalars(
                    select(UpstreamAdvisory).where(UpstreamAdvisory.source == SOURCE)
                )
            }
            changed = [r for r in rows if old.get(r["id"]) != r["record_hash"]]
            gone = set(old) - {r["id"] for r in rows}
            if gone:
                session.execute(delete(UpstreamAdvisory).where(UpstreamAdvisory.id.in_(gone)))
            if changed:
                upsert(session, UpstreamAdvisory, changed, ["id"])
        return {
            "source": SOURCE,
            "entries": len(rows),
            "skipped": skipped,
            "processed": len(changed) + len(gone),
        }
