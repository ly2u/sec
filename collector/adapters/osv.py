"""Pinned full OSV exports and watermarked, descending modified_id.csv updates."""

import csv
import io
import json
import logging
import re
from datetime import UTC, datetime
from functools import partial
from pathlib import PurePosixPath
from urllib.parse import quote

from sqlalchemy import delete, select
from stream_unzip import stream_unzip

from apps.server.models import AffectedPackage, OSVAdvisory, VulnerabilityAlias, VulnerabilityEvent
from collector.adapters.cvelist import CVE_ID
from collector.adapters.epss import ChunkReader
from collector.distros import BASES, PACKAGE_KEYS, PACKAGE_NAME, VERSION, coordinate
from collector.ingestion import ingest, state_for
from collector.store import digest, ensure_vulnerabilities, timestamp, upsert

ROOT = "https://storage.googleapis.com/osv-vulnerabilities/"
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._+-]{0,127}")
logger = logging.getLogger(__name__)


def url(base, name):
    if base not in BASES or not (
        name in ("all.zip", "modified_id.csv") or ID.fullmatch(name.removesuffix(".json"))
    ):
        raise ValueError("Invalid OSV object")
    return ROOT + quote(base, safe="") + "/" + quote(name, safe="")


def cve_ids(record, affected=None):
    scoped = ((affected or {}).get("database_specific") or {}).get("cves_map")
    if scoped is not None:
        return sorted({row["id"] for row in scoped.get("cves", []) if CVE_ID.fullmatch(row["id"])})
    candidates = record.get("upstream", []) + record.get("aliases", [])
    values = {v for v in candidates if CVE_ID.fullmatch(v)}
    if not values:
        wrapped = re.fullmatch(r"(?:DEBIAN|UBUNTU|ALPINE)-(CVE-\d{4}-\d{4,})", record["id"])
        if wrapped:
            values.add(wrapped[1])
    # Alma's upstream explicitly uses related for CVE links; preserve association, not identity.
    if record["id"].startswith("ALSA-"):
        values.update(v for v in record.get("related", []) if CVE_ID.fullmatch(v))
    return sorted(values)


def package_rows(record, base):
    if record.get("withdrawn") or record["id"].startswith("LSN-"):
        return []
    result = []
    for affected in record.get("affected", []):
        package = affected["package"]
        location = coordinate(package["ecosystem"])
        if not location:
            continue
        distro, release, subscription = location
        if BASES[base] != distro:
            raise ValueError("OSV export contains another distro")
        if not PACKAGE_NAME.fullmatch(package["name"]):
            raise ValueError("Unsafe package name")
        ranges = affected.get("ranges", [])
        if any(r["type"] != "ECOSYSTEM" for r in ranges):
            raise ValueError("Unexpected distro range type")
        for r in ranges:
            for e in r["events"]:
                if (
                    len(e) != 1
                    or next(iter(e)) not in ("introduced", "fixed", "last_affected", "limit")
                    or not VERSION.fullmatch(next(iter(e.values())))
                ):
                    raise ValueError("Invalid distro version event")
        fixed = [e["fixed"] for r in ranges for e in r["events"] if "fixed" in e]
        open_range = any(r.get("events") and "introduced" in r["events"][-1] for r in ranges)
        raw_status = (affected.get("ecosystem_specific") or {}).get("status")
        status = (
            "wont_fix"
            if raw_status in ("no-dsa", "ignored", "wont-fix")
            else ("fixed" if fixed and not open_range else "unfixed")
        )
        ids = cve_ids(record, affected)
        owner = ids[0] if len(ids) == 1 else record["id"]
        metadata = {
            "cve_ids": ids,
            "aliases": record.get("aliases", []),
            "purl": package.get("purl"),
            "versions": affected.get("versions", []) if not ranges else [],
            "ecosystem_specific": {
                key: value
                for key, value in (affected.get("ecosystem_specific") or {}).items()
                if key in ("availability", "urgency", "status")
            },
            "database_specific": {
                "source": (affected.get("database_specific") or {}).get("source")
            },
        }
        row = {
            "vulnerability_id": owner,
            "ecosystem": package["ecosystem"],
            "distro": distro,
            "release": release,
            "package_name": package["name"],
            "source_package": package["name"]
            if PACKAGE_KEYS[distro] in ("source", "origin")
            else None,
            "ranges": ranges,
            "status": status,
            "fixed_version": fixed[-1] if fixed else None,
            "source": "osv:" + base,
            "source_url": next(
                (ref["url"] for ref in record.get("references", []) if ref["type"] == "ADVISORY"),
                "https://osv.dev/vulnerability/" + quote(record["id"], safe=""),
            ),
            "advisory_id": record["id"],
            "package_key": PACKAGE_KEYS[distro],
            "requires_subscription": subscription
            or "subscription required"
            in metadata["ecosystem_specific"].get("availability", "").lower()
            and "No subscription" not in metadata["ecosystem_specific"].get("availability", ""),
            "source_metadata": metadata,
        }
        row["entry_hash"] = digest(row)
        result.append(row)
    return list({row["entry_hash"]: row for row in result}.values())


def apply_records(session, records, base):
    if not records:
        return
    old = {
        row.id: row
        for row in session.scalars(
            select(OSVAdvisory).where(OSVAdvisory.id.in_([r["id"] for r in records]))
        )
    }
    changed = []
    for record in records:
        if not ID.fullmatch(record["id"]):
            raise ValueError("Invalid OSV ID")
        previous = old.get(record["id"])
        if previous and (
            previous.record_hash == digest(record)
            or timestamp(record["modified"]) < timestamp(previous.modified_at.isoformat())
        ):
            continue
        changed.append(record)
    if not changed:
        return
    normalized = [row for record in changed for row in package_rows(record, base)]
    ensure_vulnerabilities(
        session,
        [row["vulnerability_id"] for row in normalized] + [v for r in changed for v in cve_ids(r)],
    )
    upsert(
        session,
        OSVAdvisory,
        [
            {
                "id": r["id"],
                "ecosystem": base,
                "modified_at": timestamp(r["modified"]),
                "withdrawn_at": timestamp(r.get("withdrawn")),
                "record_hash": digest(r),
                "raw_record": r,
            }
            for r in changed
        ],
        ["id"],
    )
    ids = [r["id"] for r in changed]
    existing = list(
        session.scalars(select(AffectedPackage).where(AffectedPackage.advisory_id.in_(ids)))
    )
    known = {row.entry_hash for row in existing}
    session.execute(delete(AffectedPackage).where(AffectedPackage.advisory_id.in_(ids)))
    for offset in range(0, len(normalized), 300):
        upsert(
            session,
            AffectedPackage,
            normalized[offset : offset + 300],
            ["vulnerability_id", "source", "entry_hash"],
        )
    aliases = []
    for record in changed:
        identity = cve_ids(record)
        if len(identity) == 1:
            aliases.append(
                {"vulnerability_id": identity[0], "alias": record["id"], "source": "osv"}
            )
    upsert(session, VulnerabilityAlias, aliases, ["vulnerability_id", "alias"], do_nothing=True)
    events = []
    for row in normalized:
        if row["entry_hash"] not in known and row["fixed_version"]:
            revision = digest(
                [
                    row["advisory_id"],
                    row["ecosystem"],
                    row["package_name"],
                    row["ranges"],
                    row["requires_subscription"],
                ]
            )
            events.append(
                {
                    "vulnerability_id": row["vulnerability_id"],
                    "event_type": "fixed_version_published",
                    "dedup_key": digest(
                        ["osv", "fixed_version_published", row["vulnerability_id"], revision]
                    ),
                    "source": "osv",
                    "happened_at": datetime.now(UTC),
                    "priority": "P2",
                    "is_baseline": session.info.get("is_baseline", True),
                    "payload": {
                        "distro": row["distro"],
                        "release": row["release"],
                        "package": row["package_name"],
                        "fixed_version": row["fixed_version"],
                        "requires_subscription": row["requires_subscription"],
                        "source_url": row["source_url"],
                    },
                }
            )
    for offset in range(0, len(events), 300):
        upsert(
            session,
            VulnerabilityEvent,
            events[offset : offset + 300],
            ["dedup_key"],
            do_nothing=True,
        )


class OSVAdapter:
    def __init__(self, http):
        self.http = http

    def baseline(self, engine, base, *, limit=1000, restart=False):
        ecosystems = self.http.read(ROOT + "ecosystems.txt", max_bytes=65536).decode().splitlines()
        if base not in ecosystems or base not in BASES:
            raise ValueError("OSV ecosystem not exported")
        state = state_for(engine, "osv:" + base)
        if state and not state["completed"] and not restart:
            pinned = state["cursor"]["url"]
            revision = state["revision"]
        else:
            headers = self.http.headers(url(base, "all.zip"))
            generation = headers.get("x-goog-generation")
            if not generation:
                raise ValueError("OSV generation missing; refusing unpinned baseline")
            pinned = url(base, "all.zip") + "?generation=" + generation
            revision = generation
        # The initial delta reconciles the complete CSV with stored revisions, so an
        # independently exported ZIP/CSV cannot introduce a bootstrap race.
        watermark = (
            state["cursor"]["watermark"]
            if state and not restart and not state["completed"]
            else self.latest_modified(base)
        )

        def records():
            with self.http.stream(pinned) as chunks:
                for name, _size, contents in stream_unzip(chunks):
                    if PurePosixPath(name.decode()).suffix != ".json":
                        for _ in contents:
                            pass
                        continue
                    data = bytearray()
                    for chunk in contents:
                        data.extend(chunk)
                        if len(data) > 32 * 1024 * 1024:
                            raise ValueError("Oversized OSV record")
                    yield json.loads(data)

        return ingest(
            engine,
            "osv:" + base,
            revision,
            records,
            partial(apply_records, base=base),
            limit=limit,
            restart=restart,
            metadata={"url": pinned, "watermark": watermark},
            http=self.http,
            batch_size=25,
        )

    def modified(self, base):
        with self.http.stream(url(base, "modified_id.csv")) as chunks:
            with io.TextIOWrapper(
                io.BufferedReader(ChunkReader(chunks)), encoding="utf-8", newline=""
            ) as stream:
                for row in csv.reader(stream):
                    if len(row) != 2 or not ID.fullmatch(row[1]):
                        raise ValueError("Invalid OSV modified CSV")
                    timestamp(row[0])
                    yield row

    def latest_modified(self, base):
        rows = self.modified(base)
        try:
            return next(rows)[0]
        finally:
            rows.close()

    def delta(self, engine, base, *, limit=None):
        baseline = state_for(engine, "osv:" + base)
        if not baseline or not baseline["completed"]:
            return self.baseline(engine, base, limit=limit)
        source = "osv:delta:" + base
        state = state_for(engine, source)
        if state and not state["completed"]:
            entries = state["cursor"]["entries"]
            newest = state["revision"]
        else:
            watermark = state["revision"] if state else None
            entries = []
            newest = watermark or baseline["cursor"]["watermark"]
            inventory = []
            for modified, id in self.modified(base):
                if watermark and timestamp(modified) <= timestamp(watermark):
                    break
                if not entries and not inventory:
                    newest = modified
                if watermark:
                    entries.append(id)
                else:
                    inventory.append((modified, id))
            if inventory:
                from sqlalchemy.orm import Session

                with Session(engine) as session:
                    for offset in range(0, len(inventory), 1000):
                        batch = inventory[offset : offset + 1000]
                        known = dict(
                            session.execute(
                                select(OSVAdvisory.id, OSVAdvisory.modified_at).where(
                                    OSVAdvisory.id.in_([id for _, id in batch])
                                )
                            ).all()
                        )
                        entries.extend(
                            id
                            for modified, id in batch
                            if id not in known
                            or timestamp(modified) > timestamp(known[id].isoformat())
                        )
            if not entries and state:
                return {"source": source, "processed": 0, "completed": True}

        def records():
            for id in entries:
                yield self.http.json(url(base, id + ".json"))

        return ingest(
            engine,
            source,
            newest,
            records,
            partial(apply_records, base=base),
            limit=limit,
            metadata={"entries": entries, "watermark": newest},
            http=self.http,
        )
