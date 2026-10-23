import json
import logging
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath

from sqlalchemy import select
from stream_unzip import stream_unzip

from apps.server.models import Vulnerability
from collector.cvss import assessments
from collector.ingestion import ingest, state_for
from collector.store import digest, event, timestamp, upsert

CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=5"
DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
logger = logging.getLogger(__name__)


def record_url(cve_id):
    if not CVE_ID.fullmatch(cve_id):
        raise ValueError("Invalid CVE ID")
    _, year, number = cve_id.split("-")
    return f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{number[:-3]}xxx/{cve_id}.json"


def zip_records(chunks, depth=0):
    if depth > 2:
        raise ValueError("Excessive nested ZIP depth")
    for filename, _size, contents in stream_unzip(chunks):
        name = PurePosixPath(filename.decode("utf-8"))
        if name.suffix == ".zip":
            yield from zip_records(contents, depth + 1)
        elif name.suffix == ".json" and CVE_ID.fullmatch(name.stem):
            payload = bytearray()
            for chunk in contents:
                payload.extend(chunk)
                if len(payload) > 4 * 1024 * 1024:
                    raise ValueError("Oversized CVE record")
            yield json.loads(payload)
        else:
            for _ in contents:
                pass


def normalize(record):
    metadata = record["cveMetadata"]
    cve_id, state = metadata["cveId"], metadata["state"]
    if not CVE_ID.fullmatch(cve_id) or state not in ("PUBLISHED", "REJECTED", "RESERVED"):
        raise ValueError("Invalid CVE metadata")
    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    adp = [
        item
        for item in containers.get("adp", [])
        if item.get("providerMetadata", {}).get("shortName", "").upper().startswith("CISA")
    ]
    facts = {**assessments(cna, containers.get("adp", [])), "ssvc": None, "adp_kev_flag": False}
    cwes = set()
    for container in [cna, *adp]:
        for metric in container.get("metrics", []):
            other = metric.get("other", {})
            if other.get("type", "").lower() == "ssvc":
                facts["ssvc"] = other.get("content")
            if container in adp and other.get("type", "").lower() in ("kev", "cisa_kev"):
                facts["adp_kev_flag"] = True
        for problem in container.get("problemTypes", []):
            for description in problem.get("descriptions", []):
                cwes.update(
                    re.findall(
                        r"CWE-\d+",
                        description.get("cweId", "") + " " + description.get("description", ""),
                    )
                )
        for reference in container.get("references", []):
            if container in adp and any(
                "known-exploited-vulnerabilities" in str(tag).lower()
                for tag in reference.get("tags", [])
            ):
                facts["adp_kev_flag"] = True
    descriptions = (
        cna.get("rejectedReasons", []) if state == "REJECTED" else cna.get("descriptions", [])
    )
    text = next((x["value"] for x in descriptions if x.get("lang", "").startswith("en")), "")
    return {
        "id": cve_id,
        "status": state,
        "title": cna.get("title", ""),
        "description": text,
        "published_at": timestamp(metadata.get("datePublished")),
        "modified_at": timestamp(metadata.get("dateUpdated") or metadata.get("dateRejected")),
        **facts,
        "cwes": sorted(cwes),
        "cisa_adp": {"containers": adp} if adp else None,
        "source_url": f"https://www.cve.org/CVERecord?id={cve_id}",
        "record_hash": digest(record),
        "raw_record": record,
    }


def apply_records(session, records):
    rows = [normalize(record) for record in records]
    if not rows:
        return
    columns = (
        Vulnerability.id,
        Vulnerability.status,
        Vulnerability.record_hash,
        Vulnerability.modified_at,
        Vulnerability.cvss,
        Vulnerability.severity,
        Vulnerability.cvss_metrics,
    )
    existing = {
        row["id"]: dict(row)
        for row in session.execute(
            select(*columns).where(Vulnerability.id.in_([row["id"] for row in rows]))
        ).mappings()
    }
    pending = {}
    events = []
    for row in rows:
        old = existing.get(row["id"])
        if (
            old
            and old["record_hash"] == row["record_hash"]
            and old["cvss_metrics"] == row["cvss_metrics"]
        ):
            continue
        if old and old["modified_at"] and row["modified_at"]:
            previous = (
                old["modified_at"].replace(tzinfo=UTC)
                if old["modified_at"].tzinfo is None
                else old["modified_at"]
            )
            if row["modified_at"] < previous:
                continue
        if (
            old
            and old["record_hash"]
            and (old["severity"], old["cvss"]) != (row["severity"], row["cvss"])
        ):
            events.append(
                (
                    row["id"],
                    "severity_changed",
                    row["record_hash"],
                    "cvelistV5",
                    row["modified_at"] or datetime.now(UTC),
                    {
                        "before": {"severity": old["severity"], "cvss": old["cvss"]},
                        "after": {"severity": row["severity"], "cvss": row["cvss"]},
                    },
                    "P2",
                )
            )
        if old and old["status"] != "REJECTED" and row["status"] == "REJECTED":
            events.append(
                (
                    row["id"],
                    "rejected",
                    row["record_hash"],
                    "cvelistV5",
                    row["modified_at"] or datetime.now(UTC),
                    {"reason": row["description"]},
                    "P3",
                )
            )
        pending[row["id"]] = row
        existing[row["id"]] = row
    # One lookup and one upsert per batch; avoid per-record round trips on the full corpus.
    upsert(session, Vulnerability, list(pending.values()), ["id"])
    for values in events:
        event(session, *values)


class CVEAdapter:
    def __init__(self, http):
        self.http = http

    def baseline(self, engine, *, limit=1000, restart=False, url=None):
        state = state_for(engine, "cve:baseline")
        if not url and state and not restart and not state["completed"]:
            url, revision = state["cursor"]["url"], state["revision"]
        else:
            revision = url
        if not url:
            releases = self.http.json(RELEASES)
            asset = next(
                asset
                for release in releases
                for asset in release["assets"]
                if "all_CVEs_at_midnight.zip" in asset["name"]
            )
            url = asset["browser_download_url"]
            revision = asset.get("digest") or f"{asset['name']}:{asset['size']}"

        def records():
            with self.http.stream(url) as chunks:
                yield from zip_records(chunks)

        return ingest(
            engine,
            "cve:baseline",
            revision,
            records,
            apply_records,
            limit=limit,
            restart=restart,
            metadata={"url": url},
            http=self.http,
        )

    def delta(self, engine, *, limit=1000, restart=False, since=None):
        log = self.http.json(DELTA_LOG)
        if not isinstance(log, list) or not log:
            raise ValueError("Invalid official delta log")
        state = state_for(engine, "cve:delta")
        since = (
            state["cursor"].get("fetch_time")
            if state and state["completed"] and not restart
            else since
        )
        if not state and not since:
            baseline = state_for(engine, "cve:baseline")
            pinned = baseline["cursor"].get("url", "") if baseline else ""
            boundary = re.search(r"(\d{4}-\d{2}-\d{2})_all_CVEs_at_midnight", pinned)
            if baseline and (baseline["completed"] or baseline["has_completed"]) and boundary:
                since = boundary[1] + "T00:00:00Z"
            else:
                raise ValueError(
                    "Initial delta requires --since; do not silently skip baseline history"
                )
        # Do not silently bridge a gap outside the official rolling log's coverage.
        if since and timestamp(since) < min(timestamp(entry["fetchTime"]) for entry in log):
            raise ValueError("Delta watermark expired; a new baseline is required")
        if state and not state["completed"] and not restart:
            entries = state["cursor"]["entries"]
            newest = state["cursor"]["fetch_time"]
            warnings = state["cursor"].get("warnings", [])
        else:
            selected = [
                entry
                for entry in log
                if not since or timestamp(entry["fetchTime"]) > timestamp(since)
            ]
            if not selected:
                return {"source": "cve:delta", "processed": 0, "completed": True}
            # Latest fetched document wins if an ID occurs in several delta intervals.
            unique = {}
            warnings = list(state["cursor"].get("warnings", [])) if state and not restart else []
            for entry in sorted(selected, key=lambda item: timestamp(item["fetchTime"])):
                if entry.get("error"):
                    logger.warning(
                        "Official delta entry at %s contains source errors; processing its remaining records",
                        entry["fetchTime"],
                    )
                    if entry not in warnings:
                        warnings.append(entry)
                for item in entry.get("new", []) + entry.get("updated", []):
                    unique[item["cveId"]] = item
            entries = sorted(unique)
            newest = max(selected, key=lambda item: timestamp(item["fetchTime"]))["fetchTime"]

        def records():
            for cve_id in entries:
                yield self.http.json(record_url(cve_id))

        return ingest(
            engine,
            "cve:delta",
            newest,
            records,
            apply_records,
            limit=limit,
            restart=restart,
            metadata={"entries": entries, "fetch_time": newest, "warnings": warnings},
            http=self.http,
        )
