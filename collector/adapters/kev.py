from datetime import UTC, date, datetime, time

from sqlalchemy import select

from apps.server.models import KEVEntry
from collector.adapters.cvelist import CVE_ID
from collector.ingestion import ingest
from collector.store import digest, ensure_vulnerabilities, event, upsert

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def apply_entries(session, records):
    if not records:
        return
    ids = [record["vulnerability_id"] for record in records]
    existing = dict(
        session.execute(
            select(KEVEntry.vulnerability_id, KEVEntry.is_active).where(
                KEVEntry.vulnerability_id.in_(ids)
            )
        ).all()
    )
    ensure_vulnerabilities(session, ids)
    upsert(session, KEVEntry, records, ["vulnerability_id"])
    for row in records:
        cve_id = row["vulnerability_id"]
        if not existing.get(cve_id, False):
            event(
                session,
                row["vulnerability_id"],
                "added_to_kev",
                "first-observed" if cve_id not in existing else "readded:" + row["catalog_version"],
                "kev",
                datetime.combine(row["date_added"], time(), tzinfo=UTC)
                if cve_id not in existing
                else datetime.now(UTC),
                {
                    "date_added": row["date_added"].isoformat(),
                    "catalog_version": row["catalog_version"],
                    "source_url": KEV_URL,
                },
                "P0",
            )


class KEVAdapter:
    def __init__(self, http):
        self.http = http

    def run(self, engine, *, limit=1000, restart=False):
        feed = self.http.json(KEV_URL)
        if feed["count"] != len(feed["vulnerabilities"]):
            raise ValueError("KEV catalog count mismatch")
        catalog = str(feed["catalogVersion"])
        # CISA has republished a changed catalog under the same catalogVersion
        # (2026.10.23 gained CVE-2026-110447 hours after first release). The
        # ingest revision therefore follows the content, not the label.
        revision = f"{catalog}#{digest(feed['vulnerabilities'])[:16]}"

        def records():
            for row in feed["vulnerabilities"]:
                if not CVE_ID.fullmatch(row["cveID"]):
                    raise ValueError("Invalid CVE ID in KEV")
                yield {
                    "vulnerability_id": row["cveID"],
                    "date_added": date.fromisoformat(row["dateAdded"]),
                    "due_date": date.fromisoformat(row["dueDate"]) if row.get("dueDate") else None,
                    "vendor": row["vendorProject"],
                    "product": row["product"],
                    "name": row["vulnerabilityName"],
                    "description": row["shortDescription"],
                    "required_action": row["requiredAction"],
                    "ransomware": row.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": row.get("notes", ""),
                    "catalog_version": catalog,
                    "record_hash": digest(row),
                    "is_active": True,
                    "removed_at": None,
                }

        def finish(session):
            incoming = [row["cveID"] for row in feed["vulnerabilities"]]
            removed = session.scalars(
                select(KEVEntry).where(
                    KEVEntry.is_active.is_(True), KEVEntry.vulnerability_id.not_in(incoming)
                )
            )
            now = datetime.now(UTC)
            for row in removed:
                row.is_active = False
                row.removed_at = now
                event(
                    session,
                    row.vulnerability_id,
                    "removed_from_kev",
                    revision,
                    "kev",
                    now,
                    {"catalog_version": catalog, "source_url": KEV_URL},
                    "P2",
                )

        return ingest(
            engine,
            "kev",
            revision,
            records,
            apply_entries,
            limit=limit,
            restart=restart,
            metadata={"catalog_count": feed["count"]},
            http=self.http,
            finish=finish,
            restart_on_revision_change=True,
        )
