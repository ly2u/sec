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
    existing = set(
        session.scalars(select(KEVEntry.vulnerability_id).where(KEVEntry.vulnerability_id.in_(ids)))
    )
    ensure_vulnerabilities(session, ids)
    upsert(session, KEVEntry, records, ["vulnerability_id"])
    for row in records:
        if row["vulnerability_id"] not in existing:
            event(
                session,
                row["vulnerability_id"],
                "added_to_kev",
                "first-observed",
                "kev",
                datetime.combine(row["date_added"], time(), tzinfo=UTC),
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
        revision = str(feed["catalogVersion"])

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
                    "catalog_version": revision,
                    "record_hash": digest(row),
                }

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
        )
