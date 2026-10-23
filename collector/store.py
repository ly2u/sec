import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from apps.server.models import KEVEntry, Vulnerability, VulnerabilityEvent


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def timestamp(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def upsert(session, model, rows, keys, *, do_nothing=False, update_where=None):
    if not rows:
        return
    insert = pg_insert if session.bind.dialect.name == "postgresql" else sqlite_insert
    statement = insert(model).values(rows)
    if do_nothing:
        statement = statement.on_conflict_do_nothing(index_elements=keys)
    else:
        columns = {key: getattr(statement.excluded, key) for key in rows[0] if key not in keys}
        condition = update_where(statement.excluded) if update_where else None
        statement = statement.on_conflict_do_update(
            index_elements=keys, set_=columns, where=condition
        )
    session.execute(statement)


def ensure_vulnerabilities(session, ids):
    # A KEV/EPSS-only ID has no CVE publication evidence; never fabricate PUBLISHED.
    rows = [
        {
            "id": value,
            "status": "UNKNOWN",
            "title": "",
            "description": "",
            "cwes": [],
            "adp_kev_flag": False,
            "cvss_metrics": [],
        }
        for value in sorted(set(ids))
    ]
    upsert(session, Vulnerability, rows, ["id"], do_nothing=True)


def event(session, vulnerability_id, event_type, revision, source, happened_at, payload, priority):
    upsert(
        session,
        VulnerabilityEvent,
        [
            {
                "vulnerability_id": vulnerability_id,
                "event_type": event_type,
                "dedup_key": digest([source, event_type, vulnerability_id, revision]),
                "source": source,
                "happened_at": happened_at,
                "priority": priority,
                "is_baseline": session.info.get("is_baseline", True),
                "payload": payload,
            }
        ],
        ["dedup_key"],
        do_nothing=True,
    )


def visible_vulnerabilities():
    return select(Vulnerability).where(Vulnerability.status == "PUBLISHED")


def visible_events():
    """Shared event scope for the future home page and RSS; bootstrap is never public."""
    return select(VulnerabilityEvent).where(VulnerabilityEvent.is_baseline.is_(False))


def telegram_events():
    return visible_events().where(VulnerabilityEvent.priority.in_(("P0", "P1")))


def kev_vulnerabilities():
    """KEV membership comes only from the active official catalog, never ADP flags."""
    return select(Vulnerability).join(KEVEntry).where(KEVEntry.is_active.is_(True))
