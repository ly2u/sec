"""Broadcast new public P0/P1 events to one Telegram channel.

Configured by TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID; without them the task
does nothing. The first run only records where to start, so enabling the
channel never floods it with history. Messages carry facts and a link only.
"""

import logging
import os
from types import SimpleNamespace
from urllib.parse import quote

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.server.models import IngestionState, Vulnerability, VulnerabilityEvent
from collector.store import telegram_events

logger = logging.getLogger(__name__)
# httpx logs request URLs at INFO; the Bot API URL contains the token.
logging.getLogger("httpx").setLevel(logging.WARNING)
SITE = "https://sec.ly2u.com"
API = "https://api.telegram.org"
STATE = "telegram"
PER_RUN = 20
TEXT = {
    "added_to_kev": "加入 CISA KEV：已确认被在野利用",
}
MARK = {"P0": "🔴", "P1": "🟠"}


def message(event, title):
    lines = [
        f"{MARK.get(event.priority, '')} {event.priority} {event.vulnerability_id}".strip(),
        TEXT.get(event.event_type, event.event_type),
    ]
    if title:
        lines.append(title[:200])
    lines.append(f"{SITE}/cve/{quote(event.vulnerability_id, safe='')}")
    return "\n".join(lines)


def broadcast(engine, token=None, chat=None, client=None):
    token = token if token is not None else os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat = chat if chat is not None else os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat:
        return {"skipped": "not-configured", "processed": 0, "completed": True}
    with Session(engine) as session, session.begin():
        state = session.get(IngestionState, STATE)
        if state is None:
            newest = session.scalar(select(func.max(VulnerabilityEvent.id))) or 0
            session.add(IngestionState(source=STATE, cursor={"last_event_id": newest}))
            return {"initialized": newest, "processed": 0, "completed": True}
        last = int((state.cursor or {}).get("last_event_id", 0))
        events = [
            SimpleNamespace(
                id=e.id,
                vulnerability_id=e.vulnerability_id,
                priority=e.priority,
                event_type=e.event_type,
            )
            for e in session.scalars(
                telegram_events()
                .where(VulnerabilityEvent.id > last)
                .order_by(VulnerabilityEvent.id)
                .limit(PER_RUN)
            )
        ]
        titles = dict(
            session.execute(
                select(Vulnerability.id, Vulnerability.title).where(
                    Vulnerability.id.in_([e.vulnerability_id for e in events])
                )
            ).all()
        )
    sent = 0
    own = client is None
    client = client or httpx.Client(timeout=20, follow_redirects=False)
    try:
        for event in events:
            try:
                response = client.post(
                    f"{API}/bot{token}/sendMessage",
                    json={
                        "chat_id": chat,
                        "text": message(event, titles.get(event.vulnerability_id)),
                        "disable_web_page_preview": True,
                    },
                )
            except httpx.HTTPError as error:
                # The exception text may include the URL, which contains the token.
                logger.warning("telegram send failed error=%s", type(error).__name__)
                break
            if response.status_code != 200:
                # Never log the URL: it contains the token.
                logger.warning("telegram send failed status=%s", response.status_code)
                break
            sent += 1
            last = event.id
    finally:
        if own:
            client.close()
    with Session(engine) as session, session.begin():
        state = session.get(IngestionState, STATE)
        state.cursor = {"last_event_id": last}
    # Unsent events stay pending; reporting incomplete lets the scheduler retry.
    return {"processed": sent, "pending": len(events) - sent, "completed": sent == len(events)}
