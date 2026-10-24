"""Latest scanner release, published in manifest.json so old scanners can say
"a new version is available". The scanner only prints a hint; it never updates
itself, and installing still verifies the release signature (install.sh)."""

import os
import re
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from apps.server.models import IngestionState

SOURCE = "scanner:release"
TAG = re.compile(r"v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
REPO = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}")


def latest_url():
    repo = os.environ.get("SECWATCH_RELEASE_REPO", "ly2u/sec")
    if not REPO.fullmatch(repo):
        raise ValueError("Invalid SECWATCH_RELEASE_REPO")
    return f"https://api.github.com/repos/{repo}/releases/latest"


def check(http, engine):
    data = http.json(latest_url())
    tag = data.get("tag_name") if isinstance(data, dict) else None
    if (
        not isinstance(tag, str)
        or not TAG.fullmatch(tag)
        or data.get("draft")
        or data.get("prerelease")
    ):
        raise ValueError("Unexpected latest release")
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        state = session.get(IngestionState, SOURCE)
        changed = state is None or state.source_revision != tag
        if state is None:
            state = IngestionState(source=SOURCE, cursor={})
            session.add(state)
        state.source_revision = tag
        state.completed = state.has_completed = True
        state.last_success_at = state.updated_at = now
        state.last_error = None
    return {"source": SOURCE, "latest": tag, "processed": int(changed)}


def latest(session):
    """The recorded latest release tag, or None."""
    state = session.get(IngestionState, SOURCE)
    if state and state.source_revision and TAG.fullmatch(state.source_revision):
        return state.source_revision
    return None
