import logging
from datetime import UTC, datetime

import httpx
from sqlalchemy.orm import Session

from apps.server.models import IngestionState

logger = logging.getLogger(__name__)


def state_for(engine, source):
    with Session(engine) as session:
        state = session.get(IngestionState, source)
        return (
            {
                "revision": state.source_revision,
                "cursor": state.cursor,
                "completed": state.completed,
                "has_completed": state.has_completed,
            }
            if state
            else None
        )


def ingest(
    engine,
    source,
    revision,
    factory,
    apply_batch,
    *,
    limit=1000,
    batch_size=100,
    restart=False,
    metadata=None,
    http=None,
    finish=None,
    restart_on_revision_change=False,
):
    """Commit data and the record offset together; replay a pinned stream on failure.

    Resumption is record-based, not byte-range resumption of ZIP compression state.
    An interrupted uncommitted batch is replayed; committed rows are skipped.
    """
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    with Session(engine) as session, session.begin():
        state = session.get(IngestionState, source)
        if state and state.source_revision == revision and state.completed and not restart:
            return {
                "source": source,
                "processed": 0,
                "offset": state.records_processed,
                "completed": True,
            }
        if state and state.source_revision != revision and not state.completed and not restart:
            if not restart_on_revision_change:
                raise ValueError(
                    "Incomplete snapshot changed; resume the pinned source or use --restart"
                )
            logger.warning(
                "%s revision changed during incomplete import; automatically restarting from record zero",
                source,
            )
            restart = True
        has_completed = bool(state and (state.has_completed or state.completed))
        if state is None:
            state = IngestionState(source=source)
            session.add(state)
        if restart or state.source_revision != revision:
            state.cursor = {**(metadata or {}), "offset": 0, "is_baseline": not has_completed}
            state.records_processed = 0
        else:
            state.cursor = {
                **state.cursor,
                "is_baseline": state.cursor.get("is_baseline", not has_completed),
            }
        state.has_completed = has_completed
        state.source_revision = revision
        state.completed = False
        state.last_error = None
        initial_offset = state.records_processed

    def commit(batch, position, completed=False):
        with Session(engine) as session, session.begin():
            state = session.get(IngestionState, source)
            session.info["is_baseline"] = state.cursor["is_baseline"]
            apply_batch(session, batch)
            if completed and finish:
                finish(session)
            state.cursor = {**state.cursor, "offset": position}
            state.records_processed = position
            state.completed = completed
            state.has_completed = state.has_completed or completed
            state.last_error = None
            state.last_success_at = datetime.now(UTC)
            state.updated_at = datetime.now(UTC)
        if position % 1000 == 0 or completed:
            logger.info("%s checkpoint offset=%d completed=%s", source, position, completed)

    for attempt in range(4):
        state = state_for(engine, source)
        offset = state["cursor"]["offset"]
        accepted = offset - initial_offset
        batch = []
        position = offset
        iterator = iter(factory())
        try:
            exhausted = True
            for index, record in enumerate(iterator):
                if index < offset:
                    continue
                if limit is not None and accepted >= limit:
                    exhausted = False
                    break
                batch.append(record)
                position = index + 1
                accepted += 1
                if len(batch) >= batch_size:
                    commit(batch, position)
                    batch = []
            commit(batch, position, completed=exhausted)
            return {
                "source": source,
                "processed": position - initial_offset,
                "offset": position,
                "completed": exhausted,
            }
        except Exception as error:
            with Session(engine) as session, session.begin():
                session.get(IngestionState, source).last_error = type(error).__name__
            if not isinstance(error, httpx.TransportError) or attempt == 3:
                raise
            if http:
                http.backoff(attempt)
        finally:
            close = getattr(iterator, "close", None)
            if close:
                close()
    raise RuntimeError("Unreachable retry exhaustion")
