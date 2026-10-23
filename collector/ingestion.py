from datetime import UTC, datetime

import httpx
from sqlalchemy.orm import Session

from apps.server.models import IngestionState


def state_for(engine, source):
    with Session(engine) as session:
        state = session.get(IngestionState, source)
        return (
            {
                "revision": state.source_revision,
                "cursor": state.cursor,
                "completed": state.completed,
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
            raise ValueError(
                "Incomplete snapshot changed; resume the pinned source or use --restart"
            )
        if state is None:
            state = IngestionState(source=source)
            session.add(state)
        if restart or state.source_revision != revision:
            state.cursor = {"offset": 0, **(metadata or {})}
            state.records_processed = 0
        state.source_revision = revision
        state.completed = False
        state.last_error = None
        initial_offset = state.records_processed

    def commit(batch, position, completed=False):
        with Session(engine) as session, session.begin():
            state = session.get(IngestionState, source)
            apply_batch(session, batch)
            if completed and finish:
                finish(session)
            state.cursor = {**state.cursor, "offset": position}
            state.records_processed = position
            state.completed = completed
            state.last_error = None
            state.last_success_at = datetime.now(UTC)
            state.updated_at = datetime.now(UTC)

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
