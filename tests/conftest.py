import json
import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url

from apps.server import models  # noqa: F401
from apps.server.db import Base

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def db(tmp_path):
    if os.environ.get("SECWATCH_TEST_POSTGRES") == "1":
        url = make_url(os.environ["DATABASE_URL"]).set(database="secwatch_test")
        assert url.database == "secwatch_test"
    else:
        url = "sqlite:///" + str(tmp_path / "test.db")
    engine = create_engine(url)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def foreign_keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.drop_all(engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def published():
    return json.loads((FIXTURES / "CVE-2024-3094.json").read_text())
