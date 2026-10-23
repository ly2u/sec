from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from apps.server.db import engine_for


@lru_cache(maxsize=1)
def engine():
    return engine_for()


def get_session():
    with Session(engine()) as session:
        yield session


DB = Annotated[Session, Depends(get_session)]
