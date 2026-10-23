import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "sqlite:///data/secwatch.db")


def engine_for(url: str | None = None):
    return create_engine(url or database_url(), pool_pre_ping=True)
