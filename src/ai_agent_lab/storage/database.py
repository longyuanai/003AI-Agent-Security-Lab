"""Database engine/session construction with explicit production settings."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from ai_agent_lab.storage.models import Base


def make_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Create a SQLAlchemy engine for SQLite development or PostgreSQL."""

    if not database_url or "://" not in database_url:
        raise ValueError("database_url must be an explicit SQLAlchemy URL")
    options: dict[str, object] = {"pool_pre_ping": True, "echo": echo}
    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
    engine = create_engine(database_url, **options)
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def create_schema(engine: Engine) -> None:
    """Development/test helper; production uses Alembic migrations."""

    Base.metadata.create_all(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Yield one transaction and rollback on failure."""

    session = factory()
    try:
        with session.begin():
            yield session
    finally:
        session.close()


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


__all__ = ["create_schema", "make_engine", "session_factory", "session_scope"]
