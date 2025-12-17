"""
Database connection and session management.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from attestful.core.logging import get_logger
from attestful.storage.models import Base

logger = get_logger("storage.database")

# Module-level engine and session factory
_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine(
    database_url: str | None = None,
    *,
    echo: bool = False,
) -> Engine:
    """
    Get or create the database engine.

    Args:
        database_url: Database connection URL. Defaults to SQLite in data directory.
        echo: Whether to echo SQL statements.

    Returns:
        SQLAlchemy Engine instance.
    """
    global _engine

    if _engine is not None:
        return _engine

    if database_url is None:
        # Default to SQLite in current directory
        db_path = Path.cwd() / "attestful.db"
        database_url = f"sqlite:///{db_path}"

    logger.info(f"Creating database engine: {database_url.split('?')[0]}")

    # Create engine with appropriate settings
    if database_url.startswith("sqlite"):
        _engine = create_engine(
            database_url,
            echo=echo,
            connect_args={"check_same_thread": False},
        )
        # Enable foreign keys for SQLite
        @event.listens_for(_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    else:
        _engine = create_engine(
            database_url,
            echo=echo,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )

    return _engine


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """
    Get or create the session factory.

    Args:
        engine: Optional engine to use. Creates default if not provided.

    Returns:
        Session factory.
    """
    global _session_factory

    if _session_factory is not None:
        return _session_factory

    if engine is None:
        engine = get_engine()

    _session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    return _session_factory


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """
    Get a database session as a context manager.

    Usage:
        with get_session() as session:
            session.query(...)

    Yields:
        Database session that auto-commits on success and rolls back on error.
    """
    factory = get_session_factory()
    session = factory()

    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_database(
    database_url: str | None = None,
    *,
    drop_existing: bool = False,
) -> Engine:
    """
    Initialize the database schema.

    Args:
        database_url: Database connection URL.
        drop_existing: Whether to drop existing tables first.

    Returns:
        Database engine.
    """
    engine = get_engine(database_url)

    if drop_existing:
        logger.warning("Dropping existing database tables")
        Base.metadata.drop_all(engine)

    logger.info("Creating database tables")
    Base.metadata.create_all(engine)

    return engine


def reset_engine() -> None:
    """Reset the global engine (for testing)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
