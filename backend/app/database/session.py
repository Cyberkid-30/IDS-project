"""
Database session management module.

Provides SQLAlchemy engine and session factory for database operations.
Uses SQLite as the database backend.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from app.core.config import settings
from app.core.logging import ids_logger


# Create SQLAlchemy engine
# SQLite-specific: check_same_thread=False allows multi-threaded access
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
    echo=settings.DEBUG,  # Log SQL queries in debug mode
    pool_pre_ping=True,  # Verify connections before use
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency that provides database session.

    Yields a database session and ensures proper cleanup after use.
    Use this as a FastAPI dependency injection.

    Yields:
        Session: SQLAlchemy database session

    Example:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        ids_logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def get_session() -> Session:
    """
    Get a new database session directly (non-generator version).

    Use this when you need a session outside of FastAPI dependency injection,
    such as in background workers or scripts.

    Returns:
        Session: New SQLAlchemy database session

    Note:
        Remember to close the session when done!
    """
    return SessionLocal()
