"""
Database initialization module.

Handles database creation, table setup, and initial data seeding.
"""

from pathlib import Path
from sqlalchemy import inspect

from app.database.base import Base
from app.database.session import engine
from app.core.logging import ids_logger
from app.core.config import settings


def create_tables() -> None:
    """
    Create all database tables defined in models.

    Uses SQLAlchemy's create_all which is safe to call multiple times -
    it only creates tables that don't exist.
    """
    # Import all models to register them with Base
    from app.models import signature, alert, packet  # noqa: F401

    ids_logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    ids_logger.info("Database tables created successfully")


def check_database_exists() -> bool:
    """
    Check if the database file exists.

    Returns:
        bool: True if database file exists
    """
    # Extract database path from URL (sqlite:///./data/ids.db)
    db_url = settings.DATABASE_URL
    if db_url.startswith("sqlite:///"):
        db_path = db_url.replace("sqlite:///", "")
        # Handle relative paths
        if db_path.startswith("./"):
            db_path = db_path[2:]
        return Path(db_path).exists()
    return True  # Assume exists for non-SQLite


def get_table_names() -> list:
    """
    Get list of all tables in the database.

    Returns:
        list: Names of all tables in the database
    """
    inspector = inspect(engine)
    return inspector.get_table_names()


def init_database() -> None:
    """
    Initialize the database.

    Creates the database directory if needed, creates tables,
    and performs any necessary initial setup.
    """
    # Ensure data directory exists
    data_dir = Path("data")
    data_dir.mkdir(parents=True, exist_ok=True)

    ids_logger.info("Initializing database...")

    # Create all tables
    create_tables()

    # Log existing tables
    tables = get_table_names()
    ids_logger.info(f"Database initialized with tables: {tables}")


def reset_database() -> None:
    """
    Reset the database by dropping and recreating all tables.

    WARNING: This will delete all data! Use with caution.
    """
    from app.models import signature, alert, packet  # noqa: F401

    ids_logger.warning("Resetting database - all data will be deleted!")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    ids_logger.info("Database reset complete")


if __name__ == "__main__":
    # Allow running directly for database setup
    init_database()
