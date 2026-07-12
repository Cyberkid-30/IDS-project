"""
Database initialization module.

Handles database creation, table setup, and initial data seeding.
"""

from pathlib import Path
from sqlalchemy import inspect

from app.database.base import Base
from app.database.session import engine, SessionLocal
from app.core.logging import ids_logger
from app.core.config import settings


def create_tables() -> None:
    """
    Create all database tables defined in models.

    Uses SQLAlchemy's create_all which is safe to call multiple times -
    it only creates tables that don't exist.
    """
    # Import all models to register them with Base
    from app.models import signature, alert, packet, user  # noqa: F401

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

    # Seed default admin user if no users exist
    seed_default_user()

    # Seed default signatures from JSON files if none exist
    seed_default_signatures()


def seed_default_user() -> None:
    """Create a default admin user if no users exist in the database."""
    from app.models.user import User
    from app.core.auth import hash_password

    db = SessionLocal()
    try:
        existing = db.query(User).first()
        if existing:
            ids_logger.info("Default user already exists, skipping seed")
            return

        default_user = User(
            username="admin",
            hashed_password=hash_password("admin123"),
            is_active=True,
        )
        db.add(default_user)
        db.commit()
        ids_logger.info("Default user seeded: admin / admin123")
    except Exception as e:
        db.rollback()
        ids_logger.warning(f"Could not seed default user: {e}")
    finally:
        db.close()


def seed_default_signatures() -> int:
    """
    Load default signatures from JSON files if no signatures exist.

    Returns:
        int: Number of signatures loaded
    """
    from app.models.signature import Signature
    from app.core.enums import SeverityLevel, ProtocolType
    import json

    db = SessionLocal()
    try:
        existing = db.query(Signature).first()
        if existing:
            ids_logger.info("Signatures already exist in database, skipping seed")
            return 0

        # Load default and custom signature files
        sig_files = [
            settings.SIGNATURES_DIR / "default.json",
            settings.SIGNATURES_DIR / "custom.json",
        ]

        severity_map = {
            "low": SeverityLevel.LOW,
            "medium": SeverityLevel.MEDIUM,
            "high": SeverityLevel.HIGH,
            "critical": SeverityLevel.CRITICAL,
        }
        protocol_map = {
            "tcp": ProtocolType.TCP,
            "udp": ProtocolType.UDP,
            "icmp": ProtocolType.ICMP,
            "any": ProtocolType.ANY,
        }

        total_loaded = 0
        for filepath in sig_files:
            if not filepath.exists():
                continue

            with open(filepath, "r") as f:
                data = json.load(f)

            for sig_data in data.get("signatures", []):
                sig = Signature(
                    name=sig_data["name"],
                    description=sig_data.get("description"),
                    protocol=protocol_map.get(
                        sig_data.get("protocol", "any").lower(), ProtocolType.ANY
                    ),
                    source_ip=sig_data.get("source_ip"),
                    source_port=sig_data.get("source_port"),
                    dest_ip=sig_data.get("dest_ip"),
                    dest_port=sig_data.get("dest_port"),
                    tcp_flags=sig_data.get("tcp_flags"),
                    pattern=sig_data.get("pattern"),
                    severity=severity_map.get(
                        sig_data.get("severity", "medium").lower(), SeverityLevel.MEDIUM
                    ),
                    enabled=sig_data.get("enabled", True),
                    category=sig_data.get("category"),
                    reference=sig_data.get("reference"),
                )
                db.add(sig)
                total_loaded += 1

        db.commit()
        ids_logger.info(f"Seeded {total_loaded} default signatures")
        return total_loaded
    except Exception as e:
        db.rollback()
        ids_logger.warning(f"Could not seed default signatures: {e}")
        return 0
    finally:
        db.close()


def reset_database() -> None:
    """
    Reset the database by dropping and recreating all tables.

    WARNING: This will delete all data! Use with caution.
    """
    from app.models import signature, alert, packet, user  # noqa: F401

    ids_logger.warning("Resetting database - all data will be deleted!")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    ids_logger.info("Database reset complete")


if __name__ == "__main__":
    # Allow running directly for database setup
    init_database()
