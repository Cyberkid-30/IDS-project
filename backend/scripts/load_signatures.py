#!/usr/bin/env python3
"""
Signature loader script.

Loads signatures from JSON files into the database.
Can be used for initial setup or to reload signatures.

Usage:
    python scripts/load_signatures.py [--clear]

Options:
    --clear     Clear existing signatures before loading
"""

import sys
import json
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database.init_db import init_database
from app.database.session import get_session
from app.models.signature import Signature, SeverityLevel, ProtocolType
from app.core.config import settings
from app.core.logging import ids_logger


def load_signatures_from_file(filepath: Path) -> list:
    """
    Load signatures from a JSON file.

    Args:
        filepath: Path to JSON file

    Returns:
        list: List of signature dictionaries
    """
    if not filepath.exists():
        ids_logger.warning(f"Signature file not found: {filepath}")
        return []

    try:
        with open(filepath, "r") as f:
            data = json.load(f)

        signatures = data.get("signatures", [])
        ids_logger.info(f"Loaded {len(signatures)} signatures from {filepath.name}")
        return signatures

    except json.JSONDecodeError as e:
        ids_logger.error(f"Invalid JSON in {filepath}: {e}")
        return []
    except Exception as e:
        ids_logger.error(f"Error loading {filepath}: {e}")
        return []


def create_signature_from_dict(data: dict) -> Signature:
    """
    Create a Signature model instance from dictionary.

    Args:
        data: Signature data dictionary

    Returns:
        Signature: Model instance
    """
    # Map severity string to enum
    severity_map = {
        "low": SeverityLevel.LOW,
        "medium": SeverityLevel.MEDIUM,
        "high": SeverityLevel.HIGH,
        "critical": SeverityLevel.CRITICAL,
    }

    # Map protocol string to enum
    protocol_map = {
        "tcp": ProtocolType.TCP,
        "udp": ProtocolType.UDP,
        "icmp": ProtocolType.ICMP,
        "any": ProtocolType.ANY,
    }

    return Signature(
        name=data["name"],
        description=data.get("description"),
        protocol=protocol_map.get(
            data.get("protocol", "any").lower(), ProtocolType.ANY
        ),
        source_ip=data.get("source_ip"),
        source_port=data.get("source_port"),
        dest_ip=data.get("dest_ip"),
        dest_port=data.get("dest_port"),
        pattern=data.get("pattern"),
        severity=severity_map.get(
            data.get("severity", "medium").lower(), SeverityLevel.MEDIUM
        ),
        enabled=data.get("enabled", True),
        category=data.get("category"),
        reference=data.get("reference"),
    )


def clear_signatures(db) -> int:
    """
    Clear all existing signatures from database.

    Args:
        db: Database session

    Returns:
        int: Number of signatures deleted
    """
    count = db.query(Signature).delete()
    db.commit()
    return count


def load_signatures(clear_existing: bool = False) -> dict:
    """
    Load signatures from JSON files into database.

    Args:
        clear_existing: Whether to clear existing signatures first

    Returns:
        dict: Statistics about the operation
    """
    # Initialize database
    init_database()

    db = get_session()
    stats = {
        "loaded": 0,
        "skipped": 0,
        "errors": 0,
        "cleared": 0,
    }

    try:
        # Clear existing if requested
        if clear_existing:
            stats["cleared"] = clear_signatures(db)
            ids_logger.info(f"Cleared {stats['cleared']} existing signatures")

        # Find signature files
        sig_dir = settings.SIGNATURES_DIR
        if not sig_dir.is_absolute():
            sig_dir = Path(__file__).parent.parent / sig_dir

        signature_files = [
            sig_dir / "default.json",
            sig_dir / "custom.json",
        ]

        # Load from each file
        for filepath in signature_files:
            signatures_data = load_signatures_from_file(filepath)

            for sig_data in signatures_data:
                try:
                    # Check if signature already exists
                    existing = (
                        db.query(Signature)
                        .filter(Signature.name == sig_data["name"])
                        .first()
                    )

                    if existing:
                        ids_logger.debug(f"Skipping existing: {sig_data['name']}")
                        stats["skipped"] += 1
                        continue

                    # Create new signature
                    signature = create_signature_from_dict(sig_data)
                    db.add(signature)
                    stats["loaded"] += 1
                    ids_logger.debug(f"Added: {sig_data['name']}")

                except Exception as e:
                    ids_logger.error(
                        f"Error loading signature '{sig_data.get('name', 'unknown')}': {e}"
                    )
                    stats["errors"] += 1

        db.commit()

    except Exception as e:
        ids_logger.error(f"Error during signature loading: {e}")
        db.rollback()
        raise
    finally:
        db.close()

    return stats


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Load IDS signatures from JSON files into database"
    )
    parser.add_argument(
        "--clear", action="store_true", help="Clear existing signatures before loading"
    )

    args = parser.parse_args()

    print("=" * 50)
    print("IDS Signature Loader")
    print("=" * 50)

    try:
        stats = load_signatures(clear_existing=args.clear)

        print("\nResults:")
        print(f"  Loaded:  {stats['loaded']}")
        print(f"  Skipped: {stats['skipped']} (already exist)")
        print(f"  Errors:  {stats['errors']}")
        if args.clear:
            print(f"  Cleared: {stats['cleared']}")

        print("\nSignature loading complete!")

    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
