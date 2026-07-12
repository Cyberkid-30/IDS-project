"""
API dependencies module.

Provides common dependencies for FastAPI route handlers,
including database sessions and service instances.
"""

from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.detector import DetectionEngine
from app.services.alert_manager import AlertManager
from app.services.parser import PacketParser
from app.services.matcher import SignatureMatcher


# ---------------------------------------------------------------------------
# Detection engine singleton lifecycle
# ---------------------------------------------------------------------------
# DetectionEngine is stateful (capture thread, stats, loaded signatures), so
# we manage exactly one instance at the application level.  It is created by
# init_detection_engine() during the FastAPI lifespan startup and returned by
# the get_detector() dependency for every request that needs it.

_detection_engine: Optional[DetectionEngine] = None


def init_detection_engine() -> DetectionEngine:
    """Create the single DetectionEngine instance (idempotent)."""
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine


def get_detector() -> DetectionEngine:
    """Dependency that returns the global detection engine."""
    if _detection_engine is None:
        raise RuntimeError(
            "Detection engine not initialised – call init_detection_engine() "
            "during application startup"
        )
    return _detection_engine


# ---------------------------------------------------------------------------
# Stateless service dependencies – fresh instance per request
# ---------------------------------------------------------------------------


def get_alerts_manager() -> AlertManager:
    """Dependency that provides a fresh AlertManager per request."""
    return AlertManager()


def get_parser() -> PacketParser:
    """Dependency that provides a fresh PacketParser per request."""
    return PacketParser()


def get_matcher() -> SignatureMatcher:
    """Dependency that provides a fresh SignatureMatcher per request."""
    return SignatureMatcher()


# ---------------------------------------------------------------------------
# Database session
# ---------------------------------------------------------------------------


def get_database() -> Generator[Session, None, None]:
    """
    Dependency that provides database session.

    Yields:
        Session: SQLAlchemy database session
    """
    yield from get_db()


# ---------------------------------------------------------------------------
# Guard dependency
# ---------------------------------------------------------------------------


def require_detection_running(
    detector: DetectionEngine = Depends(get_detector),
) -> DetectionEngine:
    """Require the detection engine to be running (raises 503 otherwise)."""
    if not detector.is_running:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection engine is not running",
        )
    return detector


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


class Pagination:
    """Standardised pagination parameters for list endpoints."""

    def __init__(self, page: int = 1, page_size: int = 50):
        self.page = max(1, page)
        self.page_size = min(max(1, page_size), 100)
        self.skip = (self.page - 1) * self.page_size
        self.limit = self.page_size

    def get_response_meta(self, total: int) -> dict:
        return {
            "total": total,
            "page": self.page,
            "page_size": self.page_size,
            "total_pages": (total + self.page_size - 1) // self.page_size,
        }
