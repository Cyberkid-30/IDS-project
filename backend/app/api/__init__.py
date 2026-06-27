"""
API package initialization.
"""

from app.api.router import api_router
from app.api.deps import get_database, get_detector, get_alerts_manager, Pagination

__all__ = [
    "api_router",
    "get_database",
    "get_detector",
    "get_alerts_manager",
    "Pagination",
]
