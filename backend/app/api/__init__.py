"""
API package initialization.
"""

from app.api.router import api_router
from app.api.deps import get_database, get_detector, get_alerts_manager, Pagination
from app.api.auth_deps import get_current_user

__all__ = [
    "api_router",
    "get_database",
    "get_detector",
    "get_alerts_manager",
    "Pagination",
    "get_current_user",
]
