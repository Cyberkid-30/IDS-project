"""
API router configuration.

Aggregates all route modules into a single router.
"""

from fastapi import APIRouter

from app.api.routes import alerts, signatures, system

# Create main API router
api_router = APIRouter()

# Include route modules
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])

api_router.include_router(signatures.router, prefix="/signatures", tags=["Signatures"])

api_router.include_router(system.router, prefix="/system", tags=["System"])
