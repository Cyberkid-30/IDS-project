from fastapi import APIRouter, Depends

from app.api.routes import alerts, signatures, system, auth
from app.api.auth_deps import get_current_user

api_router = APIRouter()

# Public routes (no authentication required)
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# Protected routes (authentication required)
api_router.include_router(
    alerts.router,
    prefix="/alerts",
    tags=["Alerts"],
    dependencies=[Depends(get_current_user)],
)

api_router.include_router(
    signatures.router,
    prefix="/signatures",
    tags=["Signatures"],
    dependencies=[Depends(get_current_user)],
)

api_router.include_router(
    system.router,
    prefix="/system",
    tags=["System"],
    dependencies=[Depends(get_current_user)],
)
