"""
System status and control API routes.

Provides endpoints for system health, status, and detection control.
"""

import asyncio
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.api.deps import get_detector
from app.services.detector import DetectionEngine
from app.core.config import settings
from app.core.permissions import (
    check_root_privileges,
    verify_capture_permissions,
    get_available_interfaces,
)
from app.core.logging import ids_logger

router = APIRouter()


class SystemStatus(BaseModel):
    """System status response model."""

    app_name: str
    version: str
    detection_running: bool
    signatures_loaded: int
    packets_processed: int
    alerts_generated: int
    uptime_seconds: float
    network_interface: str
    capture_filter: str
    has_capture_permissions: bool
    start_time: Optional[str] = None


class HealthCheck(BaseModel):
    """Health check response model."""

    status: str
    timestamp: str
    database: str
    detection: str


class NetworkInfo(BaseModel):
    """Network information response model."""

    available_interfaces: list
    current_interface: str
    capture_filter: str
    has_root_privileges: bool


@router.get(
    "/health",
    response_model=HealthCheck,
    summary="Health check",
    description="Check if the IDS service is healthy.",
)
def health_check(detector: DetectionEngine = Depends(get_detector)):
    """
    Perform a health check.

    Returns the overall health status including:
    - Service status
    - Database connectivity
    - Detection engine status
    """
    # Check database by attempting to import session
    try:
        from app.database.session import engine

        engine.connect()
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    # Check detection status
    detection_status = "running" if detector.is_running else "stopped"

    return HealthCheck(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        database=db_status,
        detection=detection_status,
    )


@router.get(
    "/status",
    response_model=SystemStatus,
    summary="Get system status",
    description="Get detailed system status information.",
)
def get_status(detector: DetectionEngine = Depends(get_detector)):
    """
    Get comprehensive system status.

    Returns detailed information about:
    - Application version
    - Detection engine status
    - Packet processing statistics
    - Network configuration
    """
    status_info = detector.get_status()
    perm_ok, _ = verify_capture_permissions()

    return SystemStatus(
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        detection_running=status_info["running"],
        signatures_loaded=status_info["signatures_loaded"],
        packets_processed=status_info["packets_processed"],
        alerts_generated=status_info["alerts_generated"],
        uptime_seconds=status_info["uptime_seconds"],
        network_interface=status_info["interface"],
        capture_filter=status_info["capture_filter"],
        has_capture_permissions=perm_ok,
        start_time=status_info["start_time"],
    )


@router.get(
    "/network",
    response_model=NetworkInfo,
    summary="Get network information",
    description="Get available network interfaces and configuration.",
)
def get_network_info():
    """
    Get network configuration information.

    Returns:
    - List of available network interfaces
    - Currently configured interface
    - BPF capture filter
    - Root/capture privileges status
    """
    return NetworkInfo(
        available_interfaces=get_available_interfaces(),
        current_interface=settings.NETWORK_INTERFACE,
        capture_filter=settings.CAPTURE_FILTER,
        has_root_privileges=check_root_privileges(),
    )


@router.post(
    "/detection/start",
    summary="Start detection",
    description="Start the packet capture and detection engine.",
)
async def start_detection(detector: DetectionEngine = Depends(get_detector)):
    """
    Start the detection engine.

    Begins packet capture and signature matching.
    Requires appropriate permissions for raw packet capture.

    Returns:
        Success message and status

    Raises:
        400: Detection already running
        503: Cannot start (permissions or config issue)
    """
    if detector.is_running:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Detection is already running",
        )

    # Verify permissions (fast – no I/O)
    perm_ok, perm_msg = verify_capture_permissions()
    if not perm_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot start detection: {perm_msg}",
        )

    # start_detection loads signatures from the DB – offload to thread pool
    success = await asyncio.to_thread(detector.start_detection)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to start detection engine",
        )

    ids_logger.info("Detection started via API")
    return {"status": "started", "message": "Detection engine started successfully"}


@router.post(
    "/detection/stop",
    summary="Stop detection",
    description="Stop the packet capture and detection engine.",
)
async def stop_detection(detector: DetectionEngine = Depends(get_detector)):
    """
    Stop the detection engine.

    Halts packet capture and signature matching.

    Returns:
        Success message and final statistics
    """
    if not detector.is_running:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Detection is not running"
        )

    status_info = detector.get_status()

    # stop_detection joins the writer thread – offload to thread pool
    await asyncio.to_thread(detector.stop_detection)

    ids_logger.info("Detection stopped via API")
    return {
        "status": "stopped",
        "message": "Detection engine stopped",
        "stats": {
            "packets_processed": status_info["packets_processed"],
            "alerts_generated": status_info["alerts_generated"],
            "uptime_seconds": status_info["uptime_seconds"],
        },
    }


@router.post(
    "/signatures/reload",
    summary="Reload signatures",
    description="Reload signatures from database into detection engine.",
)
async def reload_signatures(detector: DetectionEngine = Depends(get_detector)):
    """
    Reload signatures from the database.

    Useful after adding/modifying signatures to apply changes
    without restarting detection.

    Returns:
        Number of signatures loaded
    """
    count = await asyncio.to_thread(detector.reload_signatures)

    ids_logger.info(f"Signatures reloaded via API: {count} signatures")
    return {"status": "reloaded", "signatures_count": count}


@router.get(
    "/config", summary="Get configuration", description="Get current IDS configuration."
)
def get_config():
    """
    Get current system configuration.

    Returns non-sensitive configuration values.
    """
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "debug": settings.DEBUG,
        "network_interface": settings.NETWORK_INTERFACE,
        "capture_filter": settings.CAPTURE_FILTER,
        "capture_timeout": settings.CAPTURE_TIMEOUT,
        "log_level": settings.LOG_LEVEL,
        "alert_retention_days": settings.ALERT_RETENTION_DAYS,
        "api_prefix": settings.API_PREFIX,
    }
