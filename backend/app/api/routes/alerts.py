"""
Alert management API routes.

Provides endpoints for viewing, filtering, and managing security alerts.
"""

from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_database, get_alerts_manager, Pagination
from app.services.alert_manager import AlertManager
from app.schemas.alert import (
    AlertResponse,
    AlertList,
    AlertStatusUpdate,
    AlertStats,
    SeverityLevel,
    AlertStatus,
)
from app.core.logging import ids_logger

router = APIRouter()


@router.get(
    "/",
    response_model=AlertList,
    summary="Get all alerts",
    description="Retrieve a paginated list of alerts with optional filters.",
)
def get_alerts(
    pagination: Pagination = Depends(),
    severity: Optional[SeverityLevel] = Query(
        None, description="Filter by severity level"
    ),
    alert_status: Optional[AlertStatus] = Query(
        None, alias="status", description="Filter by alert status"
    ),
    source_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    dest_ip: Optional[str] = Query(
        None, description="Filter by destination IP address"
    ),
    start_date: Optional[datetime] = Query(
        None, description="Filter alerts after this datetime"
    ),
    end_date: Optional[datetime] = Query(
        None, description="Filter alerts before this datetime"
    ),
    db: Session = Depends(get_database),
    alert_manager: AlertManager = Depends(get_alerts_manager),
):
    """
    Get all alerts with pagination and filtering.

    Supports filtering by:
    - Severity level (low, medium, high, critical)
    - Status (new, acknowledged, resolved, false_positive)
    - Source/destination IP addresses
    - Date range

    Returns paginated results ordered by timestamp (newest first).
    """
    alerts, total = alert_manager.get_alerts(
        db=db,
        skip=pagination.skip,
        limit=pagination.limit,
        severity=severity.value if severity else None,
        status=alert_status.value if alert_status else None,
        source_ip=source_ip,
        dest_ip=dest_ip,
        start_date=start_date,
        end_date=end_date,
    )

    return AlertList(
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        alerts=[AlertResponse.model_validate(a) for a in alerts],
    )


@router.get(
    "/stats",
    response_model=AlertStats,
    summary="Get alert statistics",
    description="Retrieve aggregated alert statistics.",
)
def get_alert_stats(
    db: Session = Depends(get_database),
    alert_manager: AlertManager = Depends(get_alerts_manager),
):
    """
    Get comprehensive alert statistics.

    Returns:
    - Total and new alert counts
    - Breakdown by severity level
    - Today's alert count
    - Top source IPs
    - Most triggered signatures
    """
    stats = alert_manager.get_alert_stats(db)
    return AlertStats(**stats)


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get alert by ID",
    description="Retrieve a specific alert by its ID.",
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_database),
    alert_manager: AlertManager = Depends(get_alerts_manager),
):
    """
    Get a specific alert by ID.

    Args:
        alert_id: Unique alert identifier

    Returns:
        Alert details including matched signature info

    Raises:
        404: Alert not found
    """
    alert = alert_manager.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found",
        )
    return AlertResponse.model_validate(alert)


@router.patch(
    "/{alert_id}/status",
    response_model=AlertResponse,
    summary="Update alert status",
    description="Update the status of an alert (acknowledge, resolve, etc.).",
)
def update_alert_status(
    alert_id: int,
    status_update: AlertStatusUpdate,
    db: Session = Depends(get_database),
    alert_manager: AlertManager = Depends(get_alerts_manager),
):
    """
    Update an alert's status.

    Valid status transitions:
    - new -> acknowledged, resolved, false_positive
    - acknowledged -> resolved, false_positive

    Args:
        alert_id: Alert to update
        status_update: New status value

    Returns:
        Updated alert

    Raises:
        404: Alert not found
    """
    alert = alert_manager.update_alert_status(db, alert_id, status_update.status.value)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found",
        )

    db.commit()
    return AlertResponse.model_validate(alert)


@router.delete(
    "/{alert_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete alert",
    description="Delete a specific alert.",
)
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_database),
    alert_manager: AlertManager = Depends(get_alerts_manager),
):
    """
    Delete an alert.

    Args:
        alert_id: Alert to delete

    Raises:
        404: Alert not found
    """
    deleted = alert_manager.delete_alert(db, alert_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found",
        )
    db.commit()


@router.post(
    "/cleanup",
    summary="Cleanup old alerts",
    description="Delete alerts older than specified days.",
)
def cleanup_alerts(
    days: int = Query(30, ge=1, le=365, description="Delete alerts older than N days"),
    db: Session = Depends(get_database),
    alert_manager: AlertManager = Depends(get_alerts_manager),
):
    """
    Cleanup old alerts from the database.

    Args:
        days: Age threshold in days (default: 30)

    Returns:
        Number of deleted alerts
    """
    deleted_count = alert_manager.cleanup_old_alerts(db, days)
    db.commit()

    ids_logger.info(f"Cleanup complete: {deleted_count} alerts deleted")

    return {"deleted": deleted_count, "days_threshold": days}
