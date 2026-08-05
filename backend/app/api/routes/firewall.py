from ipaddress import ip_address
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_database, get_detector
from app.core.config import settings
from app.core.logging import ids_logger
from app.models.blocked_ip import BlockedIP
from app.schemas.firewall import (
    FirewallBlockList,
    FirewallBlockRequest,
    FirewallBlockResponse,
    FirewallUnblockResponse,
)
from app.services import firewall as fw

router = APIRouter()


def _reload_blocked_if_running():
    """Hot-reload the in-memory blocked-IP set when detection is running,
    so that newly blocked/unblocked IPs take effect immediately without
    restarting the capture thread."""
    try:
        engine = get_detector()
    except RuntimeError:
        return
    if engine.is_running:
        engine.reload_blocked_ips()


def _validate_path_ip(ip: str) -> str:
    """Validate that a path-supplied IP is a valid address.

    Raises 400 if malformed — defense in depth even though the DB lookup
    would simply 404 on garbage input.  Uses 400 (not 422) because path
    parameters don't trigger FastAPI's request-body validation pipeline.
    """
    try:
        ip_address(ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IP address: {ip}",
        ) from exc
    return ip


@router.post(
    "/block",
    response_model=FirewallBlockResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Block an IP address",
    description="Block a specific IP address via ufw and record it in the database.",
)
def block_ip(
    request: FirewallBlockRequest,
    db: Session = Depends(get_database),
):
    if not settings.UFW_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="UFW firewall integration is disabled",
        )

    ip = request.ip_address
    reason = request.reason

    existing = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"IP {ip} is already blocked",
        )

    success = fw.block_ip(ip)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to block IP {ip} via ufw",
        )

    blocked = BlockedIP(
        ip_address=ip,
        reason=reason or "Manual block",
        alert_count=0,
    )
    db.add(blocked)
    try:
        db.commit()
    except Exception:
        db.rollback()
        # UFW already has the deny rule; try to undo it so the firewall
        # state stays consistent with the failed DB write, then fail the
        # request cleanly instead of leaving an orphaned firewall rule.
        ids_logger.error(
            f"DB commit failed after blocking {ip}; rolling back UFW rule"
        )
        try:
            fw.unblock_ip(ip)
        except Exception as rollback_err:
            ids_logger.error(
                f"UFW rollback failed for {ip}: {rollback_err}. "
                f"Firewall state may be inconsistent — check manually."
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist block for IP {ip} (firewall rolled back)",
        )
    db.refresh(blocked)

    ids_logger.info(f"IP blocked via API: {ip} (reason: {reason})")
    _reload_blocked_if_running()
    return FirewallBlockResponse.model_validate(blocked)


@router.delete(
    "/unblock/{ip}",
    response_model=FirewallUnblockResponse,
    summary="Unblock an IP address",
    description="Remove a ufw block rule for the given IP and delete the database record.",
)
def unblock_ip(
    ip: str,
    db: Session = Depends(get_database),
):
    if not settings.UFW_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="UFW firewall integration is disabled",
        )

    ip = _validate_path_ip(ip)

    blocked = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
    if not blocked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP {ip} is not in the block list",
        )

    success = fw.unblock_ip(ip)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unblock IP {ip} via ufw",
        )

    db.delete(blocked)
    try:
        db.commit()
    except Exception:
        db.rollback()
        # Best-effort: re-add the deny rule we just removed so the
        # firewall state matches the (still-present) DB row.
        ids_logger.error(
            f"DB commit failed after unblocking {ip}; re-adding UFW rule"
        )
        try:
            fw.block_ip(ip)
        except Exception as rollback_err:
            ids_logger.error(
                f"UFW re-add failed for {ip}: {rollback_err}. "
                f"Firewall state may be inconsistent — check manually."
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist unblock for IP {ip} (firewall restored)",
        )

    ids_logger.info(f"IP unblocked via API: {ip}")
    _reload_blocked_if_running()
    return FirewallUnblockResponse(
        ip_address=ip,
        status="unblocked",
        message=f"IP {ip} has been unblocked",
    )


@router.get(
    "/blocked",
    response_model=FirewallBlockList,
    summary="List all blocked IPs",
    description="Return all IP addresses currently blocked, from the database.",
)
def get_blocked_ips(
    db: Session = Depends(get_database),
):
    entries = db.query(BlockedIP).order_by(BlockedIP.created_at.desc()).all()

    return FirewallBlockList(
        total=len(entries),
        blocked_ips=[FirewallBlockResponse.model_validate(e) for e in entries],
    )
