from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_database
from app.services import firewall as fw
from app.models.blocked_ip import BlockedIP
from app.schemas.firewall import (
    FirewallBlockRequest,
    FirewallBlockResponse,
    FirewallBlockList,
    FirewallUnblockResponse,
)
from app.core.logging import ids_logger

router = APIRouter()


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
        alert_count=1,
    )
    db.add(blocked)
    db.commit()
    db.refresh(blocked)

    ids_logger.info(f"IP blocked via API: {ip} (reason: {reason})")
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
    db.commit()

    ids_logger.info(f"IP unblocked via API: {ip}")
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
        blocked_ips=[
            FirewallBlockResponse.model_validate(e) for e in entries
        ],
    )