from sqlalchemy import Column, String, Integer

from app.database.base import Base, IDMixin, TimestampMixin


class BlockedIP(Base, IDMixin, TimestampMixin):
    __tablename__ = "blocked_ips"

    ip_address = Column(
        String(50),
        nullable=False,
        unique=True,
        index=True,
        doc="Blocked IP address",
    )
    reason = Column(
        String(500),
        nullable=True,
        doc="Reason for blocking (signature name or manual note)",
    )
    alert_count = Column(
        Integer,
        default=1,
        nullable=False,
        doc="Number of critical alerts from this IP",
    )

    def __repr__(self) -> str:
        return f"<BlockedIP(id={self.id}, ip='{self.ip_address}', reason='{self.reason}')>"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "alert_count": self.alert_count,
            "blocked_at": self.created_at.isoformat() if self.created_at else None,  # type: ignore
        }