"""
Alert model for intrusion detection events.

Alerts are generated when network traffic matches a signature.
They contain details about the matched traffic and the triggering signature.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.base import Base, TimestampMixin, IDMixin
from app.models.signature import SeverityLevel


class AlertStatus(str, Enum):
    """
    Status states for alerts.

    Attributes:
        NEW: Newly created, not yet reviewed
        ACKNOWLEDGED: Reviewed by analyst
        RESOLVED: Investigation complete
        FALSE_POSITIVE: Determined to be false alarm
    """

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(Base, IDMixin, TimestampMixin):
    """
    Database model for security alerts.

    An alert is created when a packet matches a signature's criteria.
    Contains information about both the matched packet and the signature.

    Attributes:
        signature_id: Foreign key to the triggering signature
        source_ip: Source IP address of the suspicious packet
        source_port: Source port (if applicable)
        dest_ip: Destination IP address
        dest_port: Destination port (if applicable)
        protocol: Protocol of the matched packet
        payload_snippet: First N bytes of payload for analysis
        severity: Copied from signature for quick filtering
        status: Current status of the alert
        timestamp: When the suspicious traffic was detected
        packet_count: Number of packets matching this pattern
    """

    __tablename__ = "alerts"

    # Link to signature
    signature_id = Column(
        Integer,
        ForeignKey("signatures.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="ID of the triggering signature",
    )

    # Packet information
    source_ip = Column(
        String(50), nullable=False, index=True, doc="Source IP of malicious traffic"
    )
    source_port = Column(Integer, nullable=True, doc="Source port number")
    dest_ip = Column(
        String(50),
        nullable=False,
        index=True,
        doc="Destination IP of malicious traffic",
    )
    dest_port = Column(Integer, nullable=True, doc="Destination port number")
    protocol = Column(
        String(10), nullable=False, doc="Network protocol (TCP, UDP, ICMP)"
    )

    # Payload data
    payload_snippet = Column(
        Text, nullable=True, doc="First portion of payload for analysis"
    )

    # Alert metadata
    severity = Column(
        Enum(SeverityLevel),
        nullable=False,
        index=True,
        doc="Severity level from signature",
    )
    status = Column(
        String(20),
        default="new",
        nullable=False,
        index=True,
        doc="Alert status (new, acknowledged, resolved, false_positive)",
    )
    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
        doc="When the alert was triggered",
    )
    packet_count = Column(
        Integer, default=1, nullable=False, doc="Number of matching packets"
    )

    # Additional context
    raw_packet = Column(Text, nullable=True, doc="Hex dump of raw packet for forensics")

    # Relationships
    signature = relationship("Signature", back_populates="alerts")

    def __repr__(self) -> str:
        return (
            f"<Alert(id={self.id}, signature_id={self.signature_id}, "
            f"src={self.source_ip}, dst={self.dest_ip}, severity={self.severity})>"
        )

    def to_dict(self) -> dict:
        """Convert alert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "signature_id": self.signature_id,
            "signature_name": self.signature.name if self.signature else None,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "payload_snippet": self.payload_snippet,
            "severity": self.severity.value if self.severity else None, # type: ignore
            "status": self.status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None, # type: ignore
            "packet_count": self.packet_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
