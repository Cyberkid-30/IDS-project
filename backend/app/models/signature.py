"""
Signature model for intrusion detection rules.

Signatures define patterns to match against network traffic.
Each signature contains matching criteria and metadata about the threat.
"""

from sqlalchemy import Column, String, Boolean, Text, Enum
from sqlalchemy.orm import relationship
import enum

from app.database.base import Base, TimestampMixin, IDMixin


class SeverityLevel(str, enum.Enum):
    """
    Severity levels for signatures and alerts.

    Attributes:
        LOW: Minor threat, informational
        MEDIUM: Moderate threat, requires attention
        HIGH: Serious threat, immediate attention needed
        CRITICAL: Severe threat, immediate action required
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProtocolType(str, enum.Enum):
    """
    Network protocols supported for detection.
    """

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class Signature(Base, IDMixin, TimestampMixin):
    """
    Database model for intrusion detection signatures.

    A signature defines a pattern to match against network packets.
    When a packet matches a signature, an alert is generated.

    Attributes:
        name: Human-readable name for the signature
        description: Detailed description of what the signature detects
        protocol: Network protocol to match (TCP, UDP, ICMP, or any)
        source_ip: Source IP pattern to match (supports CIDR notation)
        source_port: Source port or port range to match
        dest_ip: Destination IP pattern to match
        dest_port: Destination port or port range to match
        pattern: Regex pattern to match in packet payload
        severity: Threat severity level
        enabled: Whether the signature is active
        category: Category/type of threat (e.g., "scan", "exploit")
        reference: External reference (CVE, URL, etc.)
    """

    __tablename__ = "signatures"

    # Basic identification
    name = Column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        doc="Unique name for the signature",
    )
    description = Column(Text, nullable=True, doc="Detailed description of the threat")

    # Protocol matching
    protocol = Column(
        Enum(ProtocolType),
        default=ProtocolType.ANY,
        nullable=False,
        doc="Protocol to match",
    )

    # Network matching criteria
    source_ip = Column(
        String(50), nullable=True, doc="Source IP/CIDR to match (null = any)"
    )
    source_port = Column(
        String(50), nullable=True, doc="Source port(s) to match (null = any)"
    )
    dest_ip = Column(
        String(50), nullable=True, doc="Destination IP/CIDR to match (null = any)"
    )
    dest_port = Column(
        String(50), nullable=True, doc="Destination port(s) to match (null = any)"
    )

    # Payload pattern matching
    pattern = Column(Text, nullable=True, doc="Regex pattern to match in payload")

    # Metadata
    severity = Column(
        Enum(SeverityLevel),
        default=SeverityLevel.MEDIUM,
        nullable=False,
        index=True,
        doc="Threat severity level",
    )
    enabled = Column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        doc="Whether signature is active",
    )
    category = Column(
        String(100),
        nullable=True,
        index=True,
        doc="Threat category (e.g., scan, exploit, malware)",
    )
    reference = Column(String(500), nullable=True, doc="External reference (CVE, URL)")

    # Relationship to alerts
    alerts = relationship(
        "Alert", back_populates="signature", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Signature(id={self.id}, name='{self.name}', severity={self.severity})>"
        )

    def to_dict(self) -> dict:
        """Convert signature to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "protocol": self.protocol.value if self.protocol else None, # type: ignore
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "pattern": self.pattern,
            "severity": self.severity.value if self.severity else None, # type: ignore
            "enabled": self.enabled,
            "category": self.category,
            "reference": self.reference,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
