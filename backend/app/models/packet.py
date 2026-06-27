"""
Packet model for storing captured network packets.

This model stores parsed packet information for analysis and forensics.
Note: In production, you might want to limit packet storage to reduce DB size.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from datetime import datetime

from app.database.base import Base, IDMixin


class Packet(Base, IDMixin):
    """
    Database model for captured network packets.

    Stores essential packet header information and optional payload.
    Used for forensic analysis and debugging signature matches.

    Attributes:
        timestamp: When the packet was captured
        protocol: Network protocol (TCP, UDP, ICMP)
        source_ip: Source IP address
        source_port: Source port number
        dest_ip: Destination IP address
        dest_port: Destination port number
        payload: Packet payload (may be truncated)
        payload_size: Original payload size in bytes
        flags: TCP flags (if TCP packet)
        matched: Whether this packet triggered an alert
    """

    __tablename__ = "packets"

    # Timestamp
    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
        doc="Packet capture timestamp",
    )

    # Protocol info
    protocol = Column(
        String(10), nullable=False, index=True, doc="Protocol (TCP, UDP, ICMP)"
    )

    # Source info
    source_ip = Column(String(50), nullable=False, index=True, doc="Source IP address")
    source_port = Column(Integer, nullable=True, doc="Source port (TCP/UDP only)")

    # Destination info
    dest_ip = Column(
        String(50), nullable=False, index=True, doc="Destination IP address"
    )
    dest_port = Column(Integer, nullable=True, doc="Destination port (TCP/UDP only)")

    # Payload
    payload = Column(Text, nullable=True, doc="Packet payload (first N bytes)")
    payload_size = Column(
        Integer, default=0, nullable=False, doc="Original payload size in bytes"
    )

    # TCP specific
    flags = Column(String(20), nullable=True, doc="TCP flags (SYN, ACK, FIN, etc.)")

    # ICMP specific
    icmp_type = Column(Integer, nullable=True, doc="ICMP message type")
    icmp_code = Column(Integer, nullable=True, doc="ICMP message code")

    # Matching status
    matched = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        doc="Whether packet matched a signature",
    )

    def __repr__(self) -> str:
        return (
            f"<Packet(id={self.id}, proto={self.protocol}, "
            f"src={self.source_ip}:{self.source_port}, "
            f"dst={self.dest_ip}:{self.dest_port})>"
        )

    def to_dict(self) -> dict:
        """Convert packet to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None, # type: ignore
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "payload_size": self.payload_size,
            "flags": self.flags,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "matched": self.matched,
        }
