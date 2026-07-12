"""
Packet parser service.

Converts captured packets into database-ready format and
extracts relevant fields for signature matching.
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict

from app.services.sniffer import CapturedPacket
from app.core.logging import ids_logger


@dataclass
class ParsedPacket:
    """
    Parsed packet ready for signature matching.

    Contains all relevant fields extracted from raw packet
    in a format suitable for database storage and matching.
    """

    timestamp: float
    protocol: str
    source_ip: str
    source_port: Optional[int]
    dest_ip: str
    dest_port: Optional[int]
    payload_text: Optional[str]  # Decoded payload as string
    payload_hex: str  # Hex representation
    payload_size: int
    flags: Optional[str]
    icmp_type: Optional[int]
    icmp_code: Optional[int]
    raw_hex: str  # Hex dump of raw packet

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class PacketParser:
    """
    Service for parsing and normalizing captured packets.

    Handles payload decoding, hex conversion, and extraction
    of fields needed for signature matching.
    """

    # Maximum payload size to store (bytes)
    MAX_PAYLOAD_SIZE = 4096

    # Maximum raw packet size to store (bytes)
    MAX_RAW_SIZE = 8192

    def __init__(self):
        """Initialize the packet parser."""
        ids_logger.debug("PacketParser initialized")

    def parse(self, captured: CapturedPacket) -> ParsedPacket:
        """
        Parse a captured packet for matching and storage.

        Args:
            captured: Raw captured packet from sniffer

        Returns:
            ParsedPacket: Parsed and normalized packet
        """
        # Decode payload to text (best effort)
        payload_text = self._decode_payload(captured.payload)

        # Convert payload to hex
        payload_truncated = captured.payload[: self.MAX_PAYLOAD_SIZE]
        payload_hex = payload_truncated.hex()

        # Convert raw packet to hex
        raw_truncated = captured.raw_packet[: self.MAX_RAW_SIZE]
        raw_hex = raw_truncated.hex()

        return ParsedPacket(
            timestamp=captured.timestamp,
            protocol=captured.protocol,
            source_ip=captured.source_ip,
            source_port=captured.source_port,
            dest_ip=captured.dest_ip,
            dest_port=captured.dest_port,
            payload_text=payload_text,
            payload_hex=payload_hex,
            payload_size=len(captured.payload),
            flags=captured.flags,
            icmp_type=captured.icmp_type,
            icmp_code=captured.icmp_code,
            raw_hex=raw_hex,
        )

    def _decode_payload(self, payload: bytes) -> Optional[str]:
        """
        Attempt to decode payload bytes to text.

        Tries multiple encodings and returns the first successful decode.
        Returns None if payload cannot be decoded as text.

        Args:
            payload: Raw payload bytes

        Returns:
            str: Decoded text or None
        """
        if not payload:
            return None

        # Truncate before decoding
        truncated = payload[: self.MAX_PAYLOAD_SIZE]

        # Try common encodings
        encodings = ["utf-8", "ascii", "latin-1"]

        for encoding in encodings:
            try:
                decoded = truncated.decode(encoding, errors="strict")
                # Filter out non-printable characters
                printable = "".join(
                    c if c.isprintable() or c in "\n\r\t" else "." for c in decoded
                )
                return printable
            except (UnicodeDecodeError, UnicodeError):
                continue

        # Fallback: replace non-decodable bytes with dots
        try:
            return truncated.decode("utf-8", errors="replace")
        except Exception:
            return None

    def extract_tcp_flags(self, flags: Optional[str]) -> Dict[str, bool]:
        """
        Extract individual TCP flags from flag string.

        Args:
            flags: TCP flags string (e.g., "SA" for SYN-ACK)

        Returns:
            dict: Dictionary of flag names to boolean values
        """
        flag_map = {
            "F": "FIN",
            "S": "SYN",
            "R": "RST",
            "P": "PSH",
            "A": "ACK",
            "U": "URG",
            "E": "ECE",
            "C": "CWR",
        }

        result = {name: False for name in flag_map.values()}

        if flags:
            for char in flags:
                if char in flag_map:
                    result[flag_map[char]] = True

        return result

    def get_payload_snippet(self, parsed: ParsedPacket, max_length: int = 200) -> str:
        """
        Get a snippet of payload for alert display.

        Args:
            parsed: Parsed packet
            max_length: Maximum snippet length

        Returns:
            str: Payload snippet or placeholder
        """
        if parsed.payload_text:
            snippet = parsed.payload_text[:max_length]
            if len(parsed.payload_text) > max_length:
                snippet += "..."
            return snippet
        elif parsed.payload_hex:
            # Return hex if no text representation
            hex_snippet = parsed.payload_hex[:max_length]
            if len(parsed.payload_hex) > max_length:
                hex_snippet += "..."
            return f"[HEX] {hex_snippet}"
        else:
            return "[No payload]"


