"""
Signature matcher service.

Core matching logic that compares parsed packets against signatures.
Handles IP matching, port matching, protocol matching, and payload pattern matching.
"""

from typing import Optional, List
from dataclasses import dataclass

from app.models.signature import Signature
from app.services.parser import ParsedPacket
from app.utils.ip_utils import ip_matches_pattern
from app.utils.regex_utils import pattern_matches
from app.core.enums import ProtocolType
from app.core.logging import ids_logger


@dataclass
class MatchResult:
    """
    Result of matching a packet against a signature.

    Attributes:
        matched: Whether the packet matched the signature
        signature: The matched signature (if matched)
        match_details: Details about what matched
    """

    matched: bool
    signature: Optional[Signature] = None
    match_details: Optional[dict] = None


class SignatureMatcher:
    """
    Service for matching packets against signatures.

    Implements the core detection logic by checking each packet
    against all enabled signatures using multiple matching criteria.
    """

    def __init__(self):
        """Initialize the signature matcher."""
        ids_logger.debug("SignatureMatcher initialized")

    def match_packet(
        self, packet: ParsedPacket, signatures: List[Signature]
    ) -> List[MatchResult]:
        """
        Match a packet against all provided signatures.

        Args:
            packet: Parsed packet to check
            signatures: List of signatures to match against

        Returns:
            list: List of MatchResult for each matching signature
        """
        matches = []

        for sig in signatures:
            # Skip disabled signatures
            if not sig.enabled:  # type: ignore
                continue

            result = self._match_single(packet, sig)
            if result.matched:
                matches.append(result)
                ids_logger.debug(
                    f"Packet matched signature: {sig.name} "
                    f"({packet.source_ip} -> {packet.dest_ip})"
                )

        return matches

    def _match_single(self, packet: ParsedPacket, signature: Signature) -> MatchResult:
        """
        Match a packet against a single signature.

        All criteria must match for a positive result (AND logic).

        Args:
            packet: Parsed packet
            signature: Signature to match

        Returns:
            MatchResult: Match result with details
        """
        match_details = {}

        # 1. Check protocol
        if not self._match_protocol(packet.protocol, signature.protocol.value):
            return MatchResult(matched=False)
        match_details["protocol"] = True

        # 2. Check source IP
        if not ip_matches_pattern(packet.source_ip, signature.source_ip):  # type: ignore
            return MatchResult(matched=False)
        match_details["source_ip"] = True

        # 3. Check destination IP
        if not ip_matches_pattern(packet.dest_ip, signature.dest_ip):  # type: ignore
            return MatchResult(matched=False)
        match_details["dest_ip"] = True

        # 4. Check source port
        if not self._match_port(packet.source_port, signature.source_port):  # type: ignore
            return MatchResult(matched=False)
        match_details["source_port"] = True

        # 5. Check destination port
        if not self._match_port(packet.dest_port, signature.dest_port):  # type: ignore
            return MatchResult(matched=False)
        match_details["dest_port"] = True

        # 6. Check payload pattern
        if not self._match_payload(packet.payload_text, signature.pattern):  # type: ignore
            return MatchResult(matched=False)
        match_details["payload"] = True

        # 7. Check TCP flags (only applicable for TCP packets)
        if signature.tcp_flags is not None:
            if packet.protocol == "TCP" and not self._match_tcp_flags(
                packet.flags,
                signature.tcp_flags,  # type: ignore
            ):
                return MatchResult(matched=False)
            match_details["tcp_flags"] = True

        # All checks passed - we have a match!
        return MatchResult(
            matched=True, signature=signature, match_details=match_details
        )

    def _match_protocol(self, packet_protocol: str, signature_protocol: str) -> bool:
        """
        Check if packet protocol matches signature.

        Args:
            packet_protocol: Protocol from packet (TCP, UDP, ICMP)
            signature_protocol: Protocol from signature (or 'any')

        Returns:
            bool: True if protocol matches
        """
        # 'any' matches all protocols
        if signature_protocol.lower() == "any":
            return True

        return packet_protocol.lower() == signature_protocol.lower()

    def _match_port(
        self, packet_port: Optional[int], signature_port: Optional[str]
    ) -> bool:
        """
        Check if packet port matches signature port specification.

        Supports:
        - Single port: "80"
        - Port range: "1-1024"
        - Port list: "80,443,8080"
        - Any port: None or "any"

        Args:
            packet_port: Port number from packet (None for ICMP)
            signature_port: Port specification from signature

        Returns:
            bool: True if port matches
        """
        # No signature port means match any
        if signature_port is None or signature_port.lower() == "any":
            return True

        # No packet port (e.g., ICMP) - only matches if signature is 'any'
        if packet_port is None:
            return False

        try:
            # Check for port range (e.g., "1-1024")
            if "-" in signature_port and "," not in signature_port:
                start, end = signature_port.split("-")
                return int(start) <= packet_port <= int(end)

            # Check for port list (e.g., "80,443,8080")
            if "," in signature_port:
                ports = [int(p.strip()) for p in signature_port.split(",")]
                return packet_port in ports

            # Single port match
            return packet_port == int(signature_port)

        except (ValueError, TypeError):
            ids_logger.warning(f"Invalid port specification: {signature_port}")
            return False

    def _match_payload(self, payload: Optional[str], pattern: Optional[str]) -> bool:
        """
        Check if payload matches signature pattern.

        Args:
            payload: Packet payload text
            pattern: Regex pattern from signature

        Returns:
            bool: True if payload matches pattern
        """
        # No pattern means match any payload (including empty)
        if pattern is None:
            return True

        # Use regex utility for pattern matching
        return pattern_matches(pattern, payload, case_sensitive=False)

    def _match_tcp_flags(
        self, packet_flags: Optional[str], signature_flags: str
    ) -> bool:
        """
        Check if packet TCP flags match signature flags.

        The signature flags string specifies which flag characters must be
        present in the packet. Packet with none (no TCP flags) only matches
        if signature_flags is empty.

        Args:
            packet_flags: TCP flags from packet (e.g. 'S', 'SA', 'A')
            signature_flags: Required flag characters from signature

        Returns:
            bool: True if all required flags are present
        """
        # No packet flags - only matches empty signature flags
        if not packet_flags:
            return not signature_flags

        # Check each required character is present in packet flags
        return all(ch in packet_flags for ch in signature_flags)

    def test_signature(
        self, signature: Signature, test_packets: List[ParsedPacket]
    ) -> dict:
        """
        Test a signature against sample packets.

        Useful for signature validation before deployment.

        Args:
            signature: Signature to test
            test_packets: List of packets to test against

        Returns:
            dict: Test results with match count and details
        """
        matches = []

        for i, packet in enumerate(test_packets):
            result = self._match_single(packet, signature)
            if result.matched:
                matches.append(
                    {
                        "packet_index": i,
                        "source": f"{packet.source_ip}:{packet.source_port}",
                        "dest": f"{packet.dest_ip}:{packet.dest_port}",
                        "protocol": packet.protocol,
                    }
                )

        return {
            "total_packets": len(test_packets),
            "matches": len(matches),
            "match_details": matches,
        }
