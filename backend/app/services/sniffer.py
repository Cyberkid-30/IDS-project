"""
Packet sniffer service using Scapy.

This module handles raw packet capture from network interfaces.
It provides both synchronous and asynchronous capture capabilities.
"""

from typing import Optional, Callable, List
from dataclasses import dataclass
from scapy.all import sniff, Raw, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading

from app.core.config import settings
from app.core.logging import ids_logger
from app.core.permissions import verify_capture_permissions, validate_interface


@dataclass
class CapturedPacket:
    """
    Data class representing a captured network packet.

    Stores parsed packet information in a protocol-agnostic format
    for further processing by the detection engine.
    """

    timestamp: float
    protocol: str  # TCP, UDP, ICMP
    source_ip: str
    source_port: Optional[int]
    dest_ip: str
    dest_port: Optional[int]
    payload: bytes
    flags: Optional[str]  # TCP flags
    icmp_type: Optional[int]
    icmp_code: Optional[int]
    raw_packet: bytes  # Original packet for forensics


class PacketSniffer:
    """
    Network packet sniffer using Scapy.

    Captures packets from a specified network interface and
    converts them to CapturedPacket objects for analysis.

    Attributes:
        interface: Network interface to capture from
        filter: BPF filter string
        is_running: Whether the sniffer is currently active
    """

    def __init__(
        self, interface: Optional[str] = None, capture_filter: Optional[str] = None
    ):
        """
        Initialize the packet sniffer.

        Args:
            interface: Network interface name (default from config)
            capture_filter: BPF filter string (default from config)
        """
        self.interface = interface or settings.NETWORK_INTERFACE
        self.filter = capture_filter or settings.CAPTURE_FILTER
        self.is_running = False
        self._stop_event = threading.Event()
        self._packet_callback: Optional[Callable] = None

        ids_logger.info(
            f"PacketSniffer initialized - Interface: {self.interface}, "
            f"Filter: {self.filter}"
        )

    def verify_setup(self) -> tuple:
        """
        Verify sniffer can operate (permissions, interface).

        Returns:
            tuple: (success, message)
        """
        # Check permissions
        perm_ok, perm_msg = verify_capture_permissions()
        if not perm_ok:
            return False, perm_msg

        # Validate interface
        if not validate_interface(self.interface):
            return False, f"Interface '{self.interface}' not available"

        return True, "Sniffer setup verified"

    def _parse_packet(self, packet) -> Optional[CapturedPacket]:
        """
        Parse a Scapy packet into CapturedPacket.

        Args:
            packet: Raw Scapy packet

        Returns:
            CapturedPacket: Parsed packet or None if not IP
        """
        try:
            # Only process IP packets
            if not packet.haslayer(IP):
                return None

            ip_layer = packet[IP]

            # Extract common fields
            timestamp = float(packet.time)
            source_ip = ip_layer.src
            dest_ip = ip_layer.dst

            # Initialize optional fields
            source_port = None
            dest_port = None
            flags = None
            icmp_type = None
            icmp_code = None
            protocol = "UNKNOWN"

            # Extract protocol-specific fields
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                protocol = "TCP"
                source_port = tcp_layer.sport
                dest_port = tcp_layer.dport
                flags = str(tcp_layer.flags)

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                protocol = "UDP"
                source_port = udp_layer.sport
                dest_port = udp_layer.dport

            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                protocol = "ICMP"
                icmp_type = icmp_layer.type
                icmp_code = icmp_layer.code

            # Extract payload
            payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""

            # Get raw packet bytes
            raw_packet = bytes(packet)

            return CapturedPacket(
                timestamp=timestamp,
                protocol=protocol,
                source_ip=source_ip,
                source_port=source_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                payload=payload,
                flags=flags,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                raw_packet=raw_packet,
            )

        except Exception as e:
            ids_logger.error(f"Error parsing packet: {e}")
            return None

    def capture_packets(
        self,
        count: int = 0,
        timeout: Optional[int] = None,
        callback: Optional[Callable[[CapturedPacket], None]] = None,
    ) -> List[CapturedPacket]:
        """
        Capture packets synchronously.

        Args:
            count: Number of packets to capture (0 = unlimited)
            timeout: Capture timeout in seconds
            callback: Function to call for each captured packet

        Returns:
            list: List of CapturedPacket objects
        """
        captured_packets = []

        def packet_handler(packet):
            parsed = self._parse_packet(packet)
            if parsed:
                captured_packets.append(parsed)
                if callback:
                    callback(parsed)

        ids_logger.info(f"Starting packet capture (count={count}, timeout={timeout})")

        try:
            # Suppress Scapy warnings
            conf.verb = 0

            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=packet_handler,
                count=count if count > 0 else 0,
                timeout=timeout,
                store=False,
            )

        except PermissionError:
            ids_logger.error("Permission denied - run with sudo or set CAP_NET_RAW")
        except Exception as e:
            ids_logger.error(f"Capture error: {e}")

        ids_logger.info(f"Capture complete - {len(captured_packets)} packets")
        return captured_packets

    def start_async_capture(self, callback: Callable[[CapturedPacket], None]) -> bool:
        """
        Start asynchronous packet capture in background.

        Args:
            callback: Function to call for each packet

        Returns:
            bool: True if capture started successfully
        """
        if self.is_running:
            ids_logger.warning("Capture already running")
            return False

        # Verify setup
        ok, msg = self.verify_setup()
        if not ok:
            ids_logger.error(f"Cannot start capture: {msg}")
            return False

        self._packet_callback = callback
        self._stop_event.clear()
        self.is_running = True

        # Start capture in background thread
        capture_thread = threading.Thread(target=self._async_capture_loop, daemon=True)
        capture_thread.start()

        ids_logger.info("Async packet capture started")
        return True

    def _async_capture_loop(self):
        """Internal capture loop for async operation."""

        def packet_handler(packet):
            if self._stop_event.is_set():
                return

            parsed = self._parse_packet(packet)
            if parsed and self._packet_callback:
                self._packet_callback(parsed)

        try:
            conf.verb = 0
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=packet_handler,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception as e:
            ids_logger.error(f"Async capture error: {e}")
        finally:
            self.is_running = False
            ids_logger.info("Async capture loop ended")

    def stop_capture(self):
        """Stop the async capture."""
        if not self.is_running:
            return

        ids_logger.info("Stopping packet capture...")
        self._stop_event.set()
        self.is_running = False


