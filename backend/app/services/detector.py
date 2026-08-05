"""
Detection engine service.

Orchestrates the detection pipeline: sniffer -> parser -> matcher -> alert.
This is the main service that coordinates all components.
"""

import queue
import threading
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.enums import SeverityLevel
from app.core.logging import ids_logger
from app.database.session import get_session
from app.models.blocked_ip import BlockedIP
from app.models.signature import Signature
from app.services.alert_manager import AlertManager
from app.services.matcher import MatchResult, SignatureMatcher
from app.services.parser import PacketParser
from app.services.sniffer import CapturedPacket, PacketSniffer

_BATCH_SIZE = 50


class DetectionEngine:
    """
    Main detection engine that coordinates the IDS pipeline.

    Flow: Capture -> Parse -> Match -> Alert

    Packets from the sniffer thread are pushed onto a bounded queue and
    processed in batches by a dedicated writer thread.  This decouples
    the capture loop from the database writes, avoiding SQLite write
    contention under load.

    Attributes:
        sniffer: Packet capture service
        parser: Packet parsing service
        matcher: Signature matching service
        alert_manager: Alert generation service
        is_running: Whether detection is active
    """

    def __init__(
        self,
        sniffer: Optional[PacketSniffer] = None,
        parser: Optional[PacketParser] = None,
        matcher: Optional[SignatureMatcher] = None,
        alert_manager: Optional[AlertManager] = None,
    ):
        """
        Initialize the detection engine.

        Args:
            sniffer: Packet sniffer (default: new instance)
            parser: Packet parser (default: new instance)
            matcher: Signature matcher (default: new instance)
            alert_manager: Alert manager (default: new instance)
        """
        self.sniffer = sniffer or PacketSniffer()
        self.parser = parser or PacketParser()
        self.matcher = matcher or SignatureMatcher()
        self.alert_manager = alert_manager or AlertManager()

        self.is_running = False
        self._signatures: list[Signature] = []
        self._signatures_lock = threading.Lock()
        self._stats = DetectionStats()

        # In-memory blocked-IP set. Kept in sync with the blocked_ips
        # table so the capture thread can drop offending packets without
        # touching the database on every packet.  Guarded by
        # _blocked_lock; _reload_blocked_ips swaps in a fresh copy.
        self._blocked_ips: set[str] = set()
        self._blocked_lock = threading.Lock()

        # Bounded packet queue – decouples capture thread from DB writes
        self._packet_queue: queue.Queue = queue.Queue(
            maxsize=settings.MAX_PACKET_BUFFER
        )
        self._writer_thread: Optional[threading.Thread] = None
        self._writer_stop_event = threading.Event()

        ids_logger.info("DetectionEngine initialized")

    def load_signatures(self, db: Session) -> int:
        """
        Load enabled signatures from database.

        Args:
            db: Database session

        Returns:
            int: Number of signatures loaded
        """
        with self._signatures_lock:
            self._signatures = db.query(Signature).filter(Signature.enabled).all()
            count = len(self._signatures)

        ids_logger.info(f"Loaded {count} signatures for detection")
        return count

    def reload_signatures(self) -> int:
        """
        Reload signatures from database.

        Returns:
            int: Number of signatures loaded
        """
        db = get_session()
        try:
            return self.load_signatures(db)
        finally:
            db.close()

    def load_blocked_ips(self, db: Session) -> int:
        """
        Load blocked IP addresses from the database into an in-memory set.

        The capture thread consults this set to drop packets from blocked
        sources before they enter the detection pipeline, avoiding a DB
        round-trip per packet.

        Args:
            db: Database session

        Returns:
            int: Number of blocked IPs loaded
        """
        rows = db.query(BlockedIP).all()
        blocked = {row.ip_address for row in rows}  # type: ignore[union-attr]
        with self._blocked_lock:
            self._blocked_ips = blocked  # type: ignore
        count = len(blocked)
        ids_logger.info(f"Loaded {count} blocked IPs")
        return count

    def reload_blocked_ips(self) -> int:
        """
        Reload the blocked-IP set from the database.

        Called by the firewall routes after a block/unblock mutation so the
        capture thread picks up the change without a restart.  Matches the
        reload_signatures() pattern used for signature hot-reload.

        Returns:
            int: Number of blocked IPs loaded
        """
        db = get_session()
        try:
            return self.load_blocked_ips(db)
        finally:
            db.close()

    def is_ip_blocked(self, ip: Optional[str]) -> bool:
        """
        Thread-safe membership test against the in-memory blocked-IP set.

        Args:
            ip: Source IP to check

        Returns:
            bool: True if the IP is currently in the blocked set
        """
        if not ip:
            return False
        with self._blocked_lock:
            return ip in self._blocked_ips

    def process_packet(
        self, captured: CapturedPacket, db: Session
    ) -> list[MatchResult]:
        """
        Process a single captured packet through the detection pipeline.

        Args:
            captured: Raw captured packet
            db: Database session for storing alerts

        Returns:
            list: List of matching results
        """
        # Drop packets from blocked sources before they enter the matching
        # pipeline. The in-memory set is the fast path; the authoritative
        # check is an indexed SELECT against blocked_ips, ensuring correctness
        # even when the in-memory set is stale (e.g. in the few-millisecond
        # window between a manual block firing the UFW rule and the route
        # handler calling reload_blocked_ips()).
        if self.is_ip_blocked(captured.source_ip):
            self._stats.packets_dropped_blocked += 1
            return []
        if self._is_blocked_in_db(db, captured.source_ip):
            # Refresh the in-memory set so subsequent packets from this IP
            # take the fast path instead of re-hitting the DB.
            try:
                self.load_blocked_ips(db)
            except Exception as e:
                ids_logger.warning(
                    f"In-memory blocked set refresh failed after DB hit: {e}"
                )
            self._stats.packets_dropped_blocked += 1
            return []

        self._stats.packets_processed += 1

        parsed = self.parser.parse(captured)

        with self._signatures_lock:
            matches = self.matcher.match_packet(parsed, self._signatures)

        for match in matches:
            if match.matched and match.signature:
                self._stats.alerts_generated += 1
                alert = self.alert_manager.create_alert(
                    db=db, signature=match.signature, packet=parsed
                )

                # Auto-block source IP if critical severity and feature enabled
                if (
                    settings.AUTO_BLOCK_CRITICAL
                    and match.signature.severity == SeverityLevel.CRITICAL
                ):  # type: ignore
                    self._auto_block_ip(db, captured.source_ip, match.signature.name)  # type: ignore

        return matches

    def _is_blocked_in_db(self, db: Session, ip: Optional[str]) -> bool:
        """
        Authoritative check against the blocked_ips table.

        Used as a fallback when the in-memory set misses so that the
        "IDS will not process packets from blocked IPs" guarantee holds
        even during the reload race window. Hits a unique indexed column,
        so this is a fast point lookup.
        """
        if not ip:
            return False
        try:
            return (
                db.query(BlockedIP)
                .filter(BlockedIP.ip_address == ip)
                .first()
                is not None
            )
        except Exception as e:
            # If the DB is unreachable we fail open (allow the packet),
            # matching the original behavior — a downed DB should not turn
            # the IDS into an open door for the wider network.
            ids_logger.error(f"Blocked-IP DB check failed for {ip}: {e}")
            return False

    def _auto_block_ip(self, db: Session, ip: str, reason: str) -> None:
        """Block an IP via ufw and record in database if not already blocked."""
        from app.services import firewall as fw

        existing = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
        if existing:
            existing.alert_count += 1  # type: ignore
            return

        blocked = BlockedIP(
            ip_address=ip,
            reason=f"Auto-block: {reason}",
            alert_count=1,
        )
        db.add(blocked)

        # Immediately add to the in-memory set so subsequent packets from
        # this source are dropped without waiting for a full DB reload.
        with self._blocked_lock:
            self._blocked_ips.add(ip)

        ids_logger.warning(f"Auto-blocking critical source IP: {ip} ({reason})")

        if settings.UFW_ENABLED:
            threading.Thread(
                target=fw.block_ip,
                args=(ip,),
                daemon=True,
            ).start()

    # ------------------------------------------------------------------
    # Packet queue – writer thread
    # ------------------------------------------------------------------

    def _on_packet_captured(self, captured: CapturedPacket):
        """
        Sniffer callback – push packet onto the bounded queue.

        This is a *fast-path* drop for packets whose source IP is already in
        the in-memory blocked set. It is not authoritative — the final,
        DB-backed check happens in process_packet() so the guarantee holds
        even during the reload race window (a few packets may slip past
        this in-memory filter before reload_blocked_ips() runs, but they
        will be rejected in the writer thread before matching/alerting).

        If the queue is full the packet is dropped and a warning is
        emitted once per burst to avoid log spam.
        """
        if not self.is_running:
            return

        # Fast path: in-memory check, no DB round-trip.
        if self.is_ip_blocked(captured.source_ip):
            self._stats.packets_dropped_blocked += 1
            return

        try:
            self._packet_queue.put(captured, block=False)
        except queue.Full:
            pass

    def _writer_loop(self):
        """
        Background loop that drains the packet queue in batches and
        commits them in a single transaction to reduce SQLite lock
        contention.
        """
        while not self._writer_stop_event.is_set():
            batch: list[CapturedPacket] = []

            # Wait for at least one packet (with a timeout so we can
            # check the stop flag periodically).
            try:
                captured = self._packet_queue.get(timeout=0.5)
                batch.append(captured)
            except queue.Empty:
                continue

            # Drain as many packets as are immediately available, up to
            # _BATCH_SIZE.
            while len(batch) < _BATCH_SIZE:
                try:
                    batch.append(self._packet_queue.get_nowait())
                except queue.Empty:
                    break

            # Process the whole batch under one DB session/transaction.
            db = get_session()
            try:
                for captured in batch:
                    try:
                        self.process_packet(captured, db)
                    except Exception as e:
                        ids_logger.error(f"Error processing packet: {e}")
                db.commit()
            except Exception as e:
                ids_logger.error(f"Batch commit error: {e}")
                db.rollback()
            finally:
                db.close()

        # Drain remaining packets after stop signal.
        self._drain_queue()

    def _drain_queue(self):
        """Process any packets still in the queue after shutdown."""
        remaining = []
        while not self._packet_queue.empty():
            try:
                remaining.append(self._packet_queue.get_nowait())
            except queue.Empty:
                break

        if not remaining:
            return

        ids_logger.info(f"Draining {len(remaining)} remaining packets...")
        db = get_session()
        try:
            for captured in remaining:
                try:
                    self.process_packet(captured, db)
                except Exception as e:
                    ids_logger.error(f"Error draining packet: {e}")
            db.commit()
        except Exception as e:
            ids_logger.error(f"Drain commit error: {e}")
            db.rollback()
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_detection(self) -> bool:
        """
        Start the detection engine.

        Loads signatures and begins packet capture.  The writer thread
        is started to consume packets from the queue.
        """
        if self.is_running:
            ids_logger.warning("Detection engine already running")
            return False

        db = get_session()
        try:
            sig_count = self.load_signatures(db)
            if sig_count == 0:
                ids_logger.warning(
                    "No signatures loaded - detection may be ineffective"
                )
            # Prime the in-memory blocked-IP set so that already-blocked
            # sources are filtered as soon as capture begins.
            self.load_blocked_ips(db)
        finally:
            db.close()

        self.is_running = True
        self._stats.start_time = datetime.now(timezone.utc)
        self._writer_stop_event.clear()

        # Start the background writer thread before capture so it is
        # ready to receive packets immediately.
        self._writer_thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="packet-writer"
        )
        self._writer_thread.start()

        success = self.sniffer.start_async_capture(callback=self._on_packet_captured)

        if success:
            ids_logger.info("Detection engine started")
            ids_logger.info(
                f"Packet queue capacity: {settings.MAX_PACKET_BUFFER}, "
                f"batch size: {_BATCH_SIZE}"
            )
        else:
            self.is_running = False
            self._signal_writer_stop()
            ids_logger.error("Failed to start detection engine")

        return success

    def stop_detection(self):
        """Stop the detection engine."""
        if not self.is_running:
            return

        ids_logger.info("Stopping detection engine...")
        self.sniffer.stop_capture()
        self.is_running = False
        self._signal_writer_stop()

        ids_logger.info(
            f"Detection stopped - Processed: {self._stats.packets_processed}, "
            f"Alerts: {self._stats.alerts_generated}"
        )

    def _signal_writer_stop(self):
        """Signal the writer thread to stop and wait for it."""
        self._writer_stop_event.set()
        if self._writer_thread is not None and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=10)
            if self._writer_thread.is_alive():
                ids_logger.warning("Packet writer thread did not stop in time")

    def get_status(self) -> dict:
        """
        Get current detection engine status.

        Returns:
            dict: Status information
        """
        with self._signatures_lock:
            sig_count = len(self._signatures)

        return {
            "running": self.is_running,
            "signatures_loaded": sig_count,
            "packets_processed": self._stats.packets_processed,
            "alerts_generated": self._stats.alerts_generated,
            "packets_dropped_blocked": self._stats.packets_dropped_blocked,
            "blocked_ips": len(self._blocked_ips),
            "start_time": (
                self._stats.start_time.isoformat() if self._stats.start_time else None
            ),
            "uptime_seconds": self._stats.get_uptime_seconds(),
            "interface": self.sniffer.interface,
            "capture_filter": self.sniffer.filter,
            "queue_size": self._packet_queue.qsize(),
        }


class DetectionStats:
    """Statistics tracking for the detection engine."""

    def __init__(self):
        self.packets_processed: int = 0
        self.alerts_generated: int = 0
        self.packets_dropped_blocked: int = 0
        self.start_time: Optional[datetime] = None

    def get_uptime_seconds(self) -> float:
        """Get uptime in seconds."""
        if self.start_time is None:
            return 0.0
        delta = datetime.now(timezone.utc) - self.start_time
        return delta.total_seconds()

    def reset(self):
        """Reset all statistics."""
        self.packets_processed = 0
        self.alerts_generated = 0
        self.packets_dropped_blocked = 0
        self.start_time = None
