"""
Tests for the blocked-IP filtering guarantee in DetectionEngine.

These tests prove that the IDS will not process packets from blocked source
IPs, including the race-window case where the in-memory blocked set has
not yet been refreshed but the blocked_ips DB row already exists.
"""

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.services.detector import DetectionEngine
from app.services.sniffer import CapturedPacket
from app.models.blocked_ip import BlockedIP
from app.models.signature import Signature
from app.core.enums import SeverityLevel, ProtocolType


@pytest.fixture
def detector() -> DetectionEngine:
    return DetectionEngine()


@pytest.fixture
def signature(db_session: Session) -> Signature:
    sig = Signature(
        name="TCP Anything",
        description=None,
        protocol=ProtocolType.ANY,
        source_ip=None,
        source_port=None,
        dest_ip=None,
        dest_port=None,
        tcp_flags=None,
        pattern=None,
        severity=SeverityLevel.MEDIUM,
        enabled=True,
        category="test",
    )
    db_session.add(sig)
    db_session.commit()
    return sig


def make_captured(source_ip: str = "10.0.0.99") -> CapturedPacket:
    return CapturedPacket(
        timestamp=1000.0,
        protocol="TCP",
        source_ip=source_ip,
        source_port=40000,
        dest_ip="192.168.1.10",
        dest_port=80,
        payload=b"GET / HTTP/1.1",
        flags="S",
        icmp_type=None,
        icmp_code=None,
        raw_packet=b"\x00\x01\x02",
    )


class TestProcessPacketBlockedGuarantee:
    """process_packet must drop packets from blocked sources before matching."""

    def test_in_memory_blocked_packet_is_dropped(
        self, detector: DetectionEngine, db_session: Session, signature: Signature
    ):
        detector.load_signatures(db_session)
        # Put the IP in the in-memory set directly (mimics auto_block path).
        with detector._blocked_lock:
            detector._blocked_ips.add("10.0.0.50")

        pkt = make_captured(source_ip="10.0.0.50")
        results = detector.process_packet(pkt, db_session)

        assert results == []
        assert detector._stats.packets_dropped_blocked == 1
        assert detector._stats.packets_processed == 0
        assert detector._stats.alerts_generated == 0

    def test_db_blocked_but_not_in_memory_is_still_dropped(
        self,
        detector: DetectionEngine,
        db_session: Session,
        signature: Signature,
    ):
        """The airtight guarantee: even when the in-memory set is stale,
        a DB row for the source IP must cause the packet to be dropped."""
        detector.load_signatures(db_session)
        # Pre-seed the blocked_ips table WITHOUT refreshing the in-memory set,
        # simulating the race window between the firewall route mutating the
        # DB and calling reload_blocked_ips().
        db_session.add(BlockedIP(ip_address="10.0.0.77", reason="race", alert_count=0))
        db_session.commit()
        assert "10.0.0.77" not in detector._blocked_ips  # sanity: set is stale

        pkt = make_captured(source_ip="10.0.0.77")
        results = detector.process_packet(pkt, db_session)

        assert results == []
        assert detector._stats.packets_dropped_blocked == 1
        assert detector._stats.packets_processed == 0
        assert detector._stats.alerts_generated == 0
        # And the in-memory set must have been refreshed as a side effect.
        assert "10.0.0.77" in detector._blocked_ips

    def test_unblocked_packet_flows_through(
        self, detector: DetectionEngine, db_session: Session, signature: Signature
    ):
        detector.load_signatures(db_session)
        pkt = make_captured(source_ip="10.0.0.42")
        results = detector.process_packet(pkt, db_session)

        # Signature matches ANY protocol with no constraints, so one match.
        assert len(results) == 1
        assert detector._stats.packets_processed == 1
        assert detector._stats.packets_dropped_blocked == 0

    def test_db_check_failure_fails_open(
        self, detector: DetectionEngine, db_session: Session, signature: Signature
    ):
        """If the DB-backed check raises inside SQLAlchemy, _is_blocked_in_db
        must catch it and return False so the packet is processed (fail open)
        rather than silently widening the block list."""
        detector.load_signatures(db_session)
        with detector._blocked_lock:
            detector._blocked_ips.discard("10.0.0.42")

        # Make only the BlockedIP lookup raise; other queries (e.g. the
        # Alert-aggregation lookup inside create_alert) must keep working.
        original_query = db_session.query

        def flaky_query(model, *args, **kwargs):
            if model is BlockedIP:
                raise Exception("simulated DB outage on blocked_ips table")
            return original_query(model, *args, **kwargs)

        with patch.object(db_session, "query", side_effect=flaky_query):
            pkt = make_captured(source_ip="10.0.0.42")
            results = detector.process_packet(pkt, db_session)

        # The DB exception is caught inside _is_blocked_in_db (returns False),
        # so the packet flows through and matches the catch-all signature.
        assert len(results) == 1
        assert detector._stats.packets_processed == 1
        assert detector._stats.packets_dropped_blocked == 0


class TestIsBlockedInDb:
    """Direct unit tests for the authoritative DB check."""

    def test_returns_true_when_row_exists(
        self, detector: DetectionEngine, db_session: Session
    ):
        db_session.add(BlockedIP(ip_address="10.0.0.10", alert_count=0))
        db_session.commit()
        assert detector._is_blocked_in_db(db_session, "10.0.0.10") is True

    def test_returns_false_when_row_absent(
        self, detector: DetectionEngine, db_session: Session
    ):
        assert detector._is_blocked_in_db(db_session, "10.0.0.99") is False

    def test_returns_false_for_none_ip(
        self, detector: DetectionEngine, db_session: Session
    ):
        assert detector._is_blocked_in_db(db_session, None) is False

    def test_returns_false_on_db_exception(
        self, detector: DetectionEngine, db_session: Session
    ):
        bad_session = MagicMock()
        bad_session.query.side_effect = Exception("boom")
        assert detector._is_blocked_in_db(bad_session, "10.0.0.1") is False
