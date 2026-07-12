from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.services.alert_manager import AlertManager
from app.models.signature import Signature, SeverityLevel, ProtocolType
from app.models.alert import Alert


@pytest.fixture
def alert_manager() -> AlertManager:
    return AlertManager()


@pytest.fixture
def signature(db_session: Session) -> Signature:
    sig = Signature(
        name="Test Sig",
        description=None,
        protocol=ProtocolType.TCP,
        source_ip=None,
        source_port=None,
        dest_ip=None,
        dest_port="80",
        pattern=r"(?i)admin",
        severity=SeverityLevel.HIGH,
        enabled=True,
        category="test",
    )
    db_session.add(sig)
    db_session.commit()
    return sig


def make_parsed_packet(**kwargs):
    from app.services.parser import ParsedPacket
    defaults = dict(
        timestamp=2000.0,
        protocol="TCP",
        source_ip="10.0.0.5",
        source_port=40000,
        dest_ip="192.168.1.10",
        dest_port=80,
        payload_text="GET /admin HTTP/1.1",
        payload_hex="",
        payload_size=0,
        flags=None,
        icmp_type=None,
        icmp_code=None,
        raw_hex="aabbcc",
    )
    defaults.update(kwargs)
    return ParsedPacket(**defaults)


class TestCreateAlert:
    def test_creates_new_alert(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        alert = alert_manager.create_alert(db_session, signature, packet, aggregate=False)

        assert alert.signature_id == signature.id
        assert alert.source_ip == "10.0.0.5"
        assert alert.dest_ip == "192.168.1.10"
        assert alert.protocol == "TCP"
        assert alert.severity == SeverityLevel.HIGH
        assert alert.status == "new"
        assert alert.packet_count == 1
        assert alert.signature.name == "Test Sig"

    def test_sets_payload_snippet(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet(payload_text="SELECT * FROM users WHERE id=1")
        alert = alert_manager.create_alert(db_session, signature, packet, aggregate=False)

        assert alert.payload_snippet is not None
        assert "SELECT" in alert.payload_snippet

    def test_limits_raw_packet(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet(raw_hex="ab" * 5000)
        alert = alert_manager.create_alert(db_session, signature, packet, aggregate=False)

        assert alert.raw_packet is not None
        assert len(alert.raw_packet) <= 2000

    def test_aggregates_within_window(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()

        first = alert_manager.create_alert(db_session, signature, packet, aggregate=True)
        assert first.packet_count == 1

        second = alert_manager.create_alert(db_session, signature, packet, aggregate=True)
        assert second.id == first.id
        assert second.packet_count == 2

    def test_does_not_aggregate_outside_window(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()

        first = alert_manager.create_alert(db_session, signature, packet, aggregate=True)

        # Manually bump timestamp back past the aggregation window
        first.timestamp = datetime.utcnow() - timedelta(seconds=120)
        db_session.flush()

        second = alert_manager.create_alert(db_session, signature, packet, aggregate=True)
        assert second.id != first.id
        assert second.packet_count == 1


class TestGetAlerts:
    def test_returns_empty_when_no_alerts(self, db_session: Session, alert_manager: AlertManager):
        alerts, total = alert_manager.get_alerts(db_session)
        assert alerts == []
        assert total == 0

    def test_returns_all_alerts(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        db_session.commit()

        alerts, total = alert_manager.get_alerts(db_session)
        assert total == 1
        assert len(alerts) == 1

    def test_filters_by_severity(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        db_session.commit()

        alerts, total = alert_manager.get_alerts(db_session, severity="high")
        assert total == 1

        alerts, total = alert_manager.get_alerts(db_session, severity="low")
        assert total == 0

    def test_filters_by_status(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        db_session.commit()

        alerts, total = alert_manager.get_alerts(db_session, status="new")
        assert total == 1

        alerts, total = alert_manager.get_alerts(db_session, status="resolved")
        assert total == 0

    def test_pagination(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        for _ in range(5):
            alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        db_session.commit()

        alerts, total = alert_manager.get_alerts(db_session, skip=0, limit=2)
        assert total == 5
        assert len(alerts) == 2

        alerts, total = alert_manager.get_alerts(db_session, skip=2, limit=2)
        assert len(alerts) == 2

        alerts, total = alert_manager.get_alerts(db_session, skip=10, limit=2)
        assert len(alerts) == 0


class TestGetAlertByID:
    def test_found(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        created = alert_manager.create_alert(db_session, signature, packet, aggregate=False)

        found = alert_manager.get_alert_by_id(db_session, created.id)
        assert found is not None
        assert found.id == created.id

    def test_not_found(self, db_session: Session, alert_manager: AlertManager):
        found = alert_manager.get_alert_by_id(db_session, 999)
        assert found is None


class TestUpdateAlertStatus:
    def test_updates_status(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        alert = alert_manager.create_alert(db_session, signature, packet, aggregate=False)

        updated = alert_manager.update_alert_status(db_session, alert.id, "resolved")
        assert updated is not None
        assert updated.status == "resolved"

    def test_not_found(self, db_session: Session, alert_manager: AlertManager):
        updated = alert_manager.update_alert_status(db_session, 999, "resolved")
        assert updated is None


class TestDeleteAlert:
    def test_deletes(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        alert = alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        db_session.commit()

        deleted = alert_manager.delete_alert(db_session, alert.id)
        assert deleted is True

        db_session.commit()
        assert alert_manager.get_alert_by_id(db_session, alert.id) is None

    def test_not_found(self, db_session: Session, alert_manager: AlertManager):
        assert alert_manager.delete_alert(db_session, 999) is False


class TestGetAlertStats:
    def test_empty_stats(self, db_session: Session, alert_manager: AlertManager):
        stats = alert_manager.get_alert_stats(db_session)
        assert stats["total_alerts"] == 0
        assert stats["new_alerts"] == 0
        assert stats["critical_alerts"] == 0
        assert stats["top_source_ips"] == []
        assert stats["top_signatures"] == []

    def test_stats_with_alerts(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        db_session.commit()

        stats = alert_manager.get_alert_stats(db_session)
        assert stats["total_alerts"] == 2
        assert stats["new_alerts"] == 2
        assert stats["high_alerts"] == 2
        assert stats["top_source_ips"] == [{"ip": "10.0.0.5", "count": 2}]


class TestCleanupOldAlerts:
    def test_cleans_old_alerts(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        from datetime import timedelta
        packet = make_parsed_packet()
        alert = alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        # Set timestamp far in the past so it looks old
        alert.timestamp = alert.timestamp - timedelta(days=400)
        db_session.commit()

        deleted = alert_manager.cleanup_old_alerts(db_session, days=30)
        assert deleted == 1

    def test_keeps_recent_alerts(self, db_session: Session, alert_manager: AlertManager, signature: Signature):
        packet = make_parsed_packet()
        alert_manager.create_alert(db_session, signature, packet, aggregate=False)
        db_session.commit()

        deleted = alert_manager.cleanup_old_alerts(db_session, days=30)
        assert deleted == 0
