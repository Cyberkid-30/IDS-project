import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.signature import Signature, SeverityLevel, ProtocolType


@pytest.fixture
def alert_signature(db_session: Session) -> Signature:
    sig = Signature(
        name="Web Attack",
        description="Detects web attacks",
        protocol=ProtocolType.TCP,
        dest_port="80,443",
        pattern=r"(?i)select|union|insert",
        severity=SeverityLevel.CRITICAL,
        enabled=True,
        category="web-attack",
    )
    db_session.add(sig)
    db_session.commit()
    return sig


@pytest.fixture
def sample_alerts(db_session: Session, alert_signature: Signature) -> list[Alert]:
    alerts = [
        Alert(
            signature_id=alert_signature.id,
            source_ip="10.0.0.1",
            source_port=12345,
            dest_ip="192.168.1.1",
            dest_port=80,
            protocol="TCP",
            payload_snippet="SELECT * FROM users",
            severity=SeverityLevel.CRITICAL,
            status="new",
            packet_count=3,
        ),
        Alert(
            signature_id=alert_signature.id,
            source_ip="10.0.0.2",
            source_port=54321,
            dest_ip="192.168.1.2",
            dest_port=443,
            protocol="TCP",
            payload_snippet="union select 1,2,3",
            severity=SeverityLevel.CRITICAL,
            status="acknowledged",
            packet_count=1,
        ),
        Alert(
            signature_id=alert_signature.id,
            source_ip="10.0.0.3",
            source_port=33333,
            dest_ip="192.168.1.3",
            dest_port=8080,
            protocol="TCP",
            payload_snippet="test payload",
            severity=SeverityLevel.LOW,
            status="resolved",
            packet_count=5,
        ),
    ]
    for a in alerts:
        db_session.add(a)
    db_session.commit()
    return alerts


class TestListAlerts:
    def test_empty(self, client: TestClient):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["alerts"] == []

    def test_with_alerts(self, client: TestClient, sample_alerts):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 3

    def test_filter_by_severity(self, client: TestClient, sample_alerts):
        resp = client.get("/api/v1/alerts?severity=critical")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

        resp = client.get("/api/v1/alerts?severity=low")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_filter_by_status(self, client: TestClient, sample_alerts):
        resp = client.get("/api/v1/alerts?status=new")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

        resp = client.get("/api/v1/alerts?status=resolved")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_filter_by_source_ip(self, client: TestClient, sample_alerts):
        resp = client.get("/api/v1/alerts?source_ip=10.0.0.1")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_filter_by_dest_ip(self, client: TestClient, sample_alerts):
        resp = client.get("/api/v1/alerts?dest_ip=192.168.1.2")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_pagination(self, client: TestClient, sample_alerts):
        resp = client.get("/api/v1/alerts?page=1&page_size=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 2


class TestGetAlertStats:
    def test_empty_stats(self, client: TestClient):
        resp = client.get("/api/v1/alerts/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_alerts"] == 0

    def test_stats_with_alerts(self, client: TestClient, sample_alerts):
        resp = client.get("/api/v1/alerts/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_alerts"] == 3
        assert data["new_alerts"] == 1
        assert data["critical_alerts"] == 2
        assert data["low_alerts"] == 1
        assert len(data["top_source_ips"]) > 0


class TestGetAlert:
    def test_found(self, client: TestClient, sample_alerts):
        alert_id = sample_alerts[0].id
        resp = client.get(f"/api/v1/alerts/{alert_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == alert_id
        assert data["source_ip"] == "10.0.0.1"

    def test_not_found(self, client: TestClient):
        resp = client.get("/api/v1/alerts/999")
        assert resp.status_code == 404


class TestUpdateAlertStatus:
    def test_update(self, client: TestClient, sample_alerts):
        alert_id = sample_alerts[0].id
        resp = client.patch(
            f"/api/v1/alerts/{alert_id}/status",
            json={"status": "resolved"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

    def test_not_found(self, client: TestClient):
        resp = client.patch(
            "/api/v1/alerts/999/status",
            json={"status": "resolved"},
        )
        assert resp.status_code == 404


class TestDeleteAlert:
    def test_delete(self, client: TestClient, sample_alerts):
        alert_id = sample_alerts[0].id
        resp = client.delete(f"/api/v1/alerts/{alert_id}")
        assert resp.status_code == 204

        resp = client.get(f"/api/v1/alerts/{alert_id}")
        assert resp.status_code == 404

    def test_not_found(self, client: TestClient):
        resp = client.delete("/api/v1/alerts/999")
        assert resp.status_code == 404


class TestCleanupAlerts:
    def test_cleanup(self, client: TestClient, sample_alerts):
        resp = client.post("/api/v1/alerts/cleanup?days=30")
        assert resp.status_code == 200
        data = resp.json()
        assert "deleted" in data
