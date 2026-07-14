from unittest.mock import MagicMock
import pytest
from fastapi import status

from app.models.blocked_ip import BlockedIP


@pytest.fixture(autouse=True)
def _mock_firewall_subprocess(monkeypatch: pytest.MonkeyPatch):
    mock_ok = MagicMock()
    mock_ok.returncode = 0
    mock_ok.stdout = ""
    mock_ok.stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_ok)


class TestBlockIP:
    def test_block_ip_creates_record(self, client, db_session):
        resp = client.post("/api/v1/firewall/block", json={
            "ip_address": "10.0.0.55",
            "reason": "test block",
        })
        assert resp.status_code == status.HTTP_201_CREATED
        data = resp.json()
        assert data["ip_address"] == "10.0.0.55"
        assert data["reason"] == "test block"
        assert data["alert_count"] == 1
        assert "blocked_at" in data

        db_entry = db_session.query(BlockedIP).filter(
            BlockedIP.ip_address == "10.0.0.55"
        ).first()
        assert db_entry is not None
        assert db_entry.reason == "test block"

    def test_block_duplicate_ip_returns_conflict(self, client, db_session):
        client.post("/api/v1/firewall/block", json={
            "ip_address": "10.0.0.56",
        })
        resp2 = client.post("/api/v1/firewall/block", json={
            "ip_address": "10.0.0.56",
        })
        assert resp2.status_code == status.HTTP_409_CONFLICT

    def test_block_without_auth_returns_401(self, client):
        client.headers.clear()
        resp = client.post(
            "/api/v1/firewall/block",
            json={"ip_address": "10.0.0.99"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_block_invalid_ip_too_short(self, client):
        resp = client.post("/api/v1/firewall/block", json={
            "ip_address": "x",
        })
        assert resp.status_code == 422


class TestUnblockIP:
    def test_unblock_existing_ip(self, client, db_session):
        client.post("/api/v1/firewall/block", json={
            "ip_address": "10.0.0.60",
        })

        resp = client.delete("/api/v1/firewall/unblock/10.0.0.60")
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["ip_address"] == "10.0.0.60"
        assert data["status"] == "unblocked"

        db_entry = db_session.query(BlockedIP).filter(
            BlockedIP.ip_address == "10.0.0.60"
        ).first()
        assert db_entry is None

    def test_unblock_nonexistent_ip(self, client):
        resp = client.delete("/api/v1/firewall/unblock/10.0.0.99")
        assert resp.status_code == status.HTTP_404_NOT_FOUND


class TestListBlockedIPs:
    def test_empty_blocked_list(self, client):
        resp = client.get("/api/v1/firewall/blocked")
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["total"] == 0
        assert data["blocked_ips"] == []

    def test_blocked_list_returns_all(self, client):
        client.post("/api/v1/firewall/block", json={
            "ip_address": "10.0.0.70",
            "reason": "first",
        })
        client.post("/api/v1/firewall/block", json={
            "ip_address": "10.0.0.71",
            "reason": "second",
        })

        resp = client.get("/api/v1/firewall/blocked")
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["total"] == 2
        ips = [b["ip_address"] for b in data["blocked_ips"]]
        assert "10.0.0.70" in ips
        assert "10.0.0.71" in ips
