from fastapi.testclient import TestClient


class TestRootEndpoints:
    def test_root(self, client: TestClient):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "IDS Backend"
        assert data["status"] == "running"
        assert "docs" in data

    def test_ping(self, client: TestClient):
        resp = client.get("/ping")
        assert resp.status_code == 200
        assert resp.json() == {"ping": "pong"}


class TestHealth:
    def test_health_check(self, client: TestClient):
        resp = client.get("/api/v1/system/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["database"] == "healthy"
        assert data["detection"] in ("running", "stopped")


class TestStatus:
    def test_get_status(self, client: TestClient):
        resp = client.get("/api/v1/system/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["app_name"] == "IDS Backend"
        assert "detection_running" in data
        assert "packets_processed" in data


class TestNetworkInfo:
    def test_get_network_info(self, client: TestClient):
        resp = client.get("/api/v1/system/network")
        assert resp.status_code == 200
        data = resp.json()
        assert "available_interfaces" in data
        assert "current_interface" in data
        assert isinstance(data["current_interface"], str)
        assert len(data["current_interface"]) > 0


class TestConfig:
    def test_get_config(self, client: TestClient):
        resp = client.get("/api/v1/system/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["app_name"] == "IDS Backend"
        assert data["api_prefix"] == "/api/v1"


class TestDetectionControl:
    def test_start_detection(self, client: TestClient, mock_detector):
        assert mock_detector.is_running is False
        resp = client.post("/api/v1/system/detection/start")
        assert resp.status_code == 200
        assert resp.json()["status"] == "started"
        assert mock_detector.is_running is True

    def test_start_detection_when_already_running(self, client: TestClient, mock_detector):
        mock_detector.start_detection()
        resp = client.post("/api/v1/system/detection/start")
        assert resp.status_code == 400
        assert "already running" in resp.json()["detail"].lower()

    def test_stop_detection(self, client: TestClient, mock_detector):
        mock_detector.start_detection()
        resp = client.post("/api/v1/system/detection/stop")
        assert resp.status_code == 200
        assert resp.json()["status"] == "stopped"
        assert mock_detector.is_running is False

    def test_stop_detection_when_not_running(self, client: TestClient):
        resp = client.post("/api/v1/system/detection/stop")
        assert resp.status_code == 400
        assert "not running" in resp.json()["detail"].lower()

    def test_reload_signatures(self, client: TestClient):
        resp = client.post("/api/v1/system/signatures/reload")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "reloaded"
        assert "signatures_count" in data
