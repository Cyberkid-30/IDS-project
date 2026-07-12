from fastapi.testclient import TestClient


SIG_PAYLOAD = {
    "name": "SQL Injection Test",
    "description": "Detects SQL injection attempts",
    "protocol": "tcp",
    "dest_port": "80,443",
    "pattern": r"(?i)(select|union|insert|drop|delete).*from",
    "severity": "critical",
    "category": "web-attack",
}


class TestListSignatures:
    def test_empty_list(self, client: TestClient):
        resp = client.get("/api/v1/signatures")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["signatures"] == []

    def test_with_signatures(self, client: TestClient, sample_signatures):
        resp = client.get("/api/v1/signatures")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["signatures"]) == 3

    def test_filter_by_enabled(self, client: TestClient, sample_signatures):
        resp = client.get("/api/v1/signatures?enabled=true")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

        resp = client.get("/api/v1/signatures?enabled=false")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_filter_by_severity(self, client: TestClient, sample_signatures):
        resp = client.get("/api/v1/signatures?severity=low")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_filter_by_category(self, client: TestClient, sample_signatures):
        resp = client.get("/api/v1/signatures?category=reconnaissance")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_search(self, client: TestClient, sample_signatures):
        resp = client.get("/api/v1/signatures?search=brute")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_pagination(self, client: TestClient, sample_signatures):
        resp = client.get("/api/v1/signatures?page=1&page_size=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["signatures"]) == 2
        assert data["page"] == 1
        assert data["page_size"] == 2


class TestGetCategories:
    def test_empty(self, client: TestClient):
        resp = client.get("/api/v1/signatures/categories")
        assert resp.status_code == 200
        assert resp.json()["categories"] == []

    def test_with_categories(self, client: TestClient, sample_signatures):
        resp = client.get("/api/v1/signatures/categories")
        assert resp.status_code == 200
        cats = resp.json()["categories"]
        assert "brute-force" in cats
        assert "reconnaissance" in cats
        assert "test" in cats


class TestGetSignature:
    def test_found(self, client: TestClient, sample_signature):
        resp = client.get(f"/api/v1/signatures/{sample_signature.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Test SQL Injection"
        assert data["severity"] == "critical"

    def test_not_found(self, client: TestClient):
        resp = client.get("/api/v1/signatures/999")
        assert resp.status_code == 404


class TestCreateSignature:
    def test_create(self, client: TestClient):
        resp = client.post("/api/v1/signatures", json=SIG_PAYLOAD)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == SIG_PAYLOAD["name"]
        assert data["severity"] == "critical"
        assert data["enabled"] is True
        assert data["id"] is not None

    def test_duplicate_name(self, client: TestClient, sample_signature):
        resp = client.post("/api/v1/signatures", json=SIG_PAYLOAD)
        assert resp.status_code == 201

        resp = client.post("/api/v1/signatures", json=SIG_PAYLOAD)
        assert resp.status_code == 400
        assert "already exists" in resp.json()["detail"].lower()

    def test_invalid_regex(self, client: TestClient):
        payload = SIG_PAYLOAD.copy()
        payload["name"] = "Bad Regex"
        payload["pattern"] = r"[invalid"
        resp = client.post("/api/v1/signatures", json=payload)
        assert resp.status_code == 422


class TestUpdateSignature:
    def test_update(self, client: TestClient, sample_signature):
        resp = client.put(
            f"/api/v1/signatures/{sample_signature.id}",
            json={"description": "Updated description"},
        )
        assert resp.status_code == 200
        assert resp.json()["description"] == "Updated description"

    def test_update_not_found(self, client: TestClient):
        resp = client.put("/api/v1/signatures/999", json={"name": "New Name"})
        assert resp.status_code == 404


class TestDeleteSignature:
    def test_delete(self, client: TestClient, sample_signature):
        resp = client.delete(f"/api/v1/signatures/{sample_signature.id}")
        assert resp.status_code == 204

        resp = client.get(f"/api/v1/signatures/{sample_signature.id}")
        assert resp.status_code == 404

    def test_delete_not_found(self, client: TestClient):
        resp = client.delete("/api/v1/signatures/999")
        assert resp.status_code == 404


class TestToggleSignature:
    def test_toggle(self, client: TestClient, sample_signature):
        assert sample_signature.enabled is True

        resp = client.post(f"/api/v1/signatures/{sample_signature.id}/toggle")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

        resp = client.post(f"/api/v1/signatures/{sample_signature.id}/toggle")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True

    def test_toggle_not_found(self, client: TestClient):
        resp = client.post("/api/v1/signatures/999/toggle")
        assert resp.status_code == 404
