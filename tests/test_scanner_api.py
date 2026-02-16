"""Tests for scanner API routes"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.api.app import app


@pytest.fixture
def client():
    """FastAPI test client"""
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for GET /health"""

    def test_health_check(self, client):
        """Returns OK status"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "killhouse-scanner-engine"


class TestCreateScan:
    """Tests for POST /api/scans"""

    @patch("src.api.routes._run_scan", new_callable=AsyncMock)
    def test_create_scan_accepted(self, mock_run_scan, client):
        """POST /api/scans returns ACCEPTED with scan_id"""
        payload = {
            "analysis_id": "test-analysis-123",
            "repo_url": "https://github.com/test/repo",
            "branch": "main",
        }
        response = client.post("/api/scans", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ACCEPTED"
        assert "scan_id" in data
        assert len(data["scan_id"]) == 8

    def test_create_scan_missing_analysis_id(self, client):
        """POST /api/scans without analysis_id returns 422"""
        payload = {"repo_url": "https://github.com/test/repo"}
        response = client.post("/api/scans", json=payload)
        assert response.status_code == 422


class TestGetScanStatus:
    """Tests for GET /api/scans/{scan_id}"""

    @patch("src.api.routes._run_scan", new_callable=AsyncMock)
    def test_get_scan_status(self, mock_run_scan, client):
        """GET /api/scans/{scan_id} returns scan data after creation"""
        # Create a scan first
        payload = {"analysis_id": "test-123"}
        create_response = client.post("/api/scans", json=payload)
        scan_id = create_response.json()["scan_id"]

        # Query status
        response = client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["analysis_id"] == "test-123"
        assert data["status"] == "ACCEPTED"

    def test_get_nonexistent_scan(self, client):
        """GET /api/scans/{unknown_id} returns 404"""
        response = client.get("/api/scans/nonexist")
        assert response.status_code == 404
