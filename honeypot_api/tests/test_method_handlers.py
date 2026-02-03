"""
Test that ALL methods return 200 OK with strict JSON.
GUVI's tester tries random methods; we must never fail.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

def test_get_method_returns_json():
    # GET /api/honeypot -> 200 OK with JSON
    response = client.get("/api/honeypot")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "reply" in data
    assert data["reply"] == "Use POST."

def test_options_method_returns_json():
    # OPTIONS /api/honeypot -> 200 OK with JSON (forced)
    response = client.options("/api/honeypot")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "reply" in data
    assert "Allowed" in data["reply"]

def test_head_method_returns_json():
    # HEAD /api/honeypot -> 200 OK
    response = client.head("/api/honeypot")
    assert response.status_code == 200
    # Head requests usually return no body, but the app sends it.
    # The client might strip it, but the status is what matters most for compliance.

def test_slash_variants():
    # Test strict slash handling
    r1 = client.post("/api/honeypot/", json={}, headers={"x-api-key": settings.HONEYPOT_API_KEY})
    # Valid or invalid payload, must return 200
    assert r1.status_code == 200
    
    r2 = client.options("/api/honeypot/")
    assert r2.status_code == 200
    
    r3 = client.get("/api/honeypot/")
    assert r3.status_code == 200

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
