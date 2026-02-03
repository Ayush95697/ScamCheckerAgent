"""
Test strict GUVI compliance.
API must returning ONLY {"status": "success", "reply": "..."}
No other fields allowed.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)
API_KEY = settings.HONEYPOT_API_KEY

def test_strict_format_valid_post():
    payload = {
        "sessionId": "strict-test-1",
        "message": {"text": "hello", "timestamp": "2024-01-01T12:00:00Z"}
    }
    response = client.post("/api/honeypot", json=payload, headers={"x-api-key": API_KEY})
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "success"
    assert isinstance(data["reply"], str)
    assert len(data) == 2, f"Extra fields found: {data.keys()}"

def test_strict_format_error_fallback():
    # Send garbage
    response = client.post("/api/honeypot", content="garbage", headers={"x-api-key": API_KEY})
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "success"
    assert isinstance(data["reply"], str)
    assert len(data) == 2

def test_strict_format_auth_fail():
    response = client.post("/api/honeypot", json={}, headers={"x-api-key": "bad"})
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "success"
    assert data["reply"] == "Missing or invalid API key."
    assert len(data) == 2

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
