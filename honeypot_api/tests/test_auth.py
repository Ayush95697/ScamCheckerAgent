import pytest
import os
from fastapi.testclient import TestClient
from app.main import app

from app.config import settings

client = TestClient(app)
API_KEY = settings.HONEYPOT_API_KEY

def test_missing_api_key():
    # GUVI Req: No 401, return 200 with fallback
    response = client.post("/api/honeypot", json={})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "reply" in data
    assert data["reply"] == "Missing or invalid API key."

def test_invalid_api_key():
    response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": "wrong_key"}
    )
    # GUVI Req: No 401, return 200 with fallback
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["reply"] == "Missing or invalid API key."

def test_valid_api_key_valid_payload():
    # We use a payload that passes validation
    payload = {
        "sessionId": "test-session-123",
        "message": {
            "sender": "scammer",
            "text": "Hello I am prince of Nigeria",
            "timestamp": "2023-01-01T12:00:00"
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "en",
            "locale": "US"
        }
    }
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": API_KEY}
    )
    # 200 is expected if everything works
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "reply" in response.json()
