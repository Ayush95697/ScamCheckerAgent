import pytest
import os
from fastapi.testclient import TestClient
from app.main import app

from app.config import settings

client = TestClient(app)
API_KEY = settings.HONEYPOT_API_KEY

def test_missing_api_key():
    response = client.post("/api/honeypot", json={})
    assert response.status_code == 401
    assert response.json() == {
        "status": "error",
        "message": "Invalid API key or malformed request"
    }

def test_invalid_api_key():
    response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": "wrong_key"}
    )
    assert response.status_code == 401
    assert response.json() == {
        "status": "error",
        "message": "Invalid API key or malformed request"
    }

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
