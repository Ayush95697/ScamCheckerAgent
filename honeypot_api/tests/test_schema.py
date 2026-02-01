from fastapi.testclient import TestClient
from app.main import app
import os
import pytest
from app.models import ERROR_MESSAGE

from app.config import settings

client = TestClient(app)
API_KEY = settings.HONEYPOT_API_KEY

def test_success_schema_validation():
    payload = {
        "sessionId": "schema-test-1",
        "message": {
            "sender": "scammer",
            "text": "Win lottery now",
            "timestamp": "2023-01-01T12:00:00"
        },
        "conversationHistory": [], # Optional but good to provide
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
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "scamDetected" in data
    assert "engagementMetrics" in data
    assert "extractedIntelligence" in data
    assert "agentNotes" in data
    # Check types
    assert isinstance(data["extractedIntelligence"]["upiIds"], list)

def test_optional_history():
    payload = {
        "sessionId": "schema-test-2",
        "message": {
            "sender": "scammer",
            "text": "Win lottery now",
            "timestamp": "2023-01-01T12:00:00"
        },
        # No conversationHistory
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
    assert response.status_code == 200

def test_error_message_constants():
    # 401
    response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": "wrong"}
    )
    assert response.status_code == 401
    assert response.json()["message"] == ERROR_MESSAGE
    
    # 400 Malformed
    response = client.post(
        "/api/honeypot",
        json={"bad": "json"},
        headers={"x-api-key": API_KEY}
    )
    assert response.status_code == 400
    assert response.json()["message"] == ERROR_MESSAGE
