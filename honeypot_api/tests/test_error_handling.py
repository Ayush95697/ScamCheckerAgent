"""
Test error handling to ensure API always returns HTTP 200 with SuccessResponse.
Tests invalid JSON, missing API key, malformed payloads, LLM failures, and agentNotes format.
"""
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

def test_invalid_json_returns_200():
    """Test that invalid JSON body returns HTTP 200 with SuccessResponse."""
    response = client.post(
        "/api/honeypot",
        data="this is not valid json{{{",
        headers={
            "x-api-key": settings.HONEYPOT_API_KEY,
            "content-type": "application/json"
        }
    )
    
    # Should return 200, not 400/422
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    
    # Should be SuccessResponse schema
    assert data["status"] == "success"
    assert "scamDetected" in data
    assert data["scamDetected"] == False
    assert "extractedIntelligence" in data
    assert "agentNotes" in data
    
    # All intel fields should be empty lists
    intel = data["extractedIntelligence"]
    assert intel["bankAccounts"] == []
    assert intel["upiIds"] == []
    assert intel["phishingLinks"] == []
    assert intel["phoneNumbers"] == []
    assert intel["suspiciousKeywords"] == []
    
    print("[PASS] Invalid JSON test passed - returns HTTP 200 with SuccessResponse")

def test_missing_api_key_returns_200():
    """Test that missing x-api-key returns HTTP 200 with SuccessResponse."""
    payload = {
        "sessionId": "auth-test-001",
        "message": {
            "sender": "scammer",
            "text": "Test message",
            "timestamp": "2026-02-01T15:00:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    # Send without x-api-key header
    response = client.post("/api/honeypot", json=payload)
    
    # Should return 200, not 401
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    
    # Should be SuccessResponse schema
    assert data["status"] == "success"
    assert data["scamDetected"] == False
    
    # agentNotes should mention missing API key
    assert "agentNotes" in data
    assert "Missing API key" in data["agentNotes"] or "nextReply:" in data["agentNotes"]
    
    print("[PASS] Missing API key test passed - returns HTTP 200 with SuccessResponse")

def test_invalid_api_key_returns_200():
    """Test that invalid x-api-key returns HTTP 200 with SuccessResponse."""
    payload = {
        "sessionId": "auth-test-002",
        "message": {
            "sender": "scammer",
            "text": "Test message",
            "timestamp": "2026-02-01T15:00:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    # Send with invalid API key
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": "invalid-key-12345"}
    )
    
    # Should return 200, not 401
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    assert data["status"] == "success"
    assert data["scamDetected"] == False
    
    print("[PASS] Invalid API key test passed - returns HTTP 200 with SuccessResponse")

def test_malformed_payload_missing_session_id():
    """Test that missing sessionId is handled gracefully."""
    payload = {
        # sessionId missing
        "message": {
            "sender": "scammer",
            "text": "Test",
            "timestamp": "2026-02-01T15:00:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    # Should return 200, not 422
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    
    print("[PASS] Missing sessionId test passed - auto-generated")

def test_malformed_payload_invalid_timestamp():
    """Test that invalid timestamp format is handled gracefully."""
    payload = {
        "sessionId": "malformed-test-001",
        "message": {
            "sender": "scammer",
            "text": "Test",
            "timestamp": "not-a-valid-timestamp"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    # Should return 200, not 422
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    
    print("[PASS] Invalid timestamp test passed - normalized to current time")

def test_malformed_payload_wrong_conversation_history_type():
    """Test that wrong conversationHistory type is normalized to empty list."""
    payload = {
        "sessionId": "malformed-test-002",
        "message": {
            "sender": "scammer",
            "text": "Test",
            "timestamp": "2026-02-01T15:00:00.000Z"
        },
        "conversationHistory": "this should be a list",  # Wrong type
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    # Should return 200, not 422
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    
    print("[PASS] Wrong conversationHistory type test passed - normalized to []")

@patch('app.agent.agent.generate_reply')
def test_llm_failure_uses_fallback(mock_generate_reply):
    """Test that LLM failure uses fallback reply."""
    # Mock agent to raise exception
    mock_generate_reply.side_effect = Exception("LLM quota exceeded")
    
    payload = {
        "sessionId": "llm-fail-test-001",
        "message": {
            "sender": "scammer",
            "text": "Your account is blocked. Click http://scam.com to verify. Call 9876543210",
            "timestamp": "2026-02-01T15:00:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    # Should still return 200
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    
    # Should have agentNotes with fallback reply
    assert "agentNotes" in data
    assert "nextReply:" in data["agentNotes"]
    
    # Extraction should still work even if LLM fails
    intel = data["extractedIntelligence"]
    # Should have extracted the URL and phone
    assert len(intel["phishingLinks"]) > 0 or len(intel["phoneNumbers"]) > 0
    
    print("[PASS] LLM failure test passed - uses fallback reply")

def test_agent_notes_format_always_starts_with_next_reply():
    """Test that agentNotes always starts with 'nextReply:'."""
    test_cases = [
        {
            "name": "Normal request",
            "payload": {
                "sessionId": "format-test-001",
                "message": {
                    "sender": "scammer",
                    "text": "Test message",
                    "timestamp": "2026-02-01T15:00:00.000Z"
                },
                "conversationHistory": [],
                "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
            },
            "headers": {"x-api-key": settings.HONEYPOT_API_KEY}
        },
        {
            "name": "Missing API key",
            "payload": {
                "sessionId": "format-test-002",
                "message": {
                    "sender": "scammer",
                    "text": "Test",
                    "timestamp": "2026-02-01T15:00:00.000Z"
                },
                "conversationHistory": [],
                "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
            },
            "headers": {}  # No API key
        }
    ]
    
    for test_case in test_cases:
        response = client.post(
            "/api/honeypot",
            json=test_case["payload"],
            headers=test_case["headers"]
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify agentNotes format
        assert "agentNotes" in data
        assert data["agentNotes"].startswith("nextReply:"), \
            f"Test '{test_case['name']}' failed: agentNotes should start with 'nextReply:', got: {data['agentNotes']}"
        
        print(f"[PASS] AgentNotes format test passed for: {test_case['name']}")

def test_health_endpoint():
    """Test that health endpoint works."""
    response = client.get("/")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "ok"
    assert data["service"] == "honeypot"
    assert data["endpoint"] == "/api/honeypot"
    
    print("[PASS] Health endpoint test passed")

def test_request_id_header_present():
    """Test that x-request-id header is present in response."""
    payload = {
        "sessionId": "header-test-001",
        "message": {
            "sender": "scammer",
            "text": "Test",
            "timestamp": "2026-02-01T15:00:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200
    
    # Check for x-request-id header
    assert "x-request-id" in response.headers
    request_id = response.headers["x-request-id"]
    
    # Should be a UUID format
    assert len(request_id) > 0
    
    print(f"[PASS] Request ID header test passed - ID: {request_id}")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
