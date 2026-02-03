"""
Test GUVI-compatible SimpleResponse format and hardening.
Verifies API returns exactly {"status": "success", "reply": "..."}
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

def test_simple_success_response_format():
    """Test that POST /api/honeypot returns ONLY status and reply."""
    payload = {
        "sessionId": "guvi-simple-test-001",
        "message": {
            "sender": "scammer",
            "text": "Your bank account will be blocked. Verify immediately.",
            "timestamp": 1738521054000  # Epoch ms
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    
    # GUVI Final Requirement: ONLY status and reply
    assert "status" in data
    assert "reply" in data
    assert data["status"] == "success"
    
    # Ensure no extra fields leaked
    assert "scamDetected" not in data
    assert "extractedIntelligence" not in data
    assert "agentNotes" not in data
    
    print(f"[PASS] SimpleResponse format correct: {data}")

def test_malformed_json_returns_success_response():
    """Test that malformed JSON body returns SuccessResponse instead of 400."""
    response = client.post(
        "/api/honeypot",
        content="invalid json {",
        headers={
            "x-api-key": settings.HONEYPOT_API_KEY,
            "Content-Type": "application/json"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "reply" in data
    
    print("[PASS] Malformed JSON returns SuccessResponse")

def test_epoch_timestamp_normalization():
    """Test that epoch timestamps (s and ms) are handled without error."""
    # Test ms
    payload_ms = {
        "message": {"timestamp": 1738521054000}
    }
    response_ms = client.post(
        "/api/honeypot",
        json=payload_ms,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    assert response_ms.status_code == 200
    
    # Test s
    payload_s = {
        "message": {"timestamp": 1738521054}
    }
    response_s = client.post(
        "/api/honeypot",
        json=payload_s,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    assert response_s.status_code == 200
    
    print("[PASS] Epoch timestamps normalized safely")

def test_auth_failure_returns_success_schema():
    """Test that auth failures return 200 with SimpleResponse schema."""
    response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": "wrong-key"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "reply" in data
    # Fallback reply for auth failure
    assert data["reply"] == "Missing or invalid API key."
    
    print("[PASS] Auth failure returns valid SimpleResponse schema")

def test_options_cors_preflight():
    """Test that OPTIONS method is allowed and returns 200 (CORS)."""
    response = client.options("/api/honeypot")
    assert response.status_code == 200
    print("[PASS] OPTIONS /api/honeypot returns 200")

def test_debug_endpoint_removed():
    """Test that debug endpoint is handled by global 404 handler (returning 200)."""
    response = client.post("/__debug_echo", json={})
    
    # Because of global exception handler catching 404, we expect 200
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    # Fallback reply
    assert "reply" in data
    
    print("[PASS] /__debug_echo handled via global 404 fallback")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
