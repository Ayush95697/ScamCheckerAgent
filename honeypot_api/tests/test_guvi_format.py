"""
Test GUVI-compatible SuccessResponse format and hardening.
Verifies API returns full structured schema as expected by GUVI evaluation.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

def test_full_success_response_format():
    """Test that POST /api/honeypot returns full SuccessResponse schema."""
    payload = {
        "sessionId": "guvi-full-test-001",
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
    
    # GUVI Evaluation expects the full schema
    required_keys = {"status", "scamDetected", "engagementMetrics", "extractedIntelligence", "agentNotes"}
    assert all(k in data for k in required_keys)
    
    # Status should be "success"
    assert data["status"] == "success"
    
    # agentNotes should start with nextReply:
    assert data["agentNotes"].startswith("nextReply:")
    
    print(f"[PASS] Full SuccessResponse format correct")
    print(f"   agentNotes: {data['agentNotes'][:100]}...")

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
    assert "agentNotes" in data
    assert data["agentNotes"].startswith("nextReply:")
    
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
    """Test that auth failures return 200 with SuccessResponse schema."""
    response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": "wrong-key"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "agentNotes" in data
    assert data["agentNotes"].startswith("nextReply:")
    
    print("[PASS] Auth failure returns valid SuccessResponse schema")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
