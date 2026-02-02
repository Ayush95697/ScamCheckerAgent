"""
Test boundary hardening to ensure endpoint accepts ANY request body.
Tests empty body, malformed JSON, missing fields, and non-dict payloads.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

def test_empty_body_returns_200():
    """Test that completely empty body returns HTTP 200."""
    response = client.post(
        "/api/honeypot",
        data=b"",  # Empty body
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    assert data["status"] == "success"
    assert data["scamDetected"] == False
    assert "agentNotes" in data
    
    print("[PASS] Empty body test - returns HTTP 200 with SuccessResponse")

def test_malformed_json_returns_200():
    """Test that malformed JSON returns HTTP 200."""
    response = client.post(
        "/api/honeypot",
        data=b"{this is not valid json}",
        headers={
            "x-api-key": settings.HONEYPOT_API_KEY,
            "content-type": "application/json"
        }
    )
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    assert data["status"] == "success"
    assert data["scamDetected"] == False
    
    print("[PASS] Malformed JSON test - returns HTTP 200 with SuccessResponse")

def test_non_dict_json_returns_200():
    """Test that non-dict JSON (array, string, number) returns HTTP 200."""
    test_cases = [
        b'["array", "of", "strings"]',
        b'"just a string"',
        b'12345',
        b'null'
    ]
    
    for payload in test_cases:
        response = client.post(
            "/api/honeypot",
            data=payload,
            headers={
                "x-api-key": settings.HONEYPOT_API_KEY,
                "content-type": "application/json"
            }
        )
        
        assert response.status_code == 200, f"Expected 200 for {payload}, got {response.status_code}"
        data = response.json()
        assert data["status"] == "success"
    
    print("[PASS] Non-dict JSON test - all return HTTP 200")

def test_missing_all_fields_returns_200():
    """Test that empty dict {} returns HTTP 200."""
    response = client.post(
        "/api/honeypot",
        json={},  # Empty dict
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    assert data["scamDetected"] == False
    
    # Should have auto-generated sessionId
    assert data["engagementMetrics"]["totalMessagesExchanged"] >= 0
    
    print("[PASS] Empty dict test - returns HTTP 200 with auto-generated session")

def test_partial_payload_returns_200():
    """Test that partial payload with only some fields returns HTTP 200."""
    response = client.post(
        "/api/honeypot",
        json={"sessionId": "test-001"},  # Only sessionId, no message
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    
    print("[PASS] Partial payload test - returns HTTP 200")

def test_message_with_missing_text_returns_200():
    """Test that message without text field returns HTTP 200."""
    response = client.post(
        "/api/honeypot",
        json={
            "sessionId": "test-002",
            "message": {
                "sender": "scammer"
                # No text field
            }
        },
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    
    print("[PASS] Missing text field test - returns HTTP 200")

def test_no_content_type_header_returns_200():
    """Test that request without Content-Type header returns HTTP 200."""
    response = client.post(
        "/api/honeypot",
        data=b'{"sessionId":"test-003"}',
        headers={
            "x-api-key": settings.HONEYPOT_API_KEY
            # No content-type header
        }
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    
    print("[PASS] No Content-Type header test - returns HTTP 200")

def test_debug_echo_endpoint():
    """Test that debug echo endpoint works."""
    response = client.post(
        "/__debug_echo",
        json={"test": "data"},
        headers={"x-api-key": "test-key"}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert "content_type" in data
    assert "raw_len" in data
    assert "raw_preview" in data
    assert "headers" in data
    
    print(f"[PASS] Debug echo endpoint works")
    print(f"   Content-Type: {data['content_type']}")
    print(f"   Raw length: {data['raw_len']}")
    print(f"   Preview: {data['raw_preview'][:50]}...")

def test_valid_payload_still_works():
    """Test that valid payload still works correctly after boundary hardening."""
    payload = {
        "sessionId": "boundary-test-001",
        "message": {
            "sender": "scammer",
            "text": "Test message with URL http://scam.com and phone +91 9876543210",
            "timestamp": "2026-02-03T00:00:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "en",
            "locale": "IN"
        }
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    
    # Extraction should still work
    intel = data["extractedIntelligence"]
    assert len(intel["phishingLinks"]) > 0 or len(intel["phoneNumbers"]) > 0
    
    print("[PASS] Valid payload still works - extraction functional")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
