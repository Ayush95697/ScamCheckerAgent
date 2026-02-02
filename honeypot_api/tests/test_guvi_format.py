"""
Test GUVI-compatible SimpleResponse format.
Verifies API returns {status, reply} as expected by GUVI tester.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

def test_simple_response_format():
    """Test that POST /api/honeypot returns SimpleResponse format."""
    payload = {
        "sessionId": "guvi-test-001",
        "message": {
            "sender": "scammer",
            "text": "Your bank account will be blocked. Verify immediately.",
            "timestamp": "2026-02-03T00:00:00.000Z"
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
    
    # GUVI expects exactly these two fields
    assert "status" in data
    assert "reply" in data
    
    # Should only have these two fields (GUVI format)
    assert set(data.keys()) == {"status", "reply"}
    
    # Status should be "success"
    assert data["status"] == "success"
    
    # Reply should be a string
    assert isinstance(data["reply"], str)
    
    print(f"[PASS] SimpleResponse format correct")
    print(f"   status: {data['status']}")
    print(f"   reply: {data['reply'][:50]}...")

def test_empty_body_returns_simple_response():
    """Test that empty body returns SimpleResponse format."""
    response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    
    # Should match GUVI format
    assert set(data.keys()) == {"status", "reply"}
    assert data["status"] == "success"
    assert isinstance(data["reply"], str)
    
    print("[PASS] Empty body returns SimpleResponse")

def test_multi_turn_conversation():
    """Test multi-turn conversation returns SimpleResponse."""
    session_id = "guvi-multi-001"
    
    # First message
    payload1 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Urgent! Your account will be blocked.",
            "timestamp": "2026-02-03T00:00:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }
    
    response1 = client.post(
        "/api/honeypot",
        json=payload1,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response1.status_code == 200
    data1 = response1.json()
    assert set(data1.keys()) == {"status", "reply"}
    
    # Second message with history
    payload2 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Share your UPI ID to avoid suspension.",
            "timestamp": "2026-02-03T00:01:00.000Z"
        },
        "conversationHistory": [
            {
                "sender": "scammer",
                "text": "Urgent! Your account will be blocked.",
                "timestamp": "2026-02-03T00:00:00.000Z"
            },
            {
                "sender": "user",
                "text": data1["reply"],  # Use previous reply
                "timestamp": "2026-02-03T00:00:30.000Z"
            }
        ],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }
    
    response2 = client.post(
        "/api/honeypot",
        json=payload2,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response2.status_code == 200
    data2 = response2.json()
    assert set(data2.keys()) == {"status", "reply"}
    
    print("[PASS] Multi-turn conversation returns SimpleResponse")
    print(f"   Turn 1 reply: {data1['reply'][:40]}...")
    print(f"   Turn 2 reply: {data2['reply'][:40]}...")

def test_exception_returns_simple_response():
    """Test that exceptions return SimpleResponse format."""
    # Send invalid data that might cause internal error
    payload = {
        "sessionId": "error-test-001",
        "message": {
            "sender": "scammer",
            "text": "Test",
            "timestamp": "invalid-timestamp"
        },
        "conversationHistory": "not-a-list",  # Wrong type
        "metadata": {}
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    # Should still return 200 with SimpleResponse
    assert response.status_code == 200
    
    data = response.json()
    assert set(data.keys()) == {"status", "reply"}
    assert data["status"] == "success"
    
    print("[PASS] Exception handling returns SimpleResponse")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
