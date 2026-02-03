"""
Test GET and OPTIONS handlers for /api/honeypot endpoint.
Ensures browsers and testers don't get 405 errors.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_honeypot_returns_200():
    """Test that GET /api/honeypot returns HTTP 200 with SimpleResponse."""
    response = client.get("/api/honeypot")
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    
    # Verify SimpleResponse schema
    assert data["status"] == "success"
    assert "reply" in data
    assert data["reply"] == "Use POST with JSON body."
    
    # Verify no extra fields
    assert "scamDetected" not in data
    assert "agentNotes" not in data
    
    print("[PASS] GET /api/honeypot returns HTTP 200 with SimpleResponse")

def test_options_honeypot_returns_200():
    """Test that OPTIONS /api/honeypot returns HTTP 200 (Empty body)."""
    response = client.options("/api/honeypot")
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    # OPTIONS has no body in our implementation
    assert response.content == b""
    
    print("[PASS] OPTIONS /api/honeypot returns HTTP 200 (Empty body)")

def test_post_still_works():
    """Test that POST /api/honeypot still works after adding GET/OPTIONS."""
    from app.config import settings
    
    payload = {
        "sessionId": "method-test-001",
        "message": {
            "sender": "scammer",
            "text": "Test message",
            "timestamp": "2026-02-03T00:00:00.000Z"
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
    
    data = response.json()
    assert data["status"] == "success"
    assert "reply" in data
    
    print("[PASS] POST /api/honeypot still works correctly")

def test_browser_simulation():
    """Simulate browser opening URL - should get 200, not 405."""
    # Browsers typically send GET with various headers
    response = client.get(
        "/api/honeypot",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
    )
    
    assert response.status_code == 200, \
        f"Browser GET should return 200, not {response.status_code}"
    
    data = response.json()
    assert data["status"] == "success"
    assert "reply" in data
    
    print("[PASS] Browser simulation - GET returns 200 (not 405)")

def test_all_methods_return_consistent_behavior():
    """Verify consistency across methods."""
    from app.config import settings
    
    # GET
    get_response = client.get("/api/honeypot")
    get_data = get_response.json()
    assert get_data["status"] == "success"
    
    # POST
    post_response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    post_data = post_response.json()
    assert post_data["status"] == "success"
    
    print("[PASS] All methods consistent")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
