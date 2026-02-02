"""
Test GET and OPTIONS handlers for /api/honeypot endpoint.
Ensures browsers and testers don't get 405 errors.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_honeypot_returns_200():
    """Test that GET /api/honeypot returns HTTP 200 with SuccessResponse."""
    response = client.get("/api/honeypot")
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    
    # Verify SuccessResponse schema
    assert data["status"] == "success"
    assert data["scamDetected"] == False
    assert data["engagementMetrics"]["engagementDurationSeconds"] == 0
    assert data["engagementMetrics"]["totalMessagesExchanged"] == 0
    
    # Verify intelligence fields are empty
    intel = data["extractedIntelligence"]
    assert intel["bankAccounts"] == []
    assert intel["upiIds"] == []
    assert intel["phishingLinks"] == []
    assert intel["phoneNumbers"] == []
    assert intel["suspiciousKeywords"] == []
    
    # Verify agentNotes format
    assert "agentNotes" in data
    assert data["agentNotes"].startswith("nextReply:"), \
        f"agentNotes should start with 'nextReply:', got: {data['agentNotes']}"
    assert "POST" in data["agentNotes"] or "post" in data["agentNotes"].lower()
    
    print("[PASS] GET /api/honeypot returns HTTP 200 with SuccessResponse")

def test_options_honeypot_returns_200():
    """Test that OPTIONS /api/honeypot returns HTTP 200."""
    response = client.options("/api/honeypot")
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    
    # Verify SuccessResponse schema
    assert data["status"] == "success"
    assert data["scamDetected"] == False
    
    # Verify agentNotes format
    assert "agentNotes" in data
    assert data["agentNotes"].startswith("nextReply:"), \
        f"agentNotes should start with 'nextReply:', got: {data['agentNotes']}"
    
    print("[PASS] OPTIONS /api/honeypot returns HTTP 200 with SuccessResponse")

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
    
    # Verify agentNotes format
    assert data["agentNotes"].startswith("nextReply:"), \
        f"POST agentNotes should start with 'nextReply:', got: {data['agentNotes']}"
    
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
    
    print("[PASS] Browser simulation - GET returns 200 (not 405)")

def test_all_methods_return_same_schema():
    """Verify GET, OPTIONS, and POST all return SuccessResponse schema."""
    from app.config import settings
    
    # GET
    get_response = client.get("/api/honeypot")
    get_data = get_response.json()
    
    # OPTIONS
    options_response = client.options("/api/honeypot")
    options_data = options_response.json()
    
    # POST (empty body)
    post_response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    post_data = post_response.json()
    
    # All should have same top-level keys
    expected_keys = {"status", "scamDetected", "engagementMetrics", "extractedIntelligence", "agentNotes"}
    
    assert set(get_data.keys()) == expected_keys
    assert set(options_data.keys()) == expected_keys
    assert set(post_data.keys()) == expected_keys
    
    # All should have agentNotes starting with nextReply:
    assert get_data["agentNotes"].startswith("nextReply:")
    assert options_data["agentNotes"].startswith("nextReply:")
    assert post_data["agentNotes"].startswith("nextReply:")
    
    print("[PASS] All methods return consistent SuccessResponse schema")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
