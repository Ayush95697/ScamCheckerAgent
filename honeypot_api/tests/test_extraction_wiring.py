"""
Test extraction wiring to ensure URLs and phone numbers are captured.
This tests the critical bug fix where extraction must always run on incoming messages.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

def test_extraction_from_incoming_message():
    """
    Test that extraction captures URLs and phone numbers from incoming message.
    This is the critical bug fix - extraction must work even when scamDetected=false.
    """
    payload = {
        "sessionId": "extract-test-001",
        "message": {
            "sender": "scammer",
            "text": "Sir KYC pending hai. Turant update karo nahi toh account freeze ho jayega. Link: http://bit.ly/kyc2026 Call +91 9876543210",
            "timestamp": "2026-02-01T15:45:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "Hinglish",
            "locale": "IN"
        }
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    
    # Verify response structure
    assert data["status"] == "success"
    assert "extractedIntelligence" in data
    
    intel = data["extractedIntelligence"]
    
    # CRITICAL: Verify URL was extracted
    assert "phishingLinks" in intel
    assert len(intel["phishingLinks"]) > 0, "Expected to find phishing links"
    
    # Check for the URL (may be normalized to https://)
    links = intel["phishingLinks"]
    assert any("bit.ly/kyc2026" in link for link in links), \
        f"Expected to find bit.ly/kyc2026 in {links}"
    
    # CRITICAL: Verify phone number was extracted
    assert "phoneNumbers" in intel
    assert len(intel["phoneNumbers"]) > 0, "Expected to find phone numbers"
    
    # Check for the phone number (may be normalized to +919876543210)
    phones = intel["phoneNumbers"]
    assert any("9876543210" in phone for phone in phones), \
        f"Expected to find 9876543210 in {phones}"
    
    print(f"[PASS] Extraction test passed!")
    print(f"   Found links: {intel['phishingLinks']}")
    print(f"   Found phones: {intel['phoneNumbers']}")

def test_extraction_with_multiple_indicators():
    """Test extraction with multiple URLs, phones, and UPI IDs."""
    payload = {
        "sessionId": "extract-test-002",
        "message": {
            "sender": "scammer",
            "text": "Pay via UPI: scammer@paytm or call 9123456789. Also visit http://phishing.com and http://evil.site",
            "timestamp": "2026-02-01T16:00:00.000Z"
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
    intel = data["extractedIntelligence"]
    
    # Should find UPI
    assert len(intel["upiIds"]) > 0, "Expected to find UPI IDs"
    
    # Should find phone
    assert len(intel["phoneNumbers"]) > 0, "Expected to find phone numbers"
    
    # Should find multiple URLs
    assert len(intel["phishingLinks"]) >= 2, "Expected to find at least 2 URLs"
    
    print(f"[PASS] Multiple indicators test passed!")
    print(f"   UPIs: {intel['upiIds']}")
    print(f"   Phones: {intel['phoneNumbers']}")
    print(f"   Links: {intel['phishingLinks']}")

def test_extraction_accumulates_across_messages():
    """Test that extraction accumulates intelligence across multiple messages in same session."""
    session_id = "extract-test-003"
    
    # First message with URL
    payload1 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Click here: http://scam1.com",
            "timestamp": "2026-02-01T16:00:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    response1 = client.post(
        "/api/honeypot",
        json=payload1,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response1.status_code == 200
    data1 = response1.json()
    intel1 = data1["extractedIntelligence"]
    
    # Should have 1 link
    assert len(intel1["phishingLinks"]) >= 1
    
    # Second message with different URL and phone
    payload2 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Also visit http://scam2.com or call 9988776655",
            "timestamp": "2026-02-01T16:01:00.000Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    response2 = client.post(
        "/api/honeypot",
        json=payload2,
        headers={"x-api-key": settings.HONEYPOT_API_KEY}
    )
    
    assert response2.status_code == 200
    data2 = response2.json()
    intel2 = data2["extractedIntelligence"]
    
    # Should have accumulated both URLs
    assert len(intel2["phishingLinks"]) >= 2, \
        f"Expected at least 2 links, got {len(intel2['phishingLinks'])}"
    
    # Should have phone number
    assert len(intel2["phoneNumbers"]) >= 1
    
    print(f"[PASS] Accumulation test passed!")
    print(f"   Message 1 links: {intel1['phishingLinks']}")
    print(f"   Message 2 links: {intel2['phishingLinks']}")
    print(f"   Message 2 phones: {intel2['phoneNumbers']}")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
