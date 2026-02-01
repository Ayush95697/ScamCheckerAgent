from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from app.main import app
import os
from app.store import store

from app.config import settings

client = TestClient(app)
API_KEY = settings.HONEYPOT_API_KEY

@patch("app.main.send_final_result_callback", new_callable=AsyncMock)
def test_callback_trigger_logic(mock_callback):
    # Configure mock return value
    mock_callback.return_value = (True, 200, "Success")
    
    # Setup session with enough messages but no intel yet
    session_id = "callback-test-1"
    
    # Init store with state close to completion
    # Need 8 messages + scam detected
    store.save_session(session_id, {
        "started_at": "2023-01-01T12:00:00",
        "totalMessagesExchanged": 7,
        "scamDetected": True,
        "callback_sent": False,
        "extractedIntelligence": {
            "bankAccounts": [], "upiIds": [], "phishingLinks": [], 
            "phoneNumbers": [], "suspiciousKeywords": []
        },
        "agentNotes": "Detected scam",
        "last_agent_reply": "Ok"
    })

    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer", 
            "text": "Send money now", 
            "timestamp": "2023-01-01T12:05:00"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "US"}
    }
    
    # This request should bump totalMessagesExchanged to 8 (User) + 1 (Agent) = 9
    # And since scamDetected=True, it should trigger callback
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": API_KEY}
    )
    
    assert response.status_code == 200
    # Expected: send_final_result_callback called once
    assert mock_callback.call_count == 1
    
    # Verify session state updated
    session = store.get_session(session_id)
    assert session["callback_sent"] is True

    # Send another request, callback should NOT be sent again
    mock_callback.reset_mock()
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": API_KEY}
    )
    assert response.status_code == 200
    assert mock_callback.call_count == 0

@patch("app.main.send_final_result_callback", new_callable=AsyncMock)
def test_callback_not_triggered_early(mock_callback):
    mock_callback.return_value = (True, 200, "Success")
    session_id = "callback-test-2"
    # New session
    
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer", 
            "text": "Hello", 
            "timestamp": "2023-01-01T12:05:00"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "en", "locale": "US"}
    }
    
    response = client.post(
        "/api/honeypot",
        json=payload,
        headers={"x-api-key": API_KEY}
    )
    
    assert response.status_code == 200
    assert mock_callback.call_count == 0
