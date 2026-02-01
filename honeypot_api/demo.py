import requests
import json

url = "http://localhost:8000/api/honeypot"
headers = {
    "x-api-key": "test-api-key-123",
    "Content-Type": "application/json"
}

payload = {
    "sessionId": "demo-session-python-1",
    "message": {
        "sender": "scammer",
        "text": "URGENT: Your account is blocked. Click http://scam-site.com/verify to unlock immediately.",
        "timestamp": "2023-10-27T10:00:00Z"
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "SMS",
        "language": "en",
        "locale": "IN"
    }
}

try:
    response = requests.post(url, headers=headers, json=payload)
    print(f"Status Code: {response.status_code}")
    print("Response JSON:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
