import requests
import time

def test_kyc_extraction():
    url = "http://127.0.0.1:8000/api/honeypot"
    headers = {
        "x-api-key": "voidai",
        "Content-Type": "application/json"
    }
    
    payload = {
        "sessionId": f"extract-test-{int(time.time())}",
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
    
    print(f"Sending request to {url}...")
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print("Success! Response data:")
        extracted = data.get("extractedIntelligence", {})
        print(f"  Phones: {extracted.get('phoneNumbers')}")
        print(f"  Links: {extracted.get('phishingLinks')}")
        print(f"  Keywords: {extracted.get('suspiciousKeywords')}")
        
        # Validation
        if "+919876543210" in extracted.get('phoneNumbers', []):
            print("✅ Phone number extracted correctly.")
        else:
            print("❌ Phone number NOT extracted.")
            
        if any("bit.ly/kyc2026" in link for link in extracted.get('phishingLinks', [])):
            print("✅ Phishing link extracted correctly.")
        else:
            print("❌ Phishing link NOT extracted.")
            
        if "kyc" in extracted.get('suspiciousKeywords', []):
            print("✅ Keyword 'kyc' extracted correctly.")
        else:
            print("❌ Keyword 'kyc' NOT extracted.")
    else:
        print(f"Error! Status Code: {response.status_code}")
        print(f"Response: {response.text}")

if __name__ == "__main__":
    # Wait for server to be ready if called right after startup
    time.sleep(2)
    test_kyc_extraction()
