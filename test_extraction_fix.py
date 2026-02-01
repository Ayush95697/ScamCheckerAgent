import httpx
import asyncio
import json

async def test_extraction():
    url = "http://localhost:8000/api/honeypot"
    headers = {
        "x-api-key": "voidai",
        "Content-Type": "application/json"
    }
    
    payload = {
        "sessionId": "test-extraction-fix-3",
        "message": {
            "sender": "scammer",
            "text": "Link: http://bit.ly/kyc2026 Call +91 9876543210",
            "timestamp": "2026-02-01T20:45:00Z"
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "en",
            "locale": "IN"
        }
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json=payload, headers=headers, timeout=15.0)
            print(f"Status: {response.status_code}")
            result = response.json()
            print(json.dumps(result, indent=2))
            
            intel = result.get("extractedIntelligence", {})
            links = intel.get("phishingLinks", [])
            phones = intel.get("phoneNumbers", [])
            
            link_ok = any("bit.ly/kyc2026" in l for l in links)
            phone_ok = "+919876543210" in phones
            
            if link_ok and phone_ok:
                print("\nSUCCESS: Extraction fix verified!")
            else:
                print("\nFAIL: Extraction missing data.")
                if not link_ok: print(f"  Missing link. Found: {links}")
                if not phone_ok: print(f"  Missing phone. Found: {phones}")
                
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_extraction())
