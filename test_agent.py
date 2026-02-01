import asyncio
import sys
import os

# Add project root to sys.path
sys.path.append(os.path.join(os.getcwd(), "honeypot_api"))
os.chdir("honeypot_api")

from app.agent import agent
from app.models import Message, Sender

async def main():
    print(f"Agent Client: {agent.client}")
    print(f"API Key present: {bool(agent.api_key)}")
    print(f"API Key: {agent.api_key}")
    
    msg = "Hi, update your kyc now at bit.ly/scam"
    history = []
    intel = {"upiIds": [], "bankAccounts": [], "phishingLinks": [], "phoneNumbers": []}
    
    try:
        reply = await agent.generate_reply(msg, history, intel, 0)
        print(f"\nScammer: {msg}")
        print(f"Agent: {reply}")
        
        # Check if it was a fallback
        fallbacks = [
            "Hello? I am not understanding properly. Can you explain correctly?",
            "My internet is slow, message is not loading fully. Please wait.",
            "Ok checking one minute...",
            "Where to click? I am confused.",
            "Sir, my son is calling, I will reply in 5 mins.",
            "Payment is failing repeatedly. What is UPI ID properly?",
            "Bank server down I think. Do you have other account?",
        ]
        if reply in fallbacks:
            print("\nWARNING: FALLBACK REPLY DETECTED!")
        else:
            print("\nSUCCESS: DYNAMIC REPLY GENERATED!")
            
    except Exception as e:
        print(f"\nERROR calling agent: {e}")

if __name__ == "__main__":
    asyncio.run(main())
