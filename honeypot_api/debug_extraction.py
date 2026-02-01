from app.extraction import extractor
from app.models import Message, Sender
from datetime import datetime

def test_extraction():
    text = "Sir KYC pending hai. Turant update karo nahi toh account freeze ho jayega. Link: http://bit.ly/kyc2026 Call +91 9876543210"
    
    print(f"Testing extraction for text: {text}\n")
    
    # Test direct text extraction
    results = extractor.extract_from_text(text)
    print("Direct Text Extraction Results:")
    for key, val in results.items():
        print(f"  {key}: {val}")
    print()
    
    # Test message-based extraction
    messages = [
        Message(sender=Sender.SCAMMER, text=text, timestamp=datetime.now())
    ]
    merged_results = extractor.extract_from_messages(messages)
    print("Message-based Extraction Results:")
    for key, val in merged_results.items():
        print(f"  {key}: {val}")

if __name__ == "__main__":
    test_extraction()
