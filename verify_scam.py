import asyncio
import sys
import os

# Add the project root to sys.path
sys.path.append(os.getcwd())

from app.scam_detection import detector

async def test_cases():
    cases = [
        {
            "name": "Japan vs Pan (Tokenization)",
            "text": "I am traveling to Japan",
            "expected_scam": False,
            "desc": "Keyword 'pan' should not match 'Japan'"
        },
        {
            "name": "Obfuscated OTP (Normalization)",
            "text": "Your o.t.p is 1234. Please verify! Urgent!",
            "expected_scam": True,
            "desc": "'o.t.p' + verify + urgent should reach threshold"
        },
        {
            "name": "Digit Obfuscation (Normalization)",
            "text": "Send me your 0tp immediate for update",
            "expected_scam": True,
            "desc": "'0tp' + immediate + update should reach threshold"
        },
        {
            "name": "Hinglish Urgency",
            "text": "Jaldi kyc update karo warna account band ho jayega",
            "expected_scam": True,
            "desc": "Hinglish urgency phrases should trigger"
        },
        {
            "name": "Hinglish Payment",
            "text": "Apna upi id send karo reward aur inaam ke liye turant",
            "expected_scam": True,
            "desc": "Hinglish payment/urgency phrases should trigger"
        },
        {
            "name": "Benign Negative Signals",
            "text": "Hello hi, thank you for the assignment. ok.",
            "expected_scam": False,
            "desc": "Benign words should reduce score"
        },
        {
            "name": "URL Shortener extra detection",
            "text": "Click this bit.ly/test to verify your account!",
            "expected_scam": True,
            "desc": "bit.ly/ + verify + account should reach threshold"
        },
        {
            "name": "History Rule (Strong current)",
            "text": "Verify your account at bit.ly/scam now!",
            "history": "Hello how are you",
            "expected_scam": True,
            "desc": "Strong evidence in current should trigger scam"
        },
        {
            "name": "History Rule (Weak current, Strong history)",
            "text": "Verify update verify update",
            "history": "Your account is frozen. Click link at bit.ly/scam immediately!",
            "expected_scam": True,
            "desc": "History evidence should trigger if total_score >= threshold + 0.10"
        }
    ]

    print(f"{'Test Name':<40} | {'Result':<10} | {'Score':<6}")
    print("-" * 60)

    for case in cases:
        # We need to peek into the detector or mock it to see internal flags, 
        # but for now let's just print the public result.
        is_scam, score = await detector.check_scam(case["text"], case.get("history", ""))
        status = "PASS" if is_scam == case["expected_scam"] else "FAIL"
        
        # Calculate text score again to see internal details if needed
        internal_score, strong_ev, any_ev = detector.calculate_text_score(case["text"])
        
        print(f"{case['name']:<40} | {status:<10} | {score:<6.2f}")
        print(f"  Internal: Score={internal_score:.2f}, StrongEv={strong_ev}, AnyEv={any_ev}")
        if status == "FAIL":
            print(f"  FAILED: {case['desc']}")
            print(f"  Text: {case['text']}")
            print(f"  History: {case.get('history', '')}")
            print(f"  Got is_scam={is_scam}, score={score}")
        print("-" * 60)

if __name__ == "__main__":
    asyncio.run(test_cases())
