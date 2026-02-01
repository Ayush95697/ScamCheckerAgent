import pytest
from datetime import datetime, timedelta
from app.store import InMemorySessionStore
from app.models import Message, Sender, ExtractedIntelligence
from app.extraction import Extractor
from app.utils import check_completion
from app.scam_detection import ScamDetector

# 1) Session Deduplication
def test_session_deduplication():
    store = InMemorySessionStore()
    session_id = "test-dedupe"
    store.save_session(session_id, {"internalHistory": []})
    
    ts = datetime.now()
    # Same message, different casing
    msg1 = Message(sender=Sender.SCAMMER, text="HELLO", timestamp=ts)
    msg2 = Message(sender=Sender.SCAMMER, text="hello", timestamp=ts)
    
    # Internal history has msg1 (saved as dict)
    store.append_internal_message(session_id, "scammer", "HELLO", ts.isoformat())
    
    # Platform history has msg2
    combined = store.get_combined_history(session_id, [msg2])
    
    assert len(combined) == 1
    assert combined[0].text == "hello" # Platform history usually wins if processed first or based on alphabetical? 
    # Actually my logic: platform first, then internal. So msg2 (hello) is seen first.

# 2) UPI Robustness
def test_upi_robustness():
    extractor = Extractor()
    text = "Contact me at abc@gmail.com or pay to name@okicici. Also avoid test@example.com"
    upis = extractor.extract_upi(text)
    
    assert "name@okicici" in upis
    assert "abc@gmail.com" not in upis
    assert "test@example.com" not in upis
    assert len(upis) == 1

# 3) Callback Trigger Logic
def test_callback_trigger_logic():
    session = {
        "scamDetected": True,
        "started_at": datetime.now().isoformat(),
        "extractedIntelligence": {
            "upiIds": [],
            "bankAccounts": [],
            "phishingLinks": []
        }
    }
    
    # 2 logical turns, no intel => False
    history = [
        Message(sender=Sender.SCAMMER, text="Hi", timestamp=datetime.now()),
        Message(sender=Sender.USER, text="Hello", timestamp=datetime.now()),
        Message(sender=Sender.SCAMMER, text="Pay me", timestamp=datetime.now())
    ]
    # logical_turns = min(2, 1 + 1) = 2
    assert check_completion(session, history) == False
    
    # Reach 4 turns and add intel => True
    session["extractedIntelligence"]["upiIds"] = ["test@upi"]
    history.extend([
        Message(sender=Sender.USER, text="How?", timestamp=datetime.now()),
        Message(sender=Sender.SCAMMER, text="Use this", timestamp=datetime.now()),
        Message(sender=Sender.USER, text="Ok", timestamp=datetime.now()),
        Message(sender=Sender.SCAMMER, text="Now", timestamp=datetime.now())
    ])
    # logical_turns = min(4, 3 + 1) = 4
    assert check_completion(session, history) == True

# 4) Scam Detection Baseline
@pytest.mark.asyncio
async def test_scam_detection_baseline():
    detector = ScamDetector()
    
    # Known scam message
    scam_text = "URGENT: Your bank account is blocked. Verify KYC immediately at http://scam.link/otp"
    is_scam, score = await detector.check_scam(scam_text)
    assert is_scam == True
    assert score >= 0.65
    
    # Normal message
    normal_text = "Hello, how are you today?"
    is_scam_norm, score_norm = await detector.check_scam(normal_text)
    assert is_scam_norm == False
    assert score_norm < 0.65
