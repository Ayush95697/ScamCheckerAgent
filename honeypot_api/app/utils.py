from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.models import ExtractedIntelligence, CallbackPayload

def cap_list(items: List[str], max_size: int) -> List[str]:
    """Cap list size and deduplicate while preserving order."""
    unique_items = list(dict.fromkeys(items))  # Preserve order while deduplicating
    return unique_items[:max_size]

def calculate_engagement_duration(started_at: Any) -> int:
    if isinstance(started_at, str):
        try:
            start_time = datetime.fromisoformat(started_at)
        except:
            return 0
    elif isinstance(started_at, datetime):
        start_time = started_at
    else:
        return 0
    
    # Ensure start_time is aware (UTC)
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
        
    now = datetime.now(timezone.utc)
    
    # Only subtract if start_time is valid
    if start_time > now:
        return 0
        
    return int((now - start_time).total_seconds())

def is_intel_found(extracted: Dict[str, List[str]], high_value_only: bool = False) -> bool:
    has_upi = bool(extracted.get('upiIds'))
    has_bank = bool(extracted.get('bankAccounts'))
    has_links = bool(extracted.get('phishingLinks'))
    
    if high_value_only:
        return has_upi or has_bank or has_links
    
    has_phones = bool(extracted.get('phoneNumbers'))
    has_keywords = bool(extracted.get('suspiciousKeywords'))
    
    return has_upi or has_bank or has_links or has_phones or has_keywords

def check_completion(session: Dict[str, Any], combined_history: List[Any]) -> bool:
    # Logic:
    # - If scamDetected is false => never complete.
    if not session.get('scamDetected', False):
        return False

    extracted = session.get('extractedIntelligence', {})
    if not isinstance(extracted, dict):
        extracted = extracted.model_dump() if hasattr(extracted, 'model_dump') else {}
        
    started_at = session.get('started_at')
    duration = calculate_engagement_duration(started_at) if started_at else 0

    # Compute logical_turns from message history
    from app.models import Sender
    scammer_msgs = len([m for m in combined_history if (m.sender.value if hasattr(m.sender, "value") else str(m.sender)) == Sender.SCAMMER.value])
    agent_msgs = len([m for m in combined_history if (m.sender.value if hasattr(m.sender, "value") else str(m.sender)) == Sender.USER.value])
    logical_turns = min(scammer_msgs, agent_msgs + 1)

    # Define high_value_found
    high_value_found = is_intel_found(extracted, high_value_only=True)

    # Engagement Completion Rules:
    # 1. High-value intel found + minimum turns (4 logical turns)
    if high_value_found and logical_turns >= 4:
        return True
        
    # 2. Max engagement cap (8 logical turns)
    if logical_turns >= 8:
        return True
        
    # 3. Time limit exceeded (5 minutes)
    if duration >= 300:
        return True

    return False

def build_callback_payload(session_id: str, session: Dict[str, Any]) -> CallbackPayload:
    extracted = session.get('extractedIntelligence', {})
    if not isinstance(extracted, dict):
        extracted = extracted.model_dump() if hasattr(extracted, 'model_dump') else {}
        
    intel_model = ExtractedIntelligence(**extracted)
    
    return CallbackPayload(
        sessionId=session_id,
        scamDetected=session.get('scamDetected', False),
        totalMessagesExchanged=session.get('totalMessagesExchanged', 0),
        extractedIntelligence=intel_model,
        agentNotes=session.get('agentNotes', "Engagement completed.")
    )
