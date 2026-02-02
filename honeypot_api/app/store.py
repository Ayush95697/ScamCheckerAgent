import json
# import redis  # DISABLED: Redis completely removed for hackathon stability
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.config import settings
from app.models import Message, Sender

class SessionStore:
    def get_session(self, session_id: str) -> Dict[str, Any]:
        """Get session data."""
        raise NotImplementedError

    def save_session(self, session_id: str, data: Dict[str, Any]):
        """Save session data."""
        raise NotImplementedError

    def append_internal_message(self, session_id: str, sender: str, text: str, timestamp: str):
        """Append a message to self-managed internal history."""
        raise NotImplementedError

    def get_combined_history(self, session_id: str, platform_history: List[Message]) -> List[Message]:
        """Merge platform history with internal history."""
        raise NotImplementedError

class InMemorySessionStore(SessionStore):
    def __init__(self):
        self._store = {}

    def get_session(self, session_id: str) -> Dict[str, Any]:
        return self._store.get(session_id, {})

    def save_session(self, session_id: str, data: Dict[str, Any]):
        self._store[session_id] = data

    def append_internal_message(self, session_id: str, sender: str, text: str, timestamp: str):
        session = self.get_session(session_id)
        if not session:
            # Should ideally be initialized before calling this
            return
        
        internal = session.get("internalHistory", [])
        new_msg = {"sender": sender, "text": text, "timestamp": timestamp}
        internal.append(new_msg)
        session["internalHistory"] = internal
        self.save_session(session_id, session)

    def get_combined_history(self, session_id: str, platform_history: List[Message]) -> List[Message]:
        session = self.get_session(session_id)
        internal = session.get("internalHistory", [])
        
        # Convert internal dicts to Message objects
        internal_msgs = []
        for m in internal:
            try:
                # Coerce sender
                sender = Sender(m["sender"])
                
                ts = datetime.fromisoformat(m["timestamp"]) if isinstance(m["timestamp"], str) else m["timestamp"]
                internal_msgs.append(Message(sender=sender, text=m["text"], timestamp=ts))
            except Exception:
                continue

        # Combine and deduplicate
        combined = []
        seen = set()
        
        # Helper for dedupe key
        def get_key(msg: Message):
            # Normalize sender to string always
            s_str = msg.sender.value if isinstance(msg.sender, Sender) else str(msg.sender)
            # Normalize text for dedupe
            text_norm = msg.text.strip().lower()
            # Normalize timestamp to ISO string
            ts_iso = msg.timestamp.isoformat()
            return (s_str, text_norm, ts_iso)

        # Add platform history first
        for m in platform_history:
            key = get_key(m)
            if key not in seen:
                seen.add(key)
                combined.append(m)
        
        # Add internal history
        for m in internal_msgs:
            key = get_key(m)
            if key not in seen:
                seen.add(key)
                combined.append(m)
                
        # Sort by timestamp
        combined.sort(key=lambda x: x.timestamp)
        return combined

# DISABLED: RedisSessionStore completely removed for hackathon stability
# class RedisSessionStore(SessionStore):
#     def __init__(self, redis_url: str):
#         self._redis = redis.from_url(redis_url, decode_responses=True)
#     ...

def get_store() -> SessionStore:
    """
    HARDENED: Always return InMemorySessionStore regardless of REDIS_URL.
    Redis is completely disabled for hackathon stability.
    """
    # Force in-memory store - no Redis dependency
    return InMemorySessionStore()

store = get_store()
