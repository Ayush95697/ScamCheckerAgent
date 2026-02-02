from datetime import datetime
from enum import Enum
from typing import List, Optional, Any, Union
from pydantic import BaseModel, Field, field_validator, model_validator
import uuid

# Constants for consistent error handling
ERROR_MESSAGE = "Invalid API key or malformed request"

class Sender(str, Enum):
    SCAMMER = "scammer"
    USER = "user"

class Message(BaseModel):
    """Lenient message model - accepts flexible inputs."""
    sender: Union[Sender, str] = "scammer"
    text: str = ""  # Allow empty strings, no min_length
    timestamp: Optional[Union[str, datetime]] = None
    
    @field_validator('sender', mode='before')
    @classmethod
    def coerce_sender(cls, v):
        """Coerce sender to valid enum value."""
        if isinstance(v, str):
            v_lower = v.lower()
            if v_lower in ["scammer", "user"]:
                return v_lower
        return "scammer"  # Default fallback
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def coerce_timestamp(cls, v):
        """Accept string, datetime, or None."""
        if v is None:
            return datetime.now()
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except:
                return datetime.now()
        if isinstance(v, datetime):
            return v
        return datetime.now()

class Metadata(BaseModel):
    """Lenient metadata - accepts any strings, no enum validation."""
    channel: str = "SMS"  # Changed from Enum to str
    language: str = "en"
    locale: str = "IN"

class RequestPayload(BaseModel):
    """Lenient request payload - all fields optional or have defaults."""
    sessionId: Optional[str] = None
    message: Optional[Message] = None
    conversationHistory: Optional[List[Any]] = None  # Accept any type, normalize later
    metadata: Optional[Metadata] = None
    
    @model_validator(mode='before')
    @classmethod
    def normalize_payload(cls, data):
        """Normalize and provide defaults for all fields."""
        if not isinstance(data, dict):
            data = {}
        
        # Generate sessionId if missing
        if not data.get('sessionId'):
            data['sessionId'] = f"session-{uuid.uuid4()}"
        
        # Ensure message exists
        if not data.get('message'):
            data['message'] = {
                "sender": "scammer",
                "text": "",
                "timestamp": datetime.now()
            }
        
        # Normalize conversationHistory to list
        history = data.get('conversationHistory')
        if history is None or not isinstance(history, list):
            data['conversationHistory'] = []
        else:
            # Cap at 30 messages
            data['conversationHistory'] = history[:30]
        
        # Ensure metadata exists
        if not data.get('metadata'):
            data['metadata'] = {
                "channel": "SMS",
                "language": "en",
                "locale": "IN"
            }
        
        return data

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int

class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)

class SuccessResponse(BaseModel):
    status: str = "success"
    scamDetected: bool
    engagementMetrics: EngagementMetrics
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str

class ErrorResponse(BaseModel):
    status: str = "error"
    message: str = ERROR_MESSAGE

class CallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str
