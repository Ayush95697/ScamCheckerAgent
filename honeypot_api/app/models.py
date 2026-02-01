from datetime import datetime
from enum import Enum
from typing import List, Optional, Any
from pydantic import BaseModel, Field

# Constants for consistent error handling
ERROR_MESSAGE = "Invalid API key or malformed request"

class Channel(str, Enum):
    SMS = "SMS"
    WHATSAPP = "WhatsApp"
    EMAIL = "Email"
    CHAT = "Chat"

class Sender(str, Enum):
    SCAMMER = "scammer"
    USER = "user"

class Message(BaseModel):
    # This represents both user and scammer messages
    sender: Sender
    text: str = Field(..., min_length=1)
    timestamp: datetime

class Metadata(BaseModel):
    channel: Channel
    language: str
    locale: str

class RequestPayload(BaseModel):
    sessionId: str = Field(..., min_length=1)
    message: Message
    # Make conversationHistory OPTIONAL as per spec update
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Metadata

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
