import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from app.models import SuccessResponse, EngagementMetrics, ExtractedIntelligence
from app.agent import agent

logger = logging.getLogger("honeypot-api")

def cap_list(items: List[str], max_size: int) -> List[str]:
    """Cap list size and deduplicate."""
    unique_items = list(dict.fromkeys(items))  # Preserve order while deduplicating
    return unique_items[:max_size]

async def safe_agent_reply(
    current_message: str,
    merged_history: List[Any],
    intel_so_far: Dict,
    turn_index: int,
    timeout_seconds: float = 8.0
) -> str:
    """
    Safely generate agent reply with timeout and fallback.
    Guarantees non-empty string return.
    """
    try:
        reply = await asyncio.wait_for(
            agent.generate_reply(
                current_message=current_message,
                merged_history=merged_history,
                intel_so_far=intel_so_far,
                turn_index=turn_index
            ),
            timeout=timeout_seconds
        )
        
        if not reply or not reply.strip():
            logger.warning("Agent returned empty reply, using fallback")
            return agent._fallback_reply()
        
        # Truncate to 500 chars max
        if len(reply) > 500:
            reply = reply[:497] + "..."
        
        return reply.strip()
    
    except asyncio.TimeoutError:
        logger.error(f"Agent reply timeout after {timeout_seconds}s")
        return agent._fallback_reply()
    
    except Exception as e:
        logger.error(f"Agent reply failed: {e}", exc_info=True)
        return agent._fallback_reply()

def build_success_response(
    scam_detected: bool = False,
    engagement_duration: int = 0,
    total_messages: int = 0,
    extracted_intel: Optional[Dict[str, List[str]]] = None,
    agent_notes: str = "",
    agent_reply: str = ""
) -> SuccessResponse:
    """
    Build guaranteed valid SuccessResponse.
    Always returns proper schema with all required fields.
    """
    # Default empty intelligence
    if extracted_intel is None:
        extracted_intel = {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        }
    
    # Cap list sizes
    capped_intel = {
        "bankAccounts": cap_list(extracted_intel.get("bankAccounts", []), 20),
        "upiIds": cap_list(extracted_intel.get("upiIds", []), 20),
        "phishingLinks": cap_list(extracted_intel.get("phishingLinks", []), 20),
        "phoneNumbers": cap_list(extracted_intel.get("phoneNumbers", []), 20),
        "suspiciousKeywords": cap_list(extracted_intel.get("suspiciousKeywords", []), 50)
    }
    
    # Format agent notes - ALWAYS start with "nextReply: "
    if agent_reply:
        # Truncate reply if needed
        if len(agent_reply) > 500:
            agent_reply = agent_reply[:497] + "..."
        formatted_notes = f"nextReply: {agent_reply}"
    elif agent_notes:
        # If notes provided but no reply, ensure format
        if not agent_notes.startswith("nextReply:"):
            formatted_notes = f"nextReply: {agent_notes}"
        else:
            formatted_notes = agent_notes
    else:
        # Default fallback
        formatted_notes = f"nextReply: {agent._fallback_reply()}"
    
    return SuccessResponse(
        status="success",
        scamDetected=scam_detected,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=max(0, engagement_duration),
            totalMessagesExchanged=max(0, total_messages)
        ),
        extractedIntelligence=ExtractedIntelligence(**capped_intel),
        agentNotes=formatted_notes
    )
