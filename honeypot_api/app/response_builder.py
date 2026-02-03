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
) -> Dict[str, Any]:
    """
    Build guaranteed valid simple response for GUVI.
    Returns: {"status": "success", "reply": "..."}
    """
    # Ensure agent_reply is safe
    final_reply = agent_reply if agent_reply and agent_reply.strip() else agent._fallback_reply()
    
    # Truncate if excessively long (security/stability)
    if len(final_reply) > 1000:
        final_reply = final_reply[:997] + "..."

    return {
        "status": "success",
        "reply": final_reply.strip()
    }
