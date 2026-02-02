from fastapi import Header
from typing import Optional
from app.config import settings
import logging

logger = logging.getLogger("honeypot-api")

async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> Optional[str]:
    """
    Verify API key without raising exceptions.
    Returns the key if valid, None if invalid/missing.
    This allows the route to handle auth failures gracefully.
    """
    if x_api_key is None:
        logger.warning("Missing x-api-key header")
        return None
    
    if x_api_key != settings.HONEYPOT_API_KEY:
        logger.warning(f"Invalid API key provided: {x_api_key[:8]}...")
        return None
    
    return x_api_key
