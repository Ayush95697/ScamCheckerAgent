from fastapi import Header, HTTPException, status
from typing import Optional
from app.config import settings

async def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key is None or x_api_key != settings.HONEYPOT_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"status": "error", "message": "Invalid API key or malformed request"}
        )
    return x_api_key
