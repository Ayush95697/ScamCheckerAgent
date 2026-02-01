import httpx
import logging
import asyncio
from typing import Tuple
from app.config import settings
from app.models import CallbackPayload

logger = logging.getLogger("honeypot")

async def send_final_result_callback(payload: CallbackPayload) -> Tuple[bool, int, str]:
    """
    Sends the mandatory final result callback with retry logic.
    Returns: (success_bool, status_code, error_message)
    """
    url = settings.CALLBACK_URL
    timeout = settings.CALLBACK_TIMEOUT_SECONDS
    
    # Prepare data
    data = payload.model_dump()
    
    attempts = 2
    last_error = ""
    status_code = 0
    
    async with httpx.AsyncClient() as client:
        for attempt in range(attempts):
            try:
                response = await client.post(
                    url, json=data, timeout=timeout
                )
                status_code = response.status_code
                if response.is_success:
                    logger.info(f"Callback sent successfully: {status_code}")
                    return True, status_code, "Success"
                else:
                    last_error = f"HTTP {status_code}: {response.text}"
                    logger.warning(f"Callback attempt {attempt + 1} failed: {last_error}")
            
            except httpx.HTTPError as e:
                last_error = str(e)
                logger.warning(f"Callback attempt {attempt + 1} error: {last_error}")
            except Exception as e:
                last_error = str(e)
                logger.error(f"Callback attempt {attempt + 1} unhandled error: {last_error}")
            
            # Wait before retry if not last attempt
            if attempt < attempts - 1:
                await asyncio.sleep(0.2)
                
    return False, status_code, last_error
