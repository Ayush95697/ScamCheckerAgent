import uuid
import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from contextvars import ContextVar

logger = logging.getLogger("honeypot-api")

# Context variable to store request_id across async calls
request_id_context: ContextVar[str] = ContextVar("request_id", default="")

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add request ID tracking.
    - Generates unique request_id for each request
    - Adds x-request-id response header
    - Logs request path, latency, and any exceptions
    """
    
    async def dispatch(self, request: Request, call_next):
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request_id_context.set(request_id)
        
        # Track start time
        start_time = time.time()
        
        # Log incoming request
        logger.info(f"[{request_id}] {request.method} {request.url.path}")
        
        try:
            # Process request
            response: Response = await call_next(request)
            
            # Calculate latency
            latency_ms = int((time.time() - start_time) * 1000)
            
            # Add request ID to response headers
            response.headers["x-request-id"] = request_id
            
            # Log completion
            logger.info(
                f"[{request_id}] {request.method} {request.url.path} "
                f"- {response.status_code} - {latency_ms}ms"
            )
            
            return response
        
        except Exception as e:
            # Log exception with request ID
            latency_ms = int((time.time() - start_time) * 1000)
            logger.error(
                f"[{request_id}] {request.method} {request.url.path} "
                f"- EXCEPTION: {type(e).__name__}: {str(e)} - {latency_ms}ms",
                exc_info=True
            )
            raise

def get_request_id() -> str:
    """Get current request ID from context."""
    return request_id_context.get()
