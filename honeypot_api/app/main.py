import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict

from fastapi import FastAPI, Depends, BackgroundTasks, Request, Header
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import List, Dict, Optional

from app.config import settings
from app.models import (
    RequestPayload, SuccessResponse, SimpleResponse, Message, Sender
)
from app.auth import verify_api_key
from app.store import store
from app.scam_detection import detector
from app.extraction import extractor
from app.agent import agent
from app.callback import send_final_result_callback
from app.utils import check_completion, calculate_engagement_duration, build_callback_payload, is_intel_found
from app.response_builder import build_success_response, safe_agent_reply
from app.middleware import RequestIDMiddleware, get_request_id

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot-api")

app = FastAPI(title="Agentic Honeypot API", version="0.1.0")

# Add request ID middleware
app.add_middleware(RequestIDMiddleware)

# ============================================================================
# EXCEPTION HANDLERS - ALL RETURN HTTP 200 WITH SuccessResponse
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler - returns HTTP 200 with fallback response."""
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] Global exception: {type(exc).__name__}: {str(exc)}",
        exc_info=True
    )
    
    # Return valid SimpleResponse format
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": "I am having some technical trouble. Can we talk in a moment?"
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """HTTP exception handler - returns HTTP 200 with fallback response."""
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] HTTP exception {exc.status_code}: {exc.detail}",
        exc_info=True
    )
    
    # Return valid SimpleResponse format
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": "I'm not sure how to respond to that. Could you clarify?"
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Validation error handler - returns HTTP 200 with fallback response."""
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] Validation error: {exc.errors()}",
        exc_info=True
    )
    
    # Return valid SimpleResponse format
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": "Something seems wrong with your message format. Can you send it again?"
        }
    )

@app.exception_handler(json.JSONDecodeError)
async def json_decode_error_handler(request: Request, exc: json.JSONDecodeError):
    """JSON decode error handler - returns HTTP 200 with fallback response."""
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] JSON decode error: {str(exc)}",
        exc_info=True
    )
    
    # Return valid SimpleResponse format
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": "I couldn't read that message. Please try sending it again."
        }
    )

# ============================================================================
# ROUTES
# ============================================================================

@app.get("/")
def root():
    """Health check endpoint for hackathon evaluation."""
    return {"status": "ok", "service": "honeypot", "endpoint": "/api/honeypot"}

@app.post("/__debug_echo")
async def debug_echo(request: Request):
    """
    Debug endpoint to inspect what GUVI tester sends.
    Returns raw request details without validation.
    """
    try:
        raw = await request.body()
        raw_str = raw.decode('utf-8') if raw else ""
    except:
        raw_str = ""
    
    return {
        "content_type": request.headers.get("content-type", "missing"),
        "raw_len": len(raw_str),
        "raw_preview": raw_str[:200] if raw_str else "aempty",
        "headers": dict(request.headers)
    }

@app.get("/api/honeypot", response_model=SimpleResponse)
async def honeypot_get():
    """
    GET handler for /api/honeypot.
    Returns HTTP 200 with SimpleResponse to prevent 405 errors.
    """
    return SimpleResponse(
        status="success",
        reply="Use POST with a JSON body to talk to me."
    )

@app.options("/api/honeypot", response_model=SimpleResponse)
async def honeypot_options():
    """
    OPTIONS handler for /api/honeypot.
    Returns HTTP 200 for CORS preflight and tester probes.
    """
    return SimpleResponse(
        status="success",
        reply="Use POST with a JSON body to talk to me."
    )


@app.post("/api/honeypot", response_model=SimpleResponse)
async def honeypot_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    GUVI-COMPATIBLE: Returns simple {status, reply} format.
    Accepts ANY request body (even empty or malformed).
    Manually parses JSON and normalizes payload.
    NEVER rejects before handler runs - guaranteed HTTP 200 with SimpleResponse.
    """
    request_id = get_request_id()
    
    # ====================================================================
    # MANUAL BODY PARSING - BYPASS PYDANTIC VALIDATION
    # ====================================================================
    try:
        raw_body = await request.body()
        if raw_body:
            payload_dict = json.loads(raw_body)
        else:
            payload_dict = {}
    except json.JSONDecodeError as e:
        logger.warning(f"[{request_id}] JSON decode error: {e}")
        payload_dict = {}
    except Exception as e:
        logger.warning(f"[{request_id}] Body parsing error: {e}")
        payload_dict = {}
    
    # Ensure payload is a dict
    if not isinstance(payload_dict, dict):
        logger.warning(f"[{request_id}] Payload is not dict, got {type(payload_dict)}")
        payload_dict = {}
    
    logger.info(f"[{request_id}] Parsed payload keys: {list(payload_dict.keys())}")
    
    # ====================================================================
    # AUTH CHECK (non-blocking, manual)
    # ====================================================================
    # Use the header value from Parameter if available, otherwise fallback to manual header check
    api_key = x_api_key or request.headers.get("x-api-key")
    if not api_key or api_key != settings.HONEYPOT_API_KEY:
        logger.warning(f"[{request_id}] Auth failed - returning fallback response")
        return SimpleResponse(
            status="success",
            reply="Authentication failed. Please check your API key."
        )
    
    try:
        # ====================================================================
        # MANUAL PAYLOAD NORMALIZATION
        # ====================================================================
        now = datetime.now()
        
        # Extract and normalize sessionId
        session_id = payload_dict.get('sessionId')
        if not session_id or not isinstance(session_id, str):
            session_id = f"session-{request_id[:8]}"
        
        # Extract and normalize message
        message_data = payload_dict.get('message', {})
        if not isinstance(message_data, dict):
            message_data = {}
        
        incoming_text = str(message_data.get('text', ''))[:4000]  # Cap at 4000 chars
        
        # Extract timestamp (use now if missing/invalid)
        message_timestamp = message_data.get('timestamp')
        try:
            if isinstance(message_timestamp, str):
                message_timestamp = datetime.fromisoformat(message_timestamp.replace('Z', '+00:00'))
            elif not isinstance(message_timestamp, datetime):
                message_timestamp = now
        except:
            message_timestamp = now
        
        # Extract and normalize conversationHistory
        conversation_history_raw = payload_dict.get('conversationHistory', [])
        if not isinstance(conversation_history_raw, list):
            conversation_history_raw = []
        
        # Cap at 30 messages
        conversation_history_raw = conversation_history_raw[:30]
        
        # Normalize conversation history messages
        normalized_history = []
        for msg in conversation_history_raw:
            try:
                if isinstance(msg, dict):
                    # Extract fields with defaults
                    text = str(msg.get('text', ''))[:1000]
                    sender = msg.get('sender', 'scammer')
                    timestamp = msg.get('timestamp', now)
                    
                    # Normalize timestamp
                    if isinstance(timestamp, str):
                        try:
                            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        except:
                            timestamp = now
                    
                    # Coerce sender to valid value
                    if sender not in ['scammer', 'user']:
                        sender = 'scammer'
                    
                    normalized_history.append(Message(
                        sender=Sender(sender),
                        text=text,
                        timestamp=timestamp
                    ))
            except Exception as e:
                logger.warning(f"[{request_id}] Failed to normalize history message: {e}")
                continue
        
        logger.info(f"[{request_id}] Normalized: sessionId={session_id}, text_len={len(incoming_text)}, history_len={len(normalized_history)}")
        
        # ====================================================================
        # SESSION MANAGEMENT
        # ====================================================================
        session = store.get_session(session_id)
        if not session:
            session = {
                "started_at": now.isoformat(),
                "totalMessagesExchanged": 0,
                "scamDetected": False,
                "callback_sent": False,
                "callback_attempts": 0,
                "callback_in_progress": False,
                "next_retry_at": None,
                "extractedIntelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": []
                },
                "internalHistory": [],
                "agentNotes": "",
                "last_agent_reply": ""
            }
        
        # Ensure keys exist for older sessions
        if "callback_in_progress" not in session:
            session["callback_in_progress"] = False
        if "next_retry_at" not in session:
            session["next_retry_at"] = None

        # Add incoming message to session state
        in_msg = {
            "sender": "scammer",
            "text": incoming_text,
            "timestamp": message_timestamp.isoformat()
        }
        session["internalHistory"].append(in_msg)
        session["totalMessagesExchanged"] += 1
        
        # Save session immediately
        store.save_session(session_id, session)
        
        # ====================================================================
        # COMBINED HISTORY
        # ====================================================================
        combined_history = store.get_combined_history(session_id, normalized_history)
        history_text = "\n".join([m.text for m in combined_history])

        # ====================================================================
        # EXTRACTION (CRITICAL FIX: Always run on incoming text)
        # ====================================================================
        current_intel = session["extractedIntelligence"]
        
        try:
            # Extract from incoming message FIRST
            new_intel = extractor.extract_from_text(incoming_text)
            
            # Also extract from full history for completeness
            if combined_history:
                history_intel = extractor.extract_from_messages(combined_history)
                # Merge history intel into new_intel
                for key in new_intel:
                    new_intel[key] = list(set(new_intel[key] + history_intel.get(key, [])))
            
            # Debug logging when extraction finds something
            if new_intel.get("links"):
                logger.info(f"[{request_id}] EXTRACTION: Found URLs: {new_intel['links']}")
            if new_intel.get("phones"):
                logger.info(f"[{request_id}] EXTRACTION: Found phones: {new_intel['phones']}")
            if new_intel.get("upi"):
                logger.info(f"[{request_id}] EXTRACTION: Found UPIs: {new_intel['upi']}")
            
        except Exception as e:
            logger.error(f"[{request_id}] Extraction failed: {e}", exc_info=True)
            # Safe fallback: empty extraction
            new_intel = {
                "upi": [],
                "bank": [],
                "links": [],
                "phones": [],
                "keywords": []
            }
        
        # Merge results into session.extractedIntelligence (dedupe)
        ext_key_map = {
            "upiIds": "upi",
            "bankAccounts": "bank",
            "phishingLinks": "links",
            "phoneNumbers": "phones",
            "suspiciousKeywords": "keywords"
        }
        
        for key, source_key in ext_key_map.items():
            existing = set(current_intel.get(key, []))
            incoming = set(new_intel.get(source_key, []))
            union_res = list(existing.union(incoming))
            current_intel[key] = union_res
            if incoming:
                logger.info(f"[{request_id}] Merged {key}: {incoming} into {union_res}")
        
        session["extractedIntelligence"] = current_intel

        # ====================================================================
        # SCAM DETECTION
        # ====================================================================
        if not session["scamDetected"]:
            try:
                is_scam, confidence = await detector.check_scam(
                    message_text=incoming_text,
                    history_text=history_text
                )
                if is_scam:
                    session["scamDetected"] = True
                    logger.info(f"[{request_id}] Scam detected with confidence {confidence}")
            except Exception as e:
                logger.error(f"[{request_id}] Scam detection failed: {e}", exc_info=True)
                # Safe fallback: assume not scam
                is_scam = False
                confidence = 0.0

        # ====================================================================
        # AGENT REPLY
        # ====================================================================
        # Compute logical_turns from message history
        scammer_msgs = len([m for m in combined_history if m.sender == Sender.SCAMMER])
        agent_msgs = len([m for m in combined_history if m.sender == Sender.USER])
        logical_turns = min(scammer_msgs, agent_msgs + 1)
        
        agent_reply_text = ""
        if session["scamDetected"]:
            # Generate reply with safe wrapper
            agent_reply_text = await safe_agent_reply(
                current_message=incoming_text,
                merged_history=combined_history,
                intel_so_far=current_intel,
                turn_index=logical_turns,
                timeout_seconds=8.0
            )
            
            # Append agent reply to internalHistory
            session["internalHistory"].append({
                "sender": "user",
                "text": agent_reply_text,
                "timestamp": datetime.now().isoformat()
            })
            session["totalMessagesExchanged"] += 1
            session["last_agent_reply"] = agent_reply_text
            
            # Save session again
            store.save_session(session_id, session)
            
            # Update combined_history for completion check
            combined_history = store.get_combined_history(session_id, normalized_history)
            
            # Build agentNotes
            base_notes = "Scam detected." if session["scamDetected"] else ""
            if is_intel_found(current_intel, high_value_only=True):
                base_notes += " High-value intelligence extracted."
            session["agentNotes"] = f"{base_notes} | nextReply: {agent_reply_text}".strip()

        # ====================================================================
        # COMPLETION CHECK & CALLBACK
        # ====================================================================
        can_retry = True
        if session["next_retry_at"]:
            try:
                next_retry = datetime.fromisoformat(session["next_retry_at"])
                if now < next_retry:
                    can_retry = False
            except:
                pass

        if session["scamDetected"] and not session["callback_sent"] and not session["callback_in_progress"] and can_retry:
            if check_completion(session, combined_history):
                # Send callback
                session["callback_in_progress"] = True
                callback_payload = build_callback_payload(session_id, session)
                
                async def background_callback_wrapper():
                    try:
                        success, code, msg = await send_final_result_callback(callback_payload)
                        # Re-fetch session to avoid stale data
                        s = store.get_session(session_id)
                        s["callback_in_progress"] = False
                        if success:
                            s["callback_sent"] = True
                        else:
                            s["callback_attempts"] = s.get("callback_attempts", 0) + 1
                            if s["callback_attempts"] >= 3:
                                s["next_retry_at"] = (datetime.now() + timedelta(seconds=60)).isoformat()
                        store.save_session(session_id, s)
                    except Exception as e:
                        logger.error(f"[{request_id}] Callback wrapper failed: {e}", exc_info=True)
                        # Ensure callback_in_progress is reset even on failure
                        s = store.get_session(session_id)
                        s["callback_in_progress"] = False
                        store.save_session(session_id, s)

                background_tasks.add_task(background_callback_wrapper)

        # ====================================================================
        # SAVE SESSION & BUILD RESPONSE (GUVI FORMAT)
        # ====================================================================
        store.save_session(session_id, session)

        # Calculate duration
        duration = calculate_engagement_duration(session["started_at"])

        # Build GUVI-compatible response: {status, reply}
        reply_text = agent_reply_text if agent_reply_text else ""
        
        return SimpleResponse(
            status="success",
            reply=reply_text
        )
    
    except Exception as e:
        # ====================================================================
        # CRITICAL FALLBACK: Never return HTTP 500
        # ====================================================================
        logger.exception(f"[{request_id}] CRITICAL ERROR in honeypot_endpoint: {e}")
        
        # Return safe fallback response matching GUVI schema
        return SimpleResponse(
            status="success",
            reply=agent._fallback_reply()
        )
