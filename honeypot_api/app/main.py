import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict

from fastapi import FastAPI, Depends, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.models import (
    RequestPayload, SuccessResponse, Message, Sender
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
    
    # Return valid SuccessResponse instead of error
    response = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="System error occurred. Please try again."
    )
    
    return JSONResponse(
        status_code=200,
        content=response.model_dump()
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """HTTP exception handler - returns HTTP 200 with fallback response."""
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] HTTP exception {exc.status_code}: {exc.detail}",
        exc_info=True
    )
    
    # Return valid SuccessResponse instead of error
    response = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="Request error occurred. Please try again."
    )
    
    return JSONResponse(
        status_code=200,
        content=response.model_dump()
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Validation error handler - returns HTTP 200 with fallback response."""
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] Validation error: {exc.errors()}",
        exc_info=True
    )
    
    # Return valid SuccessResponse instead of error
    response = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="Invalid request format. Please check your payload."
    )
    
    return JSONResponse(
        status_code=200,
        content=response.model_dump()
    )

@app.exception_handler(json.JSONDecodeError)
async def json_decode_error_handler(request: Request, exc: json.JSONDecodeError):
    """JSON decode error handler - returns HTTP 200 with fallback response."""
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] JSON decode error: {str(exc)}",
        exc_info=True
    )
    
    # Return valid SuccessResponse instead of error
    response = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="Invalid JSON format. Please send valid JSON."
    )
    
    return JSONResponse(
        status_code=200,
        content=response.model_dump()
    )

# ============================================================================
# ROUTES
# ============================================================================

@app.get("/")
def root():
    """Health check endpoint for hackathon evaluation."""
    return {"status": "ok", "service": "honeypot", "endpoint": "/api/honeypot"}

@app.post("/api/honeypot", response_model=SuccessResponse)
async def honeypot_endpoint(
    request: Request,
    payload: RequestPayload,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    HARDENED: Guaranteed to return HTTP 200 with valid SuccessResponse.
    Never returns 401/422/400/500 - all errors return success schema with fallback data.
    """
    request_id = get_request_id()
    
    try:
        # ====================================================================
        # AUTH CHECK (non-blocking)
        # ====================================================================
        if api_key is None:
            logger.warning(f"[{request_id}] Auth failed - returning fallback response")
            return build_success_response(
                scam_detected=False,
                engagement_duration=0,
                total_messages=0,
                extracted_intel=None,
                agent_reply="Missing API key."
            )
        
        # ====================================================================
        # INPUT VALIDATION & CAPS
        # ====================================================================
        session_id = payload.sessionId or f"session-{request_id[:8]}"
        now = datetime.now()
        
        # Cap message text to 4000 chars
        incoming_text = (payload.message.text or "")[:4000]
        
        # Cap conversationHistory to 30 messages, each text to 1000 chars
        conversation_history = payload.conversationHistory or []
        if len(conversation_history) > 30:
            conversation_history = conversation_history[:30]
        
        # Normalize conversation history messages
        normalized_history = []
        for msg in conversation_history:
            try:
                if isinstance(msg, Message):
                    # Cap text length
                    if len(msg.text) > 1000:
                        msg.text = msg.text[:1000]
                    normalized_history.append(msg)
                elif isinstance(msg, dict):
                    # Convert dict to Message
                    text = str(msg.get('text', ''))[:1000]
                    sender = msg.get('sender', 'scammer')
                    timestamp = msg.get('timestamp', now)
                    normalized_history.append(Message(
                        sender=sender,
                        text=text,
                        timestamp=timestamp
                    ))
            except Exception as e:
                logger.warning(f"[{request_id}] Failed to normalize history message: {e}")
                continue
        
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
            "timestamp": (payload.message.timestamp or now).isoformat()
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
        # SAVE SESSION & BUILD RESPONSE
        # ====================================================================
        store.save_session(session_id, session)

        # Calculate duration
        duration = calculate_engagement_duration(session["started_at"])

        # Build response using centralized builder
        return build_success_response(
            scam_detected=session["scamDetected"],
            engagement_duration=duration,
            total_messages=session["totalMessagesExchanged"],
            extracted_intel=session["extractedIntelligence"],
            agent_notes=session.get("agentNotes", ""),
            agent_reply=agent_reply_text if session["scamDetected"] else ""
        )
    
    except Exception as e:
        # ====================================================================
        # CRITICAL FALLBACK: Never return HTTP 500
        # ====================================================================
        logger.exception(f"[{request_id}] CRITICAL ERROR in honeypot_endpoint: {e}")
        
        # Return safe fallback response matching GUVI schema
        return build_success_response(
            scam_detected=False,
            engagement_duration=0,
            total_messages=0,
            extracted_intel=None,
            agent_reply=agent._fallback_reply()
        )
