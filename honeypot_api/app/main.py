import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, BackgroundTasks, Request, Response, Security
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models import Message, Sender
from app.store import store
from app.scam_detection import detector
from app.extraction import extractor
from app.agent import agent
from app.callback import send_final_result_callback
from app.utils import (
    check_completion,
    calculate_engagement_duration,
    build_callback_payload,
)
from app.middleware import RequestIDMiddleware, get_request_id

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot-api")

# Non-blocking API key header
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

app = FastAPI(
    title="Agentic Honeypot API",
    version="0.1.0",
    description="Agentic Honey-Pot for Scam Detection & Intelligence Extraction",
)

# -----------------------------------------------------------------------------
# CORS
# -----------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestIDMiddleware)

# -----------------------------------------------------------------------------
# DETERMINISTIC RESPONSE HELPER
# -----------------------------------------------------------------------------
def ok(reply: str) -> JSONResponse:
    """
    Authorized SINGLE response path.
    Guarantees strict {"status": "success", "reply": "..."} format.
    """
    # Defensive check: ensure reply is a non-empty string
    if not isinstance(reply, str) or not reply.strip():
        # Fallback to agent's fallback
        try:
            reply = agent._fallback_reply()
        except:
            reply = "Okay."
        
        # Fallback of last resort
        if not isinstance(reply, str) or not reply.strip():
            reply = "Okay."

    return JSONResponse(
        status_code=200,
        content={"status": "success", "reply": reply.strip()},
        media_type="application/json",
    )

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------
def _normalize_timestamp(ts: Any) -> datetime:
    now = datetime.now(timezone.utc)
    try:
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        if isinstance(ts, (int, float)):
            if ts > 10_000_000_000:
                return datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str) and ts.strip():
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return now
    return now

def _empty_intel() -> Dict[str, List[str]]:
    return {
        "bankAccounts": [], "upiIds": [], "phishingLinks": [],
        "phoneNumbers": [], "suspiciousKeywords": [],
    }

def _ensure_session(session_id: str, now: datetime) -> Dict[str, Any]:
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
            "extractedIntelligence": _empty_intel(),
            "internalHistory": [],
            "agentNotes": "",
            "last_agent_reply": "",
        }
    return session

# -----------------------------------------------------------------------------
# GLOBAL EXCEPTION HANDLERS (ALL RETURN 200 OK)
# -----------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return ok("I am having technical trouble. Please wait.")

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.error(f"HTTP {exc.status_code} {request.method} {request.url.path}")
    return ok("Please resend.")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error: {exc}")
    return ok("Message format error.")

@app.exception_handler(json.JSONDecodeError)
async def json_decode_error_handler(request: Request, exc: json.JSONDecodeError):
    logger.error(f"JSON decode error: {exc}")
    # Be robust: user message might just have bad chars
    return ok("I couldn't read that message. Please try sending it again.")

# -----------------------------------------------------------------------------
# PROBE ROUTE HANDLERS
# -----------------------------------------------------------------------------
@app.get("/")
def root():
    return ok("System online.")

@app.get("/api/honeypot")
@app.get("/api/honeypot/")
async def honeypot_get():
    return ok("Use POST.")

@app.options("/api/honeypot")
@app.options("/api/honeypot/")
async def honeypot_options():
    return ok("Allowed: POST, OPTIONS, HEAD, GET.")

@app.head("/api/honeypot")
@app.head("/api/honeypot/")
@app.head("/")
async def honeypot_head():
    return ok("OK")

# -----------------------------------------------------------------------------
# CORE LOGIC
# -----------------------------------------------------------------------------
async def _handle_honeypot(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str],
) -> JSONResponse:
    rid = get_request_id()

    # 1. Parse JSON manually
    payload = {}
    try:
        raw = await request.body()
        if raw:
            payload = json.loads(raw)
    except Exception as e:
        logger.warning(f"[{rid}] Parse failed: {e}")
        # Log raw for debugging if needed (middleware handles this too)
        return ok("Invalid JSON.")

    if not isinstance(payload, dict):
        return ok("Invalid payload.")

    # 2. Auth
    api_key = x_api_key or request.headers.get("x-api-key")
    if not api_key or api_key != settings.HONEYPOT_API_KEY:
        return ok("Missing or invalid API key.")

    # 3. Normalize
    now = datetime.now(timezone.utc)
    session_id = payload.get("sessionId")
    if not isinstance(session_id, str) or not session_id.strip():
        session_id = f"session-{rid[:8]}"

    msg_obj = payload.get("message", {})
    if not isinstance(msg_obj, dict):
        msg_obj = {}
    
    incoming_text = str(msg_obj.get("text", "") or "")[:4000]
    incoming_ts = _normalize_timestamp(msg_obj.get("timestamp"))

    conv_raw = payload.get("conversationHistory", [])
    if not isinstance(conv_raw, list):
        conv_raw = []
    
    normalized_history: List[Message] = []
    for m in conv_raw[:30]:
        if not isinstance(m, dict): continue
        try:
            t = str(m.get("text",""))[:1000]
            s = m.get("sender", "scammer")
            ts = _normalize_timestamp(m.get("timestamp"))
            if s not in ["scammer", "user"]: s = "scammer"
            normalized_history.append(Message(sender=Sender(s), text=t, timestamp=ts))
        except: continue

    # 4. Session & Storage
    session = _ensure_session(session_id, now)
    session["internalHistory"].append({
        "sender": "scammer",
        "text": incoming_text,
        "timestamp": incoming_ts.isoformat()
    })
    session["totalMessagesExchanged"] = session.get("totalMessagesExchanged", 0) + 1
    store.save_session(session_id, session)

    combined_history = store.get_combined_history(session_id, normalized_history)
    history_text = "\n".join([m.text for m in combined_history])

    # 5. Extraction
    current_intel = session["extractedIntelligence"]
    try:
        new_intel = extractor.extract_from_text(incoming_text)
        # Simplified merge logic
        for k, v in new_intel.items():
            current_intel[k] = list(set(current_intel.get(k, []) + v))
        session["extractedIntelligence"] = current_intel
    except Exception as e:
        logger.error(f"Extraction error: {e}")

    # 6. Scam Detection
    if not session.get("scamDetected", False):
        try:
            is_scam, confidence = await detector.check_scam(incoming_text, history_text)
            if is_scam:
                session["scamDetected"] = True
        except Exception as e:
            logger.error(f"Detection error: {e}")

    # 7. Agent Reply
    agent_reply_text = "Okay."
    if session.get("scamDetected", False):
        try:
             # Calculate turn index
            scammer_msgs = len([m for m in combined_history if m.sender == Sender.SCAMMER])
            agent_msgs = len([m for m in combined_history if m.sender == Sender.USER])
            turn_index = min(scammer_msgs, agent_msgs + 1)
            
            # Using agent directly
            agent_reply_text = await agent.generate_reply(
                incoming_text, combined_history, current_intel, turn_index
            )
        except:
            agent_reply_text = agent._fallback_reply()
    
    if not agent_reply_text or not agent_reply_text.strip():
        agent_reply_text = agent._fallback_reply()

    # Update session
    session["internalHistory"].append({
        "sender": "user", 
        "text": agent_reply_text, 
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    session["totalMessagesExchanged"] += 1
    session["last_agent_reply"] = agent_reply_text
    
    # Summary for callback (NOT nextReply)
    u_count = len(current_intel.get("upiIds", []))
    b_count = len(current_intel.get("bankAccounts", []))
    session["agentNotes"] = f"ScamDetected: {session['scamDetected']}. Msgs: {session['totalMessagesExchanged']}. UPI: {u_count}, Bank: {b_count}."

    # 8. Callback Background Task
    if session.get("scamDetected", False) and not session.get("callback_sent", False) and not session.get("callback_in_progress", False):
        # Retry logic check...
        can_retry = True
        if session.get("next_retry_at"):
            try:
                next_retry = datetime.fromisoformat(session["next_retry_at"])
                if next_retry.tzinfo is None:
                    next_retry = next_retry.replace(tzinfo=timezone.utc)
                if now < next_retry:
                    can_retry = False
            except: pass
        
        if can_retry and check_completion(session, combined_history):
            session["callback_in_progress"] = True
            store.save_session(session_id, session)
            
            payload = build_callback_payload(session_id, session)
            async def bg_callback():
                try:
                    success, code, msg = await send_final_result_callback(payload)
                    s = store.get_session(session_id)
                    if s:
                        s["callback_in_progress"] = False
                        if success: s["callback_sent"] = True
                        else: 
                             s["callback_attempts"] = s.get("callback_attempts", 0) + 1
                             s["next_retry_at"] = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
                        store.save_session(session_id, s)
                except Exception as e:
                     logger.error(f"Callback error: {e}")
                     s = store.get_session(session_id)
                     if s:
                        s["callback_in_progress"] = False
                        store.save_session(session_id, s)

            background_tasks.add_task(bg_callback)

    store.save_session(session_id, session)
    return ok(agent_reply_text)

# -----------------------------------------------------------------------------
# POST ENTRY POINTS
# -----------------------------------------------------------------------------
@app.post("/api/honeypot")
@app.post("/api/honeypot/")
@app.post("/")
async def honeypot_entry(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Security(api_key_header),
):
    try:
        return await _handle_honeypot(request, background_tasks, x_api_key)
    except Exception as e:
        logger.error(f"Entry error: {e}")
        return ok("System busy.")
