import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, BackgroundTasks, Request, Response, Security
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.security import APIKeyHeader

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
    is_intel_found,
)
from app.response_builder import build_success_response, safe_agent_reply
from app.middleware import RequestIDMiddleware, get_request_id

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot-api")

# Swagger security header (non-blocking)
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

app = FastAPI(
    title="Agentic Honeypot API",
    version="0.1.0",
    description="Agentic Honey-Pot for Scam Detection & Intelligence Extraction",
)

# Request ID middleware
app.add_middleware(RequestIDMiddleware)

# -----------------------------------------------------------------------------
# Force content-type (some testers omit Content-Type)
# -----------------------------------------------------------------------------
@app.middleware("http")
async def force_json_content_type(request: Request, call_next):
    """
    GUVI/endpoint-testers sometimes omit Content-Type.
    We still manually parse bytes, but adding content-type avoids upstream weirdness
    in some clients/middlewares.
    """
    try:
        # This is a bit hacky, but effective for hackathon testers.
        hdr_list = request.headers.__dict__.get("_list", None)
        if hdr_list is not None:
            has_ct = any(k.lower() == b"content-type" for (k, _v) in hdr_list)
            if not has_ct:
                hdr_list.append((b"content-type", b"application/json"))
    except Exception:
        pass
    return await call_next(request)

# -----------------------------------------------------------------------------
# Exception handlers (ALWAYS HTTP 200 + SuccessResponse schema)
# -----------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] Global exception: {type(exc).__name__}: {str(exc)}",
        exc_info=True,
    )
    resp = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="I am having some technical trouble. Can we talk in a moment?",
    )
    return JSONResponse(status_code=200, content=resp.model_dump())

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] HTTP exception {exc.status_code}: {exc.detail}",
        exc_info=True,
    )
    resp = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="I'm not sure how to respond to that. Could you clarify?",
    )
    return JSONResponse(status_code=200, content=resp.model_dump())

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] Validation error: {exc.errors()}",
        exc_info=True,
    )
    resp = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="Something seems wrong with your message format. Can you send it again?",
    )
    return JSONResponse(status_code=200, content=resp.model_dump())

@app.exception_handler(json.JSONDecodeError)
async def json_decode_error_handler(request: Request, exc: json.JSONDecodeError):
    request_id = get_request_id()
    logger.error(
        f"[{request_id}] JSON decode error: {str(exc)}",
        exc_info=True,
    )
    resp = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="I couldn't read that message. Please try sending it again.",
    )
    return JSONResponse(status_code=200, content=resp.model_dump())

# -----------------------------------------------------------------------------
# Utility: robust timestamp normalization (epoch seconds/ms, iso string, datetime)
# -----------------------------------------------------------------------------
def normalize_timestamp(ts: Any) -> datetime:
    now = datetime.now()
    try:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            # epoch ms vs seconds
            if ts > 10_000_000_000:  # ms
                return datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str) and ts.strip():
            # ISO with Z
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return now
    return now

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "honeypot", "endpoint": "/api/honeypot"}

@app.post("/__debug_echo")
async def debug_echo(request: Request):
    """
    Use this to inspect what a tester sends.
    """
    try:
        raw = await request.body()
        raw_str = raw.decode("utf-8", "ignore") if raw else ""
    except Exception:
        raw_str = ""
    return {
        "content_type": request.headers.get("content-type", "missing"),
        "raw_len": len(raw_str),
        "raw_preview": raw_str[:200] if raw_str else "empty",
        "headers": dict(request.headers),
    }

# Probe-friendly routes (NO response_model; always 200 JSON)
@app.get("/api/honeypot")
@app.get("/api/honeypot/")
async def honeypot_get_probe():
    resp = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="Use POST with JSON body.",
    )
    return JSONResponse(status_code=200, content=resp.model_dump())

@app.options("/api/honeypot")
@app.options("/api/honeypot/")
async def honeypot_options_probe():
    # Some testers do OPTIONS first
    return Response(status_code=200)

@app.head("/api/honeypot")
@app.head("/api/honeypot/")
@app.head("/")
async def honeypot_head_probe():
    # Some testers probe with HEAD
    return Response(status_code=200)

# -----------------------------------------------------------------------------
# Main handler implementation (single function)
# -----------------------------------------------------------------------------
async def _honeypot_handler(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: str,
) -> JSONResponse:
    """
    Hard requirement: never reject before handler runs.
    Always return HTTP 200 with full SuccessResponse schema.
    """
    request_id = get_request_id()

    # --------------------------
    # Manual body parse
    # --------------------------
    payload_dict: Dict[str, Any] = {}
    try:
        raw_body = await request.body()
        if raw_body:
            payload_dict = json.loads(raw_body)
        else:
            payload_dict = {}
    except Exception as e:
        logger.warning(f"[{request_id}] Body parse failed: {type(e).__name__}: {e}")
        payload_dict = {}

    if not isinstance(payload_dict, dict):
        logger.warning(f"[{request_id}] Payload not dict: {type(payload_dict)}")
        payload_dict = {}

    # --------------------------
    # Auth (non-blocking)
    # --------------------------
    api_key = x_api_key or request.headers.get("x-api-key")
    if not api_key or api_key != settings.HONEYPOT_API_KEY:
        resp = build_success_response(
            scam_detected=False,
            engagement_duration=0,
            total_messages=0,
            extracted_intel=None,
            agent_reply="Missing or invalid API key.",
        )
        return JSONResponse(status_code=200, content=resp.model_dump())

    # --------------------------
    # Normalize input (lenient)
    # --------------------------
    now = datetime.now()

    session_id = payload_dict.get("sessionId")
    if not isinstance(session_id, str) or not session_id.strip():
        session_id = f"session-{request_id[:8]}"

    message_data = payload_dict.get("message", {})
    if not isinstance(message_data, dict):
        message_data = {}

    incoming_text = str(message_data.get("text", "") or "")[:4000]
    message_timestamp = normalize_timestamp(message_data.get("timestamp"))

    # conversationHistory may be missing/wrong type
    conversation_history_raw = payload_dict.get("conversationHistory", [])
    if not isinstance(conversation_history_raw, list):
        conversation_history_raw = []
    conversation_history_raw = conversation_history_raw[:30]

    normalized_history: List[Message] = []
    for msg in conversation_history_raw:
        if not isinstance(msg, dict):
            continue
        try:
            text = str(msg.get("text", "") or "")[:1000]
            sender = msg.get("sender", "scammer")
            ts = normalize_timestamp(msg.get("timestamp"))
            if sender not in ["scammer", "user"]:
                sender = "scammer"
            normalized_history.append(
                Message(sender=Sender(sender), text=text, timestamp=ts)
            )
        except Exception:
            continue

    # --------------------------
    # Session load/init
    # --------------------------
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
                "suspiciousKeywords": [],
            },
            "internalHistory": [],
            "agentNotes": "",
            "last_agent_reply": "",
        }

    # Ensure keys exist
    session.setdefault("callback_in_progress", False)
    session.setdefault("next_retry_at", None)
    session.setdefault("callback_attempts", 0)

    # Append incoming scammer message
    session["internalHistory"].append(
        {
            "sender": "scammer",
            "text": incoming_text,
            "timestamp": message_timestamp.isoformat(),
        }
    )
    session["totalMessagesExchanged"] += 1
    store.save_session(session_id, session)

    # --------------------------
    # Combined history
    # --------------------------
    combined_history = store.get_combined_history(session_id, normalized_history)
    history_text = "\n".join([m.text for m in combined_history]) if combined_history else ""

    # --------------------------
    # Extraction (always run on incoming text)
    # --------------------------
    current_intel = session.get("extractedIntelligence", {})
    try:
        new_intel = extractor.extract_from_text(incoming_text)

        if combined_history:
            hist_intel = extractor.extract_from_messages(combined_history)
            for k in new_intel:
                new_intel[k] = list(set(new_intel[k] + hist_intel.get(k, [])))

        if new_intel.get("links"):
            logger.info(f"[{request_id}] EXTRACTION urls: {new_intel['links']}")
        if new_intel.get("phones"):
            logger.info(f"[{request_id}] EXTRACTION phones: {new_intel['phones']}")
        if new_intel.get("upi"):
            logger.info(f"[{request_id}] EXTRACTION upi: {new_intel['upi']}")
    except Exception as e:
        logger.error(f"[{request_id}] Extraction failed: {e}", exc_info=True)
        new_intel = {"upi": [], "bank": [], "links": [], "phones": [], "keywords": []}

    ext_key_map = {
        "upiIds": "upi",
        "bankAccounts": "bank",
        "phishingLinks": "links",
        "phoneNumbers": "phones",
        "suspiciousKeywords": "keywords",
    }

    for out_key, src_key in ext_key_map.items():
        existing = set(current_intel.get(out_key, []))
        incoming = set(new_intel.get(src_key, []))
        current_intel[out_key] = list(existing.union(incoming))

    session["extractedIntelligence"] = current_intel

    # --------------------------
    # Scam detection
    # --------------------------
    is_scam = session.get("scamDetected", False)
    if not is_scam:
        try:
            detected, confidence = await detector.check_scam(
                message_text=incoming_text, history_text=history_text
            )
            if detected:
                session["scamDetected"] = True
                is_scam = True
                logger.info(f"[{request_id}] Scam detected (conf={confidence})")
        except Exception as e:
            logger.error(f"[{request_id}] Scam detection failed: {e}", exc_info=True)

    # --------------------------
    # Agent reply (only when scamDetected true)
    # --------------------------
    agent_reply_text = ""
    if session.get("scamDetected", False):
        try:
            scammer_msgs = len([m for m in combined_history if m.sender == Sender.SCAMMER])
            agent_msgs = len([m for m in combined_history if m.sender == Sender.USER])
            logical_turns = min(scammer_msgs, agent_msgs + 1)

            agent_reply_text = await safe_agent_reply(
                current_message=incoming_text,
                merged_history=combined_history,
                intel_so_far=current_intel,
                turn_index=logical_turns,
                timeout_seconds=8.0,
            )
        except Exception:
            agent_reply_text = agent._fallback_reply()

        # Append agent reply to internal history
        session["internalHistory"].append(
            {"sender": "user", "text": agent_reply_text, "timestamp": datetime.now().isoformat()}
        )
        session["totalMessagesExchanged"] += 1
        session["last_agent_reply"] = agent_reply_text

        # STRICT requirement: agentNotes MUST start with "nextReply:"
        session["agentNotes"] = f"nextReply: {agent_reply_text}"

        store.save_session(session_id, session)

    # --------------------------
    # Callback (final result)
    # --------------------------
    can_retry = True
    if session.get("next_retry_at"):
        try:
            next_retry = datetime.fromisoformat(session["next_retry_at"])
            if now < next_retry:
                can_retry = False
        except Exception:
            pass

    if (
        session.get("scamDetected", False)
        and not session.get("callback_sent", False)
        and not session.get("callback_in_progress", False)
        and can_retry
    ):
        if check_completion(session, combined_history):
            session["callback_in_progress"] = True
            store.save_session(session_id, session)

            callback_payload = build_callback_payload(session_id, session)

            async def background_callback_wrapper():
                try:
                    success, code, msg = await send_final_result_callback(callback_payload)
                    s = store.get_session(session_id) or session
                    s["callback_in_progress"] = False
                    if success:
                        s["callback_sent"] = True
                    else:
                        s["callback_attempts"] = s.get("callback_attempts", 0) + 1
                        if s["callback_attempts"] >= 3:
                            s["next_retry_at"] = (datetime.now() + timedelta(seconds=60)).isoformat()
                    store.save_session(session_id, s)
                except Exception as e:
                    logger.error(f"[{request_id}] Callback failed: {e}", exc_info=True)
                    s = store.get_session(session_id) or session
                    s["callback_in_progress"] = False
                    store.save_session(session_id, s)

            background_tasks.add_task(background_callback_wrapper)

    # --------------------------
    # Final response (FULL schema)
    # --------------------------
    store.save_session(session_id, session)
    duration = calculate_engagement_duration(session["started_at"])

    resp = build_success_response(
        scam_detected=session.get("scamDetected", False),
        engagement_duration=duration,
        total_messages=session.get("totalMessagesExchanged", 0),
        extracted_intel=session.get("extractedIntelligence", None),
        agent_reply=agent_reply_text,
        # we already set agentNotes strictly in session, but builder will format too
        agent_notes=session.get("agentNotes", ""),
    )
    return JSONResponse(status_code=200, content=resp.model_dump())

# -----------------------------------------------------------------------------
# POST entrypoints (cover dumb testers)
# -----------------------------------------------------------------------------
@app.post("/api/honeypot")
@app.post("/api/honeypot/")
@app.post("/")
async def honeypot_entry(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: str = Security(api_key_header),
):
    try:
        return await _honeypot_handler(request, background_tasks, x_api_key)
    except Exception as e:
        request_id = get_request_id()
        logger.exception(f"[{request_id}] CRITICAL honeypot_entry error: {e}")
        resp = build_success_response(
            scam_detected=False,
            engagement_duration=0,
            total_messages=0,
            extracted_intel=None,
            agent_reply=agent._fallback_reply(),
        )
        return JSONResponse(status_code=200, content=resp.model_dump())
