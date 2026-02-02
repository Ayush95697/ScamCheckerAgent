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
    is_intel_found,
)
from app.response_builder import build_success_response, safe_agent_reply
from app.middleware import RequestIDMiddleware, get_request_id

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot-api")

# Non-blocking API key header (used for swagger + Security injection)
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

app = FastAPI(
    title="Agentic Honeypot API",
    version="0.1.0",
    description="Agentic Honey-Pot for Scam Detection & Intelligence Extraction",
)

# -----------------------------------------------------------------------------
# CORS (CRITICAL for GUVI browser-based tester)
# -----------------------------------------------------------------------------
# The GUVI tester page runs on hackathon.guvi.in and calls your API via fetch().
# Without CORS headers, the browser blocks the request BEFORE it reaches your server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # hackathon-safe; tighten later if needed
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],          # required for x-api-key
)

# Request ID middleware (your existing middleware)
app.add_middleware(RequestIDMiddleware)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _normalize_timestamp(ts: Any) -> datetime:
    now = datetime.now(timezone.utc)
    try:
        if isinstance(ts, datetime):
            # ensure tz-aware
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

        if isinstance(ts, (int, float)):
            # epoch ms vs seconds
            if ts > 10_000_000_000:  # ms
                return datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(ts, tz=timezone.utc)

        if isinstance(ts, str) and ts.strip():
            # ISO string; accept 'Z'
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return now
    return now


def _empty_intel() -> Dict[str, List[str]]:
    return {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": [],
    }


def _ensure_session(session_id: str, now: datetime) -> Dict[str, Any]:
    session = store.get_session(session_id)
    if session:
        # ensure keys exist
        session.setdefault("started_at", now.isoformat())
        session.setdefault("totalMessagesExchanged", 0)
        session.setdefault("scamDetected", False)
        session.setdefault("callback_sent", False)
        session.setdefault("callback_attempts", 0)
        session.setdefault("callback_in_progress", False)
        session.setdefault("next_retry_at", None)
        session.setdefault("extractedIntelligence", _empty_intel())
        session.setdefault("internalHistory", [])
        session.setdefault("agentNotes", "")
        session.setdefault("last_agent_reply", "")
        return session

    return {
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


# -----------------------------------------------------------------------------
# Exception handlers (ALWAYS return HTTP 200 + full SuccessResponse schema)
# -----------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    rid = get_request_id()
    logger.error(f"[{rid}] Global exception: {type(exc).__name__}: {exc}", exc_info=True)
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
    rid = get_request_id()
    logger.error(f"[{rid}] HTTP exception {exc.status_code}: {exc.detail}", exc_info=True)
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
    rid = get_request_id()
    logger.error(f"[{rid}] Validation error: {exc.errors()}", exc_info=True)
    resp = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="Something seems wrong with the message format. Please resend.",
    )
    return JSONResponse(status_code=200, content=resp.model_dump())


@app.exception_handler(json.JSONDecodeError)
async def json_decode_error_handler(request: Request, exc: json.JSONDecodeError):
    rid = get_request_id()
    logger.error(f"[{rid}] JSON decode error: {exc}", exc_info=True)
    resp = build_success_response(
        scam_detected=False,
        engagement_duration=0,
        total_messages=0,
        extracted_intel=None,
        agent_reply="I couldn't read that message. Please try sending it again.",
    )
    return JSONResponse(status_code=200, content=resp.model_dump())


# -----------------------------------------------------------------------------
# Basic routes
# -----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "honeypot", "endpoint": "/api/honeypot"}


@app.post("/__debug_echo")
async def debug_echo(request: Request):
    """
    Debug endpoint to confirm what GUVI is sending.
    You should see OPTIONS + POST in Network tab after CORS is enabled.
    """
    try:
        raw = await request.body()
        raw_str = raw.decode("utf-8", "ignore") if raw else ""
    except Exception:
        raw_str = ""
    return {
        "content_type": request.headers.get("content-type", "missing"),
        "origin": request.headers.get("origin", "missing"),
        "raw_len": len(raw_str),
        "raw_preview": raw_str[:200] if raw_str else "empty",
        "headers_subset": {
            "origin": request.headers.get("origin"),
            "content-type": request.headers.get("content-type"),
            "x-api-key": "present" if request.headers.get("x-api-key") else "missing",
        },
    }


# Probe-friendly endpoints (some testers probe with GET/OPTIONS/HEAD)
@app.get("/api/honeypot")
@app.get("/api/honeypot/")
async def honeypot_probe_get():
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
async def honeypot_probe_options():
    return Response(status_code=200)


@app.head("/api/honeypot")
@app.head("/api/honeypot/")
@app.head("/")
async def honeypot_probe_head():
    return Response(status_code=200)


# -----------------------------------------------------------------------------
# Core handler (manual JSON parse + normalization + always SuccessResponse)
# -----------------------------------------------------------------------------
async def _handle_honeypot(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str],
) -> JSONResponse:
    rid = get_request_id()

    # -------------------------
    # Manual parse (never throw)
    # -------------------------
    payload: Dict[str, Any] = {}
    try:
        raw = await request.body()
        if raw:
            payload = json.loads(raw)
        else:
            payload = {}
    except Exception as e:
        logger.warning(f"[{rid}] Body parse failed: {type(e).__name__}: {e}")
        payload = {}

    if not isinstance(payload, dict):
        logger.warning(f"[{rid}] Payload not dict: {type(payload)}")
        payload = {}

    # -------------------------
    # Auth (non-blocking)
    # -------------------------
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

    # -------------------------
    # Normalize fields (GUVI can send epoch ms)
    # -------------------------
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
    conv_raw = conv_raw[:30]

    normalized_history: List[Message] = []
    for m in conv_raw:
        if not isinstance(m, dict):
            continue
        try:
            t = str(m.get("text", "") or "")[:1000]
            s = m.get("sender", "scammer")
            ts = _normalize_timestamp(m.get("timestamp"))
            if s not in ["scammer", "user"]:
                s = "scammer"
            normalized_history.append(Message(sender=Sender(s), text=t, timestamp=ts))
        except Exception:
            continue

    # -------------------------
    # Session state
    # -------------------------
    session = _ensure_session(session_id, now)

    session["internalHistory"].append(
        {"sender": "scammer", "text": incoming_text, "timestamp": incoming_ts.isoformat()}
    )
    session["totalMessagesExchanged"] += 1
    store.save_session(session_id, session)

    # combined history for detection + agent
    combined_history = store.get_combined_history(session_id, normalized_history)
    history_text = "\n".join([m.text for m in combined_history]) if combined_history else ""

    # -------------------------
    # Extraction (always on incoming text + history)
    # -------------------------
    current_intel = session.get("extractedIntelligence") or _empty_intel()

    try:
        new_intel = extractor.extract_from_text(incoming_text)
        if combined_history:
            hist_intel = extractor.extract_from_messages(combined_history)
            for k in new_intel:
                new_intel[k] = list(set(new_intel[k] + hist_intel.get(k, [])))
    except Exception as e:
        logger.error(f"[{rid}] Extraction failed: {e}", exc_info=True)
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

    # -------------------------
    # Scam detection
    # -------------------------
    if not session.get("scamDetected", False):
        try:
            is_scam, confidence = await detector.check_scam(
                message_text=incoming_text,
                history_text=history_text,
            )
            if is_scam:
                session["scamDetected"] = True
                logger.info(f"[{rid}] Scam detected (conf={confidence})")
        except Exception as e:
            logger.error(f"[{rid}] Scam detection failed: {e}", exc_info=True)

    # -------------------------
    # Agent reply
    # -------------------------
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

        session["internalHistory"].append(
            {"sender": "user", "text": agent_reply_text, "timestamp": datetime.now(timezone.utc).isoformat()}
        )
        session["totalMessagesExchanged"] += 1
        session["last_agent_reply"] = agent_reply_text

        # STRICT formatting requirement
        session["agentNotes"] = f"nextReply: {agent_reply_text}"

    # -------------------------
    # Callback scheduling (final result)
    # -------------------------
    can_retry = True
    if session.get("next_retry_at"):
        try:
            next_retry = datetime.fromisoformat(session["next_retry_at"])
            if next_retry.tzinfo is None:
                next_retry = next_retry.replace(tzinfo=timezone.utc)
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
                            s["next_retry_at"] = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
                    store.save_session(session_id, s)
                except Exception as e:
                    logger.error(f"[{rid}] Callback failed: {e}", exc_info=True)
                    s = store.get_session(session_id) or session
                    s["callback_in_progress"] = False
                    store.save_session(session_id, s)

            background_tasks.add_task(background_callback_wrapper)

    # save session
    store.save_session(session_id, session)

    # -------------------------
    # Build final response (full SuccessResponse schema)
    # -------------------------
    duration = calculate_engagement_duration(session["started_at"])
    resp = build_success_response(
        scam_detected=bool(session.get("scamDetected", False)),
        engagement_duration=int(duration),
        total_messages=int(session.get("totalMessagesExchanged", 0)),
        extracted_intel=session.get("extractedIntelligence", None),
        agent_notes=session.get("agentNotes", ""),  # must start with nextReply:
        agent_reply=agent_reply_text,
    )
    return JSONResponse(status_code=200, content=resp.model_dump())


# -----------------------------------------------------------------------------
# POST entrypoints (covers GUVI tester variations)
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
        rid = get_request_id()
        logger.exception(f"[{rid}] CRITICAL honeypot_entry error: {e}")
        resp = build_success_response(
            scam_detected=False,
            engagement_duration=0,
            total_messages=0,
            extracted_intel=None,
            agent_reply=agent._fallback_reply(),
        )
        return JSONResponse(status_code=200, content=resp.model_dump())
