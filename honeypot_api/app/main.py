import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict

from fastapi import FastAPI, Depends, BackgroundTasks, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.config import settings
from app.models import (
    RequestPayload, SuccessResponse, ErrorResponse, 
    EngagementMetrics, ExtractedIntelligence, Message, Sender,
    ERROR_MESSAGE
)
from app.auth import verify_api_key
from app.store import store
from app.scam_detection import detector
from app.extraction import extractor
from app.agent import agent
from app.callback import send_final_result_callback
from app.utils import check_completion, calculate_engagement_duration, build_callback_payload, is_intel_found

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot-api")

app = FastAPI(title="Agentic Honeypot API", version="0.1.0")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": ERROR_MESSAGE}
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"status": "error", "message": ERROR_MESSAGE}
    )

@app.post("/api/honeypot", response_model=SuccessResponse, dependencies=[Depends(verify_api_key)])
async def honeypot_endpoint(payload: RequestPayload, background_tasks: BackgroundTasks):
    session_id = payload.sessionId
    now = datetime.now()
    incoming_text = payload.message.text
    
    # 1. Retrieve or Initialize Session
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
    if "callback_in_progress" not in session: session["callback_in_progress"] = False
    if "next_retry_at" not in session: session["next_retry_at"] = None

    # 2. Add incoming message to session state
    in_msg = {"sender": "scammer", "text": incoming_text, "timestamp": payload.message.timestamp.isoformat()}
    session["internalHistory"].append(in_msg)
    session["totalMessagesExchanged"] += 1
    
    # Save session immediately so get_combined_history reads the latest
    store.save_session(session_id, session)
    
    # 3. Retrieve Combined History
    combined_history = store.get_combined_history(session_id, payload.conversationHistory)
    history_text = "\n".join([m.text for m in combined_history])

    # 4. Scam Detection
    if not session["scamDetected"]:
        is_scam, confidence = await detector.check_scam(message_text=incoming_text, history_text=history_text)
        if is_scam:
            session["scamDetected"] = True

    # 5. Extraction
    new_intel = extractor.extract_from_messages(combined_history)
    
    # Merge results into session.extractedIntelligence (dedupe)
    current_intel = session["extractedIntelligence"]
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
            logger.info(f"EXTRACTION DEBUG: Merged {key}: {incoming} into {union_res}")
    
    session["extractedIntelligence"] = current_intel

    # 5. Agent Reply
    # Compute logical_turns from message history
    scammer_msgs = len([m for m in combined_history if m.sender == Sender.SCAMMER])
    agent_msgs = len([m for m in combined_history if m.sender == Sender.USER])
    logical_turns = min(scammer_msgs, agent_msgs + 1)
    
    agent_reply_text = ""
    if session["scamDetected"]:
        # Generate reply
        agent_reply_text = await agent.generate_reply(
            current_message=incoming_text,
            merged_history=combined_history,
            intel_so_far=current_intel,
            turn_index=logical_turns
        )
        
        # Append agent reply to internalHistory
        session["internalHistory"].append({"sender": "user", "text": agent_reply_text, "timestamp": datetime.now().isoformat()})
        session["totalMessagesExchanged"] += 1
        session["last_agent_reply"] = agent_reply_text
        
        # Save session again
        store.save_session(session_id, session)
        
        # Update combined_history for completion check
        combined_history = store.get_combined_history(session_id, payload.conversationHistory)
        
        # Ensure agentNotes ALWAYS includes reply when scamDetected is true
        base_notes = "Scam detected." if session["scamDetected"] else ""
        if is_intel_found(current_intel, high_value_only=True):
             base_notes += " High-value intelligence extracted."
        session["agentNotes"] = f"{base_notes} | nextReply: {agent_reply_text}".strip()

    # 6. Check Completion & Callback
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

            background_tasks.add_task(background_callback_wrapper)

    # 7. Save Session
    store.save_session(session_id, session)

    # 8. Build Response
    duration = calculate_engagement_duration(session["started_at"])

    return SuccessResponse(
        scamDetected=session["scamDetected"],
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=duration,
            totalMessagesExchanged=session["totalMessagesExchanged"]
        ),
        extractedIntelligence=ExtractedIntelligence(**session["extractedIntelligence"]),
        agentNotes=session["agentNotes"]
    )
