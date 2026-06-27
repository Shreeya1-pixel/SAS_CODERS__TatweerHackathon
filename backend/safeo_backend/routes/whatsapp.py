"""
WhatsApp Business Cloud API Webhook routes.
"""
from __future__ import annotations

import hmac
import hashlib
import json
import logging
import os
from typing import Any, Dict

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, Response, status
from fastapi.responses import PlainTextResponse

from .universal import _run_scan, ScanContext

logger = logging.getLogger("safeo.whatsapp")

router = APIRouter(prefix="/webhooks", tags=["WhatsApp Webhook"])

_live_stream: list[Dict[str, Any]] = []

async def send_whatsapp_message(to_phone: str, body: str) -> Dict[str, Any]:
    """
    Sends a WhatsApp message using Meta Cloud API.
    If credentials are unset, runs in mock/demo mode.
    """
    phone_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
    access_token = os.getenv("WHATSAPP_ACCESS_TOKEN")

    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": body}
    }

    if not phone_id or not access_token:
        # Demo mode: Log what would have been sent
        msg = f"[DEMO MODE] Would send WhatsApp message to {to_phone}: {body}"
        logger.info(msg)

        # Log to the demo event log (shared request log)
        from .waf import append_request_log
        import uuid
        from datetime import datetime, timezone

        append_request_log({
            "request_id": f"mock-wa-{uuid.uuid4().hex[:6]}",
            "module": "whatsapp",
            "source_system": "whatsapp_outbound",
            "risk_score": 0.0,
            "decision": "allow",
            "user_id": to_phone,
            "type": "whatsapp_outbound",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": msg,
            "sender_phone": to_phone,
            "channel": "whatsapp"
        })

        return {
            "status": "mock_success",
            "message_id": f"mock-msg-{uuid.uuid4()}",
            "payload_sent": payload
        }

    # Live mode: Make the HTTP call to Graph API
    url = f"https://graph.facebook.com/v19.0/{phone_id}/messages"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    import httpx
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, headers=headers, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            logger.info("Successfully sent WhatsApp message to %s, message_id=%s", to_phone, data.get("messages", [{}])[0].get("id"))
            return data
    except Exception as exc:
        logger.error("Failed to send WhatsApp message to %s: %s", to_phone, exc, exc_info=True)
        return {"status": "error", "detail": str(exc)}


async def run_whatsapp_scan(text: str, phone: str, name: str, business_num: str, wamid: str = "") -> Dict[str, Any]:
    """
    Asynchronously run the SafeO scanner over the incoming WhatsApp text message.
    """
    logger.info("Starting async scan for WhatsApp message from %s", phone)
    ctx = ScanContext(
        user_id=phone or "anonymous",
        source_system="whatsapp_business",
        sender_phone=phone,
        sender_name=name,
        business_number=business_num,
        channel="whatsapp"
    )
    try:
        result = await _run_scan(text, ctx)
        scan_id = result.get("scan_id")
        decision = result.get("decision")
        score = result.get("risk_score")
        logger.info(
            "WhatsApp scan complete. ID: %s, Decision: %s, Score: %s",
            scan_id,
            decision,
            score
        )

        outbound_msg = None
        if decision == "BLOCK":
            # Send customer-facing message (no jargon)
            from .whatsapp_templates import WHATSAPP_TEMPLATES
            body = WHATSAPP_TEMPLATES.get("BLOCK", "Your message was blocked.")
            msg_res = await send_whatsapp_message(phone, body)
            
            if msg_res.get("status") == "mock_success":
                outbound_msg = body

            # Separately log an internal alert.
            # _run_scan already schedules run_investigation for BLOCK decisions.
            logger.warning(
                "INTERNAL ALERT: WhatsApp message from %s blocked. Scan ID: %s, Risk Score: %s. Investigation triggered.",
                phone,
                scan_id,
                score
            )
        elif decision == "WARN":
            # Let it pass through but tag it as flagged in the request log.
            from .waf import get_request_log
            logs = get_request_log()
            flagged = False
            for entry in reversed(logs):
                if entry.get("request_id") == scan_id:
                    entry["flagged"] = True
                    entry["status"] = "flagged"
                    flagged = True
                    logger.info("Tagged WhatsApp scan %s as flagged in request log", scan_id)
                    break
            if not flagged:
                logger.warning("Could not find WhatsApp scan %s in request log to flag", scan_id)
        elif decision == "ALLOW":
            # No customer-facing action needed.
            pass

        if wamid:
            for item in _live_stream:
                if item["id"] == wamid:
                    item["decision"] = decision
                    item["risk_score"] = score
                    item["simulated_reply"] = outbound_msg
                    item["status"] = "done"
                    break

        return {
            "decision": decision,
            "risk_score": score,
            "simulated_reply": outbound_msg
        }

    except Exception as exc:
        logger.error("Error executing background WhatsApp scan: %s", exc, exc_info=True)
        return {
            "decision": "ERROR",
            "risk_score": 0.0,
            "simulated_reply": str(exc)
        }



@router.get("/whatsapp")
async def verify_whatsapp_webhook(
    mode: str = Query(None, alias="hub.mode"),
    verify_token: str = Query(None, alias="hub.verify_token"),
    challenge: str = Query(None, alias="hub.challenge")
):
    """
    Webhook verification endpoint. Meta calls this once upon registering the URL.
    """
    expected_token = os.getenv("WHATSAPP_VERIFY_TOKEN", "safeo_hackathon_2026")
    
    if mode == "subscribe" and verify_token == expected_token:
        logger.info("WhatsApp webhook verified successfully.")
        return Response(content=challenge, media_type="text/plain")
    
    logger.warning("WhatsApp webhook verification failed. Token mismatch.")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Verification token mismatch"
    )


@router.post("/whatsapp")
async def receive_whatsapp_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    simulated: str = Query(None)
):
    """
    WhatsApp message webhook event receiver. Rejects invalid signatures with 401.
    Processes valid messages in the background and returns 200 OK immediately.
    """
    signature_header = request.headers.get("X-Hub-Signature-256", "")
    app_secret = os.getenv("WHATSAPP_APP_SECRET", "")
    
    raw_body = await request.body()

    if not app_secret or simulated == "true":
        logger.warning("WHATSAPP_APP_SECRET is unset or simulated mode; skipping signature verification.")
    else:
        if not signature_header.startswith("sha256="):
            logger.warning("Missing or invalid X-Hub-Signature-256 signature format.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid signature header"
            )
        
        expected_signature = signature_header[7:].strip()
        computed_signature = hmac.new(
            app_secret.encode("utf-8"),
            raw_body,
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(computed_signature, expected_signature):
            logger.error("WhatsApp webhook signature mismatch.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Signature verification failed"
            )

    try:
        data = json.loads(raw_body.decode("utf-8"))
    except json.JSONDecodeError:
        logger.error("Failed to decode WhatsApp webhook request body as JSON.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )

    # Standard Meta Cloud API payload navigation
    entries = data.get("entry", [])
    for entry in entries:
        changes = entry.get("changes", [])
        for change in changes:
            value = change.get("value", {})
            messages = value.get("messages", [])
            contacts = value.get("contacts", [])
            metadata = value.get("metadata", {})

            business_num = metadata.get("display_phone_number", "unknown")
            
            sender_name = "anonymous"
            if contacts:
                sender_name = contacts[0].get("profile", {}).get("name", "anonymous")

            for msg in messages:
                if msg.get("type") == "text":
                    text_body = msg.get("text", {}).get("body", "")
                    sender_phone = msg.get("from", "")
                    
                    if text_body:
                        msg_id = msg.get("id", f"msg_{os.urandom(4).hex()}")
                        
                        if simulated == "true":
                            # For demo simulator, run synchronously and return the result
                            result = await run_whatsapp_scan(
                                text_body,
                                sender_phone,
                                sender_name,
                                business_num
                            )
                            
                            from datetime import datetime
                            _live_stream.append({
                                "id": msg_id,
                                "sender": "user",
                                "text": text_body,
                                "timestamp": datetime.now().strftime("%I:%M %p"),
                                "status": "done",
                                "decision": result.get("decision", "ALLOW"),
                                "risk_score": result.get("risk_score", 0.0),
                                "simulated_reply": result.get("simulated_reply")
                            })
                            if len(_live_stream) > 50:
                                _live_stream.pop(0)

                            return {
                                "status": "received",
                                "decision": result.get("decision", "ALLOW"),
                                "risk_score": result.get("risk_score", 0.0),
                                "simulated_reply": result.get("simulated_reply")
                            }
                        else:
                            from datetime import datetime
                            _live_stream.append({
                                "id": msg_id,
                                "sender": "user",
                                "text": text_body,
                                "timestamp": datetime.now().strftime("%I:%M %p"),
                                "status": "pending",
                                "decision": None,
                                "risk_score": 0.0,
                                "simulated_reply": None
                            })
                            if len(_live_stream) > 50:
                                _live_stream.pop(0)

                            # Schedule background scan to respond 200 immediately
                            background_tasks.add_task(
                                run_whatsapp_scan,
                                text_body,
                                sender_phone,
                                sender_name,
                                business_num,
                                msg_id
                            )

    return {"status": "accepted"}

@router.get("/whatsapp/live")
async def get_whatsapp_live_stream():
    return _live_stream


@router.get("/whatsapp/last-scan/{phone}")
async def get_last_whatsapp_scan(phone: str):
    """
    Returns the latest scan result and outbound message (if any) for a phone number.
    """
    from .waf import get_request_log
    logs = get_request_log()

    scan_entry = None
    outbound_entry = None

    # Iterate in reverse to find the latest entries
    for entry in reversed(logs):
        source = entry.get("source_system") or entry.get("module") or ""
        user_id = entry.get("user_id")

        if source == "whatsapp_business" and user_id == phone and not scan_entry:
            scan_entry = entry
        elif source == "whatsapp_outbound" and user_id == phone and not outbound_entry:
            outbound_entry = entry

        if scan_entry and (scan_entry.get("decision") != "block" or outbound_entry):
            break

    if not scan_entry:
        return {"found": False}

    return {
        "found": True,
        "scan_id": scan_entry.get("request_id"),
        "decision": (scan_entry.get("decision") or "").upper(),
        "risk_score": scan_entry.get("risk_score"),
        "timestamp": scan_entry.get("timestamp"),
        "outbound_message": outbound_entry.get("details") if outbound_entry else None
    }


async def _run_demo_sequence():
    import uuid
    import asyncio
    from datetime import datetime, timezone
    from .waf import append_request_log
    
    scan_id_1 = str(uuid.uuid4())[:12]
    scan_id_2 = str(uuid.uuid4())[:12]
    
    # Message 1
    msg1_text = "Hey, I have an issue with my order. Can you check my delivery status please?"
    _live_stream.append({
        "id": scan_id_1,
        "sender": "user",
        "text": msg1_text,
        "timestamp": datetime.now().strftime("%I:%M %p"),
        "status": "done",
        "decision": "ALLOW",
        "risk_score": 0.12,
        "simulated_reply": None
    })
    
    append_request_log({
        "request_id": scan_id_1,
        "module": "whatsapp_business",
        "source_system": "whatsapp_business",
        "risk_score": 0.12,
        "decision": "allow",
        "user_id": "971500000000",
        "patterns": [],
        "type": "v1_scan",
        "tier_used": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": "whatsapp"
    })
    
    await asyncio.sleep(5)
    
    # Message 2
    msg2_text = "Also, the tracking page says my order is frozen. Can you check if this link is correct? secure-login-whatsapp-support.com/verify-order"
    _live_stream.append({
        "id": scan_id_2,
        "sender": "user",
        "text": msg2_text,
        "timestamp": datetime.now().strftime("%I:%M %p"),
        "status": "done",
        "decision": "BLOCK",
        "risk_score": 0.96,
        "simulated_reply": "Your message was blocked."
    })
    
    append_request_log({
        "request_id": scan_id_2,
        "module": "whatsapp_business",
        "source_system": "whatsapp_business",
        "risk_score": 0.96,
        "decision": "block",
        "user_id": "971500000000",
        "patterns": ["phishing_link"],
        "type": "v1_scan",
        "tier_used": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": "whatsapp"
    })

@router.post("/whatsapp/demo-sequence")
async def trigger_whatsapp_demo_sequence(background_tasks: BackgroundTasks):
    _live_stream.clear()
    background_tasks.add_task(_run_demo_sequence)
    return {"status": "started"}

