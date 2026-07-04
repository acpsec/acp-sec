"""Chat router.

Contract-identical port from dashboard/serve.py:
    - POST /api/chat/sentryagent (2.7) — Claude API proxy for the SentryAgent UI

No request-side auth gate: the API key lives server-side (ANTHROPIC_API_KEY) and
is never sent by the client. The blocking Claude call is made through an
injectable client (get_anthropic_client) so tests mock it — the suite never
makes a live Claude API call.

The system prompt is copied VERBATIM from the Flask handler (not imported from
dashboard/) so this router stands alone.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acpsec_api.deps import get_anthropic_client
from acpsec_api.utils import is_json_request

router = APIRouter()

# History + per-message caps, verbatim from Flask (token-abuse guardrails).
HISTORY_LIMIT = 20
CONTENT_CHAR_CAP = 4000
CHAT_MODEL = "claude-sonnet-4-6"
CHAT_MAX_TOKENS = 1024

# Copied verbatim from dashboard/serve.py's chat_sentryagent handler. Kept here
# so the router has no runtime dependency on the Flask app.
SENTRYAGENT_SYSTEM = (
    "You are SentryAgent, an ERC-8183 compliant smart contract agent deployed on "
    "Base Sepolia testnet (chain 84532). Help users interact with the contract at "
    "0x7770ED57E3993d4555951a557cd158a6Fb87A470 through natural language.\n\n"
    "Available actions — emit a JSON code block when the user wants to act:\n"
    "- createJob(provider, evaluator, expiryHours) — Create a job. provider and "
    "evaluator are Ethereum addresses; expiryHours defaults to 24.\n"
    "- fundJob(jobId, amountETH) — Fund a job; amountETH in ETH (e.g. 0.001).\n"
    "- submitDeliverable(jobId, hash) — Submit bytes32 deliverable hash.\n"
    "- completeJob(jobId) — Complete job, release funds to provider (evaluator only).\n"
    "- rejectJob(jobId, reason) — Reject job, refund client (evaluator only).\n"
    "- recoverExpiredJob(jobId) — Recover funds from expired job (client only).\n"
    "- getJob(jobId) — Read-only: fetch job details.\n"
    "- getAgentInfo() — Read-only: fetch agent name, version, purpose.\n\n"
    "When the user wants an action respond with:\n"
    "1. Brief friendly explanation\n"
    '2. Action block on its own: ```json\n{"action": "actionName", "params": {...}}\n```\n\n'
    "Read actions (getJob, getAgentInfo) execute immediately with no wallet needed. "
    "Write actions show a confirm dialog before execution. "
    "If required params are missing ask for them before emitting the JSON block. "
    "Keep responses concise. This is testnet — no real funds at risk."
)


@router.post("/api/chat/sentryagent")
async def chat_sentryagent(
    request: Request,
    client: Optional[Any] = Depends(get_anthropic_client),
) -> Any:
    """SentryAgent AI chat proxy — forwards messages to Claude, key stays server-side.

    Request body: { "messages": [{"role": "user"|"assistant", "content": "..."}] }
    Returns:      { "ok": true, "reply": "..." }
    """
    if not is_json_request(request):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=415
        )

    # Env is checked FIRST (before the client) so the two 503s keep Flask's
    # distinct messages: missing key vs. missing anthropic package.
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return JSONResponse(
            {"ok": False, "error": "AI chat not configured (ANTHROPIC_API_KEY not set)"},
            status_code=503,
        )
    if client is None:
        return JSONResponse(
            {"ok": False, "error": "anthropic package not installed — pip install anthropic"},
            status_code=503,
        )

    payload  = await request.json()
    raw_msgs = payload.get("messages") or []

    # Sanitise and cap history to prevent token abuse (verbatim from Flask).
    messages = [
        {"role": m["role"], "content": str(m["content"])[:CONTENT_CHAR_CAP]}
        for m in raw_msgs[-HISTORY_LIMIT:]
        if m.get("role") in ("user", "assistant") and m.get("content")
    ]
    if not messages:
        return JSONResponse(
            {"ok": False, "error": "'messages' must be a non-empty list"}, status_code=422
        )

    # anthropic is importable here (client is not None) — import for the error type.
    import anthropic

    try:
        resp = client.messages.create(
            model=CHAT_MODEL,
            max_tokens=CHAT_MAX_TOKENS,
            system=SENTRYAGENT_SYSTEM,
            messages=messages,
        )
        reply = resp.content[0].text
        return {"ok": True, "reply": reply}
    except anthropic.APIError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)
    except Exception as exc:  # noqa: BLE001 — mirror Flask's catch-all
        return JSONResponse(
            {"ok": False, "error": "Chat error: " + str(exc)}, status_code=500
        )
