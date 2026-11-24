"""Request-body size cap (pure ASGI middleware).

Every endpoint takes a small JSON body (the largest real payload — a full scan
report posted to /api/score — is tens of KB), but nothing upstream bounds what
a client may send, and handlers read the whole body into memory. Requests whose
body exceeds ``MAX_BODY_BYTES`` get a flat 413 before any handler runs:

* a declared ``Content-Length`` over the cap is refused without reading;
* otherwise (e.g. chunked uploads) the body is read up to the cap + 1 byte,
  then replayed to the app — so hand-parsed and Pydantic-bodied endpoints
  see the identical refusal.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from starlette.responses import JSONResponse

MAX_BODY_BYTES = 1024 * 1024  # 1 MiB — ~30x the largest seeded scan report
BODY_TOO_LARGE_ERROR = "request body too large"

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class BodySizeLimit:
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True  # malformed length — refuse rather than guess
            if too_big:
                await self._refuse(scope, receive, send)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            if len(body) > self.max_bytes:
                await self._refuse(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _refuse(scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse({"ok": False, "error": BODY_TOO_LARGE_ERROR}, status_code=413)
        await response(scope, receive, send)
