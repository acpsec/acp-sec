"""Scanner auth gate — reusable FastAPI dependency.

Contract-identical port of ``_require_scanner_token`` / ``_is_same_origin_request``
in dashboard/serve.py. Gates the SSRF-sensitive scanner endpoints:

    - allow when SCANNER_TOKEN is unset (open dev mode)
    - allow same-origin browser requests (Origin host == Host header)
    - allow explicit X-Scanner-Token header matching SCANNER_TOKEN
    - otherwise → 401 {"ok": False, "error": <denial message>}

Reused by /api/scanner/lookup (2.5a), /scan + /bulk (2.5b), and
/api/onchain/check (2.6).

SPLIT-ORIGIN NOTE: the same-origin path is preserved from Flask EXACTLY for
parity. In Task 2.8 the frontend (Vercel) and backend (Railway) become
different origins, so the same-origin path will no longer apply — cross-origin
callers will need X-Scanner-Token. That adaptation belongs to 2.8. Do NOT
change the logic here.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse

# Exact denial body from Flask (dashboard/serve.py).
SCANNER_DENIED_ERROR = (
    "scanner endpoint requires same-origin browser request "
    "OR X-Scanner-Token header"
)
SCANNER_DENIED_BODY = {"ok": False, "error": SCANNER_DENIED_ERROR}


class ScannerAccessDenied(Exception):
    """Raised by ``require_scanner_access`` when the gate rejects a request.

    Converted to a 401 JSON response by ``scanner_access_denied_handler``,
    registered on the app in main.py, so the body matches Flask exactly
    (a flat {"ok": False, "error": ...}, not FastAPI's {"detail": ...}).
    """


def is_same_origin_request(request: Request) -> bool:
    """True iff the request's Origin host matches its Host header.

    Mirrors Flask's ``_is_same_origin_request``: compares HOSTS (not full
    URLs) so upstream TLS termination (Railway) doesn't cause a scheme
    mismatch. Uses only the Origin header — never Referer.
    """
    origin = request.headers.get("origin", "")
    if not origin or origin == "null":
        return False
    try:
        origin_host = urlparse(origin).netloc.lower()
    except Exception:
        return False
    host = request.headers.get("host", "").lower()
    return bool(origin_host) and origin_host == host


def require_scanner_access(request: Request) -> None:
    """FastAPI dependency: allow (return None) or raise ScannerAccessDenied.

    Same truth table as Flask's ``_require_scanner_token``:
      * SCANNER_TOKEN unset  → allow (open)
      * same-origin request  → allow
      * valid X-Scanner-Token→ allow
      * else                 → deny (401)
    """
    required = os.environ.get("SCANNER_TOKEN", "").strip()
    if not required:
        # No token configured → endpoints behave exactly as in dev (open).
        return

    if is_same_origin_request(request):
        return

    sent = request.headers.get("x-scanner-token", "").strip()
    if not sent or sent != required:
        raise ScannerAccessDenied()
    return


def scanner_access_denied_handler(
    request: Request, exc: ScannerAccessDenied
) -> JSONResponse:
    """Render ScannerAccessDenied as Flask's flat 401 body."""
    return JSONResponse(SCANNER_DENIED_BODY, status_code=401)
