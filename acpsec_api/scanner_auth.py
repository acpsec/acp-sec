"""Scanner auth gate — reusable FastAPI dependency.

Gates the SSRF-sensitive scanner endpoints:

    - allow when SCANNER_TOKEN is unset or blank (open dev mode)
    - allow explicit X-Scanner-Token header matching SCANNER_TOKEN
      (constant-time comparison)
    - otherwise → 401 {"ok": False, "error": <denial message>}

Reused by /api/scanner/lookup (2.5a), /scan + /bulk (2.5b), and
/api/onchain/check (2.6).

SAME-ORIGIN SHORTCUT REMOVED: the Flask original also allowed requests whose
Origin host equalled the Host header. Both headers are client-controlled, so
any non-browser caller could send ``Origin: https://<api host>`` and skip the
token entirely. Since the split-origin deployment (Task 2.8: frontend on
Vercel, API on Railway) no legitimate caller is same-origin — the frontend
already sends X-Scanner-Token — so the shortcut was only ever a bypass.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Request
from fastapi.responses import JSONResponse

SCANNER_DENIED_ERROR = "scanner endpoint requires X-Scanner-Token header"
SCANNER_DENIED_BODY = {"ok": False, "error": SCANNER_DENIED_ERROR}


class ScannerAccessDenied(Exception):
    """Raised by ``require_scanner_access`` when the gate rejects a request.

    Converted to a 401 JSON response by ``scanner_access_denied_handler``,
    registered on the app in main.py, so the body matches Flask exactly
    (a flat {"ok": False, "error": ...}, not FastAPI's {"detail": ...}).
    """


def scanner_token() -> str:
    """The configured SCANNER_TOKEN, whitespace-stripped ("" = unset/blank).

    Single source of truth for "is the gate enforcing?" — the gate below and
    /api/health's ``scanner_protected`` both read it, so the health flag can
    never report protection the gate does not enforce (e.g. a blank value).
    """
    return os.environ.get("SCANNER_TOKEN", "").strip()


def require_scanner_access(request: Request) -> None:
    """FastAPI dependency: allow (return None) or raise ScannerAccessDenied.

    Truth table (Origin / Host are ignored — see module docstring):
      * SCANNER_TOKEN unset/blank → allow (open)
      * valid X-Scanner-Token     → allow
      * else                      → deny (401)
    """
    required = scanner_token()
    if not required:
        # No token configured → endpoints behave exactly as in dev (open).
        return

    sent = request.headers.get("x-scanner-token", "").strip()
    # compare_digest is constant-time, so response timing reveals nothing about
    # how much of a guessed token matched. It needs bytes for non-ASCII input:
    # Starlette decodes header bytes as latin-1 (lossless), so encoding back to
    # latin-1 recovers exactly what the client sent, compared against the
    # token's UTF-8 bytes ("surrogatepass" encodes any env str without raising).
    if not sent or not hmac.compare_digest(
        sent.encode("latin-1"),
        required.encode("utf-8", "surrogatepass"),
    ):
        raise ScannerAccessDenied()
    return


def scanner_access_denied_handler(
    request: Request, exc: ScannerAccessDenied
) -> JSONResponse:
    """Render ScannerAccessDenied as Flask's flat 401 body."""
    return JSONResponse(SCANNER_DENIED_BODY, status_code=401)
