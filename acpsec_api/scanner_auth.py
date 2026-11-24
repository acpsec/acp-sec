"""Scanner auth gate — reusable FastAPI dependency.

Gates the SSRF-sensitive scanner endpoints:

    - SCANNER_TOKEN unset or blank:
        * in Railway production → 503 {"ok": False, "error": <not configured>}
          (fail closed — a deploy that lost its token must not turn open)
        * anywhere else → allow (open dev mode)
    - allow explicit X-Scanner-Token header matching SCANNER_TOKEN
      (constant-time comparison)
    - otherwise → 401 {"ok": False, "error": <denial message>}

PRODUCTION DETECTION: ``RAILWAY_ENVIRONMENT_NAME == "production"`` (stripped,
case-insensitive). Chosen over an app-level flag (e.g. ACPSEC_ENV) because
Railway injects it into every deployment by itself — the fail-closed guard is
armed with no extra variable, whereas a flag someone must remember to set fails
OPEN when forgotten, the very failure this guard exists to stop. Trade-off: the
guard is Railway-specific — hosting production elsewhere (or renaming the
Railway environment) needs this predicate updated. Local dev and ``pytest`` run
without the variable and stay open; ``railway run`` against production injects
it, so a local process started that way fails closed too.

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
SCANNER_UNCONFIGURED_ERROR = "scanner endpoint is not configured on this server"
SCANNER_UNCONFIGURED_BODY = {"ok": False, "error": SCANNER_UNCONFIGURED_ERROR}


class ScannerAccessDenied(Exception):
    """Raised by ``require_scanner_access`` when the gate rejects a request.

    Converted to a 401 JSON response by ``scanner_access_denied_handler``,
    registered on the app in main.py, so the body matches Flask exactly
    (a flat {"ok": False, "error": ...}, not FastAPI's {"detail": ...}).
    """


class ScannerNotConfigured(Exception):
    """Raised by ``require_scanner_access`` in production with no SCANNER_TOKEN.

    Rendered as a 503 by ``scanner_not_configured_handler`` (registered in
    main.py): the server is misconfigured, and no token the caller could send
    would be accepted, so this is not a 401.
    """


def scanner_token() -> str:
    """The configured SCANNER_TOKEN, whitespace-stripped ("" = unset/blank)."""
    return os.environ.get("SCANNER_TOKEN", "").strip()


def is_production() -> bool:
    """True on the Railway production environment (see module docstring)."""
    return os.environ.get("RAILWAY_ENVIRONMENT_NAME", "").strip().lower() == "production"


def scanner_mode() -> str:
    """How the gate treats a request: "token", "closed" or "open".

    Single source of truth — the gate below and /api/health's
    ``scanner_protected`` both read it, so the health flag can never report
    protection the gate does not enforce (e.g. a blank token in dev).
    """
    if scanner_token():
        return "token"
    return "closed" if is_production() else "open"


def require_scanner_access(request: Request) -> None:
    """FastAPI dependency: allow (return None) or raise.

    Truth table (Origin / Host are ignored — see module docstring):
      * SCANNER_TOKEN unset/blank, production → ScannerNotConfigured (503)
      * SCANNER_TOKEN unset/blank, elsewhere  → allow (open dev mode)
      * valid X-Scanner-Token                 → allow
      * else                                  → ScannerAccessDenied (401)
    """
    mode = scanner_mode()
    if mode == "open":
        return
    if mode == "closed":
        raise ScannerNotConfigured()

    required = scanner_token()

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


def scanner_not_configured_handler(
    request: Request, exc: ScannerNotConfigured
) -> JSONResponse:
    """Render ScannerNotConfigured as a flat 503 body (same shape as the 401)."""
    return JSONResponse(SCANNER_UNCONFIGURED_BODY, status_code=503)
