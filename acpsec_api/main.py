"""FastAPI application instance for acpsec_api.

Creates the app, wires credentialed CORS for the split-origin deployment
(frontend on Vercel, API on Railway — Task 2.8), and mounts the routers.
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from acpsec_api.scanner_auth import (
    ScannerAccessDenied,
    ScannerNotConfigured,
    scanner_access_denied_handler,
    scanner_not_configured_handler,
)
from acpsec_api.routers import b20, health, leaderboard, onchain, scanner, score

# --- CORS (Task 2.8) ------------------------------------------------------
# Credentialed CORS (cookie auth) forbids a wildcard origin, so the allowlist is
# explicit static entries, plus an OPT-IN regex. Both are env-overridable so
# staging/prod can lock the list down without a code change.
_DEFAULT_CORS_ORIGINS = [
    "https://acpsec.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
# No default origin regex. The former default (https://acpsec-web-[a-z0-9-]+\.vercel\.app)
# matched ANY Vercel project named "acpsec-web-*": vercel.app hostnames are
# first-come across all Vercel accounts, so anyone could host a credentialed,
# allowed origin — and it matched none of our real projects. Prefer exact
# origins; set CORS_ALLOWED_ORIGIN_REGEX only for hostnames you control.
_DEFAULT_CORS_ORIGIN_REGEX: str | None = None


def _cors_origins() -> list[str]:
    """Static allowlist — CORS_ALLOWED_ORIGINS (comma-separated) overrides."""
    raw = os.environ.get("CORS_ALLOWED_ORIGINS", "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return _DEFAULT_CORS_ORIGINS


def _cors_origin_regex() -> str | None:
    """Origin regex — opt-in via CORS_ALLOWED_ORIGIN_REGEX (default: none)."""
    return os.environ.get("CORS_ALLOWED_ORIGIN_REGEX", "").strip() or _DEFAULT_CORS_ORIGIN_REGEX


app = FastAPI(
    title="ACP-SEC API",
    description="FastAPI backend for the ACP-SEC dashboard/app.",
    version="0.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_origin_regex=_cors_origin_regex(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Scanner gate denials render as Flask's flat 401 body (not FastAPI's {"detail"});
# production without a SCANNER_TOKEN fails closed — same flat shape, as a 503.
app.add_exception_handler(ScannerAccessDenied, scanner_access_denied_handler)
app.add_exception_handler(ScannerNotConfigured, scanner_not_configured_handler)

app.include_router(health.router)
app.include_router(score.router)
app.include_router(leaderboard.router)
app.include_router(scanner.router)
app.include_router(onchain.router)
app.include_router(b20.router)
