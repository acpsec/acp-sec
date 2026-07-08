"""FastAPI application instance for acpsec_api.

Creates the app, wires credentialed CORS for the split-origin deployment
(frontend on Vercel, API on Railway — Task 2.8), and mounts the routers.
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from acpsec_api.scanner_auth import (
    ScannerAccessDenied,
    scanner_access_denied_handler,
)
from acpsec_api.routers import b20, chat, health, leaderboard, onchain, scanner, score

# --- CORS (Task 2.8) ------------------------------------------------------
# Credentialed CORS (cookie auth) forbids a wildcard origin, so the allowlist is
# explicit static entries + a regex for Vercel preview deploys. Both are
# env-overridable so staging/prod can lock the list down without a code change.
_DEFAULT_CORS_ORIGINS = [
    "https://acpsec.app",
    "https://staging.acpsec.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
# Vercel preview URLs: acpsec-web-<hash>-<scope>.vercel.app
_DEFAULT_CORS_ORIGIN_REGEX = r"https://acpsec-web-[a-z0-9-]+\.vercel\.app"


def _cors_origins() -> list[str]:
    """Static allowlist — CORS_ALLOWED_ORIGINS (comma-separated) overrides."""
    raw = os.environ.get("CORS_ALLOWED_ORIGINS", "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return _DEFAULT_CORS_ORIGINS


def _cors_origin_regex() -> str:
    """Preview-deploy regex — CORS_ALLOWED_ORIGIN_REGEX overrides."""
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

# Scanner gate denials render as Flask's flat 401 body (not FastAPI's {"detail"}).
app.add_exception_handler(ScannerAccessDenied, scanner_access_denied_handler)

app.include_router(health.router)
app.include_router(score.router)
app.include_router(leaderboard.router)
app.include_router(scanner.router)
app.include_router(onchain.router)
app.include_router(chat.router)
app.include_router(b20.router)
