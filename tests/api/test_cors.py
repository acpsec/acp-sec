"""CORS configuration tests (Task 2.8 — split-origin deployment).

The FastAPI app runs on a different origin (Railway) than the frontend (Vercel),
so credentialed CORS must be configured explicitly. These tests exercise the
default allowlist baked into acpsec_api.main at import:

    static : https://acpsec.app, http://localhost:3000, http://127.0.0.1:3000
    regex  : https://acpsec-web-<...>.vercel.app  (Vercel preview deploys)

Starlette preflight behaviour (verified): an allowed Origin returns 200 with
``Access-Control-Allow-Origin`` echoed; a disallowed Origin returns 400 with NO
``Access-Control-Allow-Origin`` header (so the browser blocks the response).

Credentialed CORS cannot use a wildcard origin — the allowlist is explicit +
regex, never ``*``.
"""

from __future__ import annotations

import pytest


def _preflight(client, origin: str, method: str = "GET"):
    return client.options(
        "/api/health",
        headers={"Origin": origin, "Access-Control-Request-Method": method},
    )


# --- Allowed origins ------------------------------------------------------

@pytest.mark.parametrize(
    "origin",
    [
        "https://acpsec.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
)
def test_cors_allowed_static_origins(fastapi_client, origin) -> None:
    resp = _preflight(fastapi_client, origin)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == origin


def test_cors_vercel_preview_origin(fastapi_client) -> None:
    # Vercel preview URLs (acpsec-web-<hash>-<scope>.vercel.app) match the regex.
    origin = "https://acpsec-web-git-feat-x-acpsec.vercel.app"
    resp = _preflight(fastapi_client, origin)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == origin


# --- Disallowed origins ---------------------------------------------------

def test_cors_disallowed_origin(fastapi_client) -> None:
    # A foreign origin gets NO Access-Control-Allow-Origin → browser blocks it.
    resp = _preflight(fastapi_client, "https://evil.com")
    assert "access-control-allow-origin" not in resp.headers


def test_cors_disallowed_lookalike_vercel(fastapi_client) -> None:
    # A different Vercel project must NOT match the acpsec-web-* regex.
    resp = _preflight(fastapi_client, "https://evil-web-abc.vercel.app")
    assert "access-control-allow-origin" not in resp.headers


def test_cors_staging_origin_removed(fastapi_client) -> None:
    # The staging line (staging.acpsec.app) was decommissioned — the Railway
    # service, the deploy/staging branch, and the Vercel project are all deleted.
    # It must no longer be in the default allowlist: a preflight from it gets NO
    # Access-Control-Allow-Origin header, exactly like any other foreign origin.
    resp = _preflight(fastapi_client, "https://staging.acpsec.app")
    assert "access-control-allow-origin" not in resp.headers


# --- Credentialed CORS ----------------------------------------------------

def test_cors_credentialed(fastapi_client) -> None:
    # Cookie auth needs credentialed CORS: allow-credentials must be true on an
    # allowed origin, and the origin must be echoed (not "*", which browsers
    # reject alongside credentials).
    resp = _preflight(fastapi_client, "https://acpsec.app")
    assert resp.headers.get("access-control-allow-credentials") == "true"
    assert resp.headers.get("access-control-allow-origin") == "https://acpsec.app"


def test_cors_actual_request_has_headers(fastapi_client) -> None:
    # A real (non-preflight) GET from an allowed origin carries the CORS headers.
    resp = fastapi_client.get("/api/health", headers={"Origin": "https://acpsec.app"})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "https://acpsec.app"
    assert resp.headers.get("access-control-allow-credentials") == "true"
