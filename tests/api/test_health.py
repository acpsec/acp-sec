"""Parity tests for GET /api/health (Task 2.2).

Contract (from dashboard/serve.py), deliberately EXTENDED 2026-07-30 with a
prod-precondition boolean for the env smoke check (open-item #7 follow-up):
    {ok: bool, service: str, acpsec_available: bool,
     scanner_protected: bool, scanner_configured: bool,
     leaderboard_configured: bool}

``scanner_protected`` = the scanner gate turns away unauthenticated callers
(token enforced, or production failing closed). ``scanner_configured`` = a
SCANNER_TOKEN is actually set — the prod-smoke precondition, since a fail-closed
production is protected but has a non-working scanner.

The exact-equality assertion (the hard-won A1 golden contract) is preserved —
only the frozen shape grew, on purpose.
"""

from __future__ import annotations

import pytest


def test_health_returns_expected_shape(fastapi_client, monkeypatch) -> None:
    # Golden values frozen from the FastAPI response while the Flask parity test
    # (test_health_parity_with_flask) still passed — see PR A1. Extended with
    # leaderboard_configured (secret-presence boolean, same idiom as
    # scanner_protected): both default False with the vars unset.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    monkeypatch.delenv("LEADERBOARD_PASSWORD", raising=False)
    resp = fastapi_client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {
        "ok": True,
        "service": "acp-sec-dashboard",
        "acpsec_available": True,
        "scanner_protected": False,
        "scanner_configured": False,
        "leaderboard_configured": False,
    }

    # Each presence flag is computed per-request from its env var.
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "pw")
    body = fastapi_client.get("/api/health").json()
    assert body["scanner_protected"] is True
    assert body["scanner_configured"] is True
    assert body["leaderboard_configured"] is True


def test_health_blank_scanner_token_not_protected(fastapi_client, monkeypatch) -> None:
    # Regression: a whitespace-only SCANNER_TOKEN leaves the gate OPEN (it strips
    # the value), so health must not report it as protected. The flag uses the
    # gate's own predicate — the prod-smoke precondition check relies on it.
    monkeypatch.setenv("SCANNER_TOKEN", "   ")
    body = fastapi_client.get("/api/health").json()
    assert body["scanner_protected"] is False
    assert body["scanner_configured"] is False


@pytest.mark.parametrize("token", [None, "   "], ids=["unset", "blank"])
def test_health_production_without_token_is_protected_not_configured(
    fastapi_client, monkeypatch, token
) -> None:
    # Production with no usable token fails CLOSED: nobody gets through the gate
    # (protected), but the scanner cannot work (not configured). The
    # prod-smoke precondition reads scanner_configured, so it still fires.
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    if token is None:
        monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    else:
        monkeypatch.setenv("SCANNER_TOKEN", token)
    body = fastapi_client.get("/api/health").json()
    assert body["scanner_protected"] is True
    assert body["scanner_configured"] is False


def test_health_production_with_token(fastapi_client, monkeypatch) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    body = fastapi_client.get("/api/health").json()
    assert body["scanner_protected"] is True
    assert body["scanner_configured"] is True
