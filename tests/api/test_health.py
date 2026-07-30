"""Parity tests for GET /api/health (Task 2.2).

Contract (from dashboard/serve.py), deliberately EXTENDED 2026-07-30 with two
prod-precondition booleans for the env smoke check (open-item #7 follow-up):
    {ok: bool, service: str, acpsec_available: bool,
     scanner_protected: bool, anthropic_configured: bool, leaderboard_configured: bool}

The exact-equality assertion (the hard-won A1 golden contract) is preserved —
only the frozen shape grew, on purpose.
"""

from __future__ import annotations


def test_health_returns_expected_shape(fastapi_client, monkeypatch) -> None:
    # Golden values frozen from the FastAPI response while the Flask parity test
    # (test_health_parity_with_flask) still passed — see PR A1. Extended with
    # anthropic_configured / leaderboard_configured (secret-presence booleans, same
    # idiom as scanner_protected): all three default False with the vars unset.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("LEADERBOARD_PASSWORD", raising=False)
    resp = fastapi_client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {
        "ok": True,
        "service": "acp-sec-dashboard",
        "acpsec_available": True,
        "scanner_protected": False,
        "anthropic_configured": False,
        "leaderboard_configured": False,
    }

    # Each presence flag is computed per-request from its env var.
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "pw")
    body = fastapi_client.get("/api/health").json()
    assert body["scanner_protected"] is True
    assert body["anthropic_configured"] is True
    assert body["leaderboard_configured"] is True
