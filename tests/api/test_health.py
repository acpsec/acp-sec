"""Parity tests for GET /api/health (Task 2.2).

Contract (from dashboard/serve.py), deliberately EXTENDED 2026-07-30 with a
prod-precondition boolean for the env smoke check (open-item #7 follow-up):
    {ok: bool, service: str, acpsec_available: bool,
     scanner_protected: bool, leaderboard_configured: bool}

The exact-equality assertion (the hard-won A1 golden contract) is preserved —
only the frozen shape grew, on purpose.
"""

from __future__ import annotations


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
        "leaderboard_configured": False,
    }

    # Each presence flag is computed per-request from its env var.
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "pw")
    body = fastapi_client.get("/api/health").json()
    assert body["scanner_protected"] is True
    assert body["leaderboard_configured"] is True
