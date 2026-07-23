"""Parity tests for GET /api/health (Task 2.2).

Contract (from dashboard/serve.py):
    {ok: bool, service: str, acpsec_available: bool, scanner_protected: bool}
"""

from __future__ import annotations

from tests.api.conftest import assert_parity


def test_health_returns_expected_shape(fastapi_client, monkeypatch) -> None:
    # Golden values frozen from the FastAPI response while the Flask parity test
    # (test_health_parity_with_flask) still passed — see PR A1. This replaces the
    # byte-for-byte oracle with an exact, oracle-free contract assertion.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    resp = fastapi_client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {
        "ok": True,
        "service": "acp-sec-dashboard",
        "acpsec_available": True,
        "scanner_protected": False,
    }

    # scanner_protected is computed per-request from SCANNER_TOKEN presence.
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    assert fastapi_client.get("/api/health").json()["scanner_protected"] is True


def test_health_parity_with_flask(fastapi_client, flask_client) -> None:
    assert_parity(fastapi_client, flask_client, "/api/health")
