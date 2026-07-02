"""Parity tests for GET /api/health (Task 2.2).

Contract (from dashboard/serve.py):
    {ok: bool, service: str, acpsec_available: bool, scanner_protected: bool}
"""

from __future__ import annotations

from tests.api.conftest import assert_parity


def test_health_returns_expected_shape(fastapi_client) -> None:
    resp = fastapi_client.get("/api/health")
    assert resp.status_code == 200

    body = resp.json()
    assert set(body) == {"ok", "service", "acpsec_available", "scanner_protected"}
    assert body["ok"] is True
    assert isinstance(body["service"], str)
    assert isinstance(body["acpsec_available"], bool)
    assert isinstance(body["scanner_protected"], bool)


def test_health_parity_with_flask(fastapi_client, flask_client) -> None:
    assert_parity(fastapi_client, flask_client, "/api/health")
