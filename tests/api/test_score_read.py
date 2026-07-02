"""Parity + contract tests for score READ endpoints (Task 2.3a).

Contracts (from dashboard/serve.py):
    GET    /api/score  empty      -> 200 {"ok": False, "data": None}
    GET    /api/score  populated  -> 200 {"ok": True,  "data": <dict>}
    DELETE /api/score             -> 200 {"ok": True}   (clears memory + file)
    GET    /api/controls          -> 200 {source, acpsec_available, checks, asf_controls}

Parity notes:
  * /api/controls is stateless → full Flask parity via assert_parity.
  * /api/score is stateful and Flask's store isn't externally seedable, so we
    only parity-check the EMPTY state (both apps fresh = both empty). Seeded /
    delete behaviour is asserted FastAPI-only against an isolated temp store.
"""

from __future__ import annotations

from acpsec_api.store import _DEFAULT_STORE_FILE
from tests.api.conftest import assert_parity

_SAMPLE_SCORE = {
    "agent_name": "Test Agent",
    "final_score": 87.5,
    "band": "A",
    "verdict": "HARDENED",
    "controls": [{"ctrl": "AUTH-01", "score": 3, "max": 3}],
    "source": "manual",
}


# --- GET /api/score -------------------------------------------------------

def test_get_score_empty_state(isolated_client) -> None:
    client, _store = isolated_client
    resp = client.get("/api/score")
    assert resp.status_code == 200
    assert resp.json() == {"ok": False, "data": None}


def test_get_score_populated(isolated_client) -> None:
    client, store = isolated_client
    store.set(_SAMPLE_SCORE)
    resp = client.get("/api/score")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": _SAMPLE_SCORE}


def test_delete_score(isolated_client) -> None:
    client, store = isolated_client
    store.set(_SAMPLE_SCORE)

    resp = client.delete("/api/score")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    # After delete, GET returns the empty-state contract again.
    after = client.get("/api/score")
    assert after.status_code == 200
    assert after.json() == {"ok": False, "data": None}


def test_get_score_empty_parity_with_flask(fastapi_client, flask_client) -> None:
    # Empty-state parity is only meaningful when the real store is empty. Flask's
    # test client reads the real dashboard/score_store.json, which we cannot
    # seed from outside; skip rather than assert against unknown data.
    import pytest

    if _DEFAULT_STORE_FILE.exists():
        pytest.skip("real score store is populated; empty-state parity not applicable")
    assert_parity(fastapi_client, flask_client, "/api/score", "GET")


# --- GET /api/controls (stateless → full parity) --------------------------

def test_controls_shape(fastapi_client) -> None:
    resp = fastapi_client.get("/api/controls")
    assert resp.status_code == 200

    body = resp.json()
    assert set(body) == {"source", "acpsec_available", "checks", "asf_controls"}
    assert isinstance(body["source"], str)
    assert isinstance(body["acpsec_available"], bool)
    assert isinstance(body["checks"], list) and body["checks"]
    assert isinstance(body["asf_controls"], list) and body["asf_controls"]


def test_controls_parity_with_flask(fastapi_client, flask_client) -> None:
    assert_parity(fastapi_client, flask_client, "/api/controls", "GET")
