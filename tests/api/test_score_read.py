"""Contract tests for score READ endpoints.

Contracts (from dashboard/serve.py):
    GET    /api/score  empty      -> 200 {"ok": False, "data": None}
    GET    /api/score  populated  -> 200 {"ok": True,  "data": <dict>}
    DELETE /api/score             -> 200 {"ok": True}   (clears the caller's slot)

Per-visitor since the global slot was removed: seeding goes through a minted
session whose cookie the client then carries (see test_score_session.py).
    GET    /api/controls          -> 200 {source, acpsec_available, checks, asf_controls}

"""

from __future__ import annotations

from acpsec_api.routers.score import SCORE_SESSION_COOKIE


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


def _seed_visitor(client, store, data) -> None:
    sid = store.new_session()
    store.set(sid, data)
    client.cookies.set(SCORE_SESSION_COOKIE, sid, domain="testserver.local")  # cookiejar: dotless host → .local


def test_get_score_populated(isolated_client) -> None:
    client, store = isolated_client
    _seed_visitor(client, store, _SAMPLE_SCORE)
    resp = client.get("/api/score")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": _SAMPLE_SCORE}


def test_delete_score(isolated_client) -> None:
    client, store = isolated_client
    _seed_visitor(client, store, _SAMPLE_SCORE)

    resp = client.delete("/api/score")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    # After delete, GET returns the empty-state contract again.
    after = client.get("/api/score")
    assert after.status_code == 200
    assert after.json() == {"ok": False, "data": None}


# --- GET /api/controls (stateless) ---------------------------------------

def test_controls_full_body(fastapi_client) -> None:
    # Golden: /api/controls returns the acpsec catalogue + ASF defaults verbatim.
    # Frozen against the source of truth (not a brittle literal) while the Flask
    # parity oracle still existed and matched (see PR A1, now retired).
    from acpsec.catalogue import get_check_catalogue
    from acpsec_api.fallback_catalogue import ASF_CONTROLS_DEFAULT

    resp = fastapi_client.get("/api/controls")
    assert resp.status_code == 200
    assert resp.json() == {
        "source": "acpsec",
        "acpsec_available": True,
        "checks": get_check_catalogue(),
        "asf_controls": ASF_CONTROLS_DEFAULT,
    }
