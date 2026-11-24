"""The dashboard score is per visitor, never a shared global slot.

Each visitor's slot is bound to a server-minted, HttpOnly session cookie.
Visitors cannot read, overwrite or delete each other's score, and a cookie
value the server did not mint is never adopted. Separate TestClients model
separate browsers (separate cookie jars); https base URL so the default
``Secure`` cookie flows.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from acpsec_api.deps import get_score_store
from acpsec_api.main import app
from acpsec_api.routers.score import SCORE_SESSION_COOKIE
from acpsec_api.scoring import auto_normalise
from acpsec_api.store import SessionScoreStore

_ASF_A = {"agent_name": "Agent A", "controls": [{"ctrl": "AUTH-01", "score": 3, "max": 3}]}
_ASF_B = {"agent_name": "Agent B", "controls": [{"ctrl": "AUTH-01", "score": 1, "max": 3}]}


@pytest.fixture
def browsers():
    store = SessionScoreStore()
    app.dependency_overrides[get_score_store] = lambda: store
    try:
        yield (
            TestClient(app, base_url="https://testserver"),
            TestClient(app, base_url="https://testserver"),
            store,
        )
    finally:
        app.dependency_overrides.pop(get_score_store, None)


def test_score_is_per_visitor(browsers) -> None:
    a, b, _ = browsers
    assert a.post("/api/score", json=_ASF_A).status_code == 200
    assert a.get("/api/score").json() == {"ok": True, "data": auto_normalise(_ASF_A)}
    assert b.get("/api/score").json() == {"ok": False, "data": None}


def test_visitors_cannot_overwrite_each_other(browsers) -> None:
    a, b, _ = browsers
    a.post("/api/score", json=_ASF_A)
    b.post("/api/score", json=_ASF_B)
    assert a.get("/api/score").json()["data"] == auto_normalise(_ASF_A)
    assert b.get("/api/score").json()["data"] == auto_normalise(_ASF_B)


def test_manual_score_is_per_visitor_too(browsers) -> None:
    a, b, _ = browsers
    manual = {"agent_name": "M", "controls": [
        {"ctrl": "AUTH-01", "name": "x", "score": 3, "max": 3, "severity": "HIGH", "status": "pass"}]}
    assert a.post("/api/score/manual", json=manual).status_code == 200
    assert a.get("/api/score").json()["ok"] is True
    assert b.get("/api/score").json() == {"ok": False, "data": None}


def test_delete_only_clears_own_slot(browsers) -> None:
    a, b, _ = browsers
    a.post("/api/score", json=_ASF_A)
    assert b.delete("/api/score").json() == {"ok": True}
    assert a.get("/api/score").json()["data"] == auto_normalise(_ASF_A)
    assert a.delete("/api/score").json() == {"ok": True}
    assert a.get("/api/score").json() == {"ok": False, "data": None}


def test_unknown_session_cookie_is_not_adopted(browsers) -> None:
    a, _, store = browsers
    tried: list = []
    real_set = store.set
    store.set = lambda sid, data: tried.append(sid) or real_set(sid, data)  # spy
    # (cookiejar treats the dotless test host as "testserver.local")
    a.cookies.set(SCORE_SESSION_COOKIE, "attacker-chosen-value", domain="testserver.local")
    resp = a.post("/api/score", json=_ASF_A)
    minted = resp.cookies.get(SCORE_SESSION_COOKIE)
    assert tried[0] == "attacker-chosen-value"  # the forged id did reach the server…
    assert minted and minted != "attacker-chosen-value"  # …and was replaced, not adopted
    assert store.get("attacker-chosen-value") is None
    assert store.get(minted) == auto_normalise(_ASF_A)


def test_existing_session_is_reused_not_reminted(browsers) -> None:
    a, _, store = browsers
    first = a.post("/api/score", json=_ASF_A).cookies.get(SCORE_SESSION_COOKIE)
    second = a.post("/api/score", json=_ASF_B)
    assert second.cookies.get(SCORE_SESSION_COOKIE) is None  # no new Set-Cookie
    assert store.get(first) == auto_normalise(_ASF_B)
    assert len(store) == 1


def test_session_cookie_flags(browsers, monkeypatch) -> None:
    monkeypatch.delenv("ACPSEC_COOKIE_SAMESITE", raising=False)
    monkeypatch.delenv("ACPSEC_COOKIE_SECURE", raising=False)
    a, _, _ = browsers
    header = a.post("/api/score", json=_ASF_A).headers["set-cookie"].lower()
    for flag in ("httponly", "secure", "samesite=none", "path=/", "max-age="):
        assert flag in header


def test_get_and_delete_never_mint_a_session(browsers) -> None:
    a, _, store = browsers
    assert "set-cookie" not in a.get("/api/score").headers
    assert "set-cookie" not in a.delete("/api/score").headers
    assert len(store) == 0


# --- Store bounds (unit) --------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_store_evicts_least_recently_used_beyond_capacity() -> None:
    store = SessionScoreStore(max_sessions=3, ttl_seconds=3600, clock=_Clock())
    sids = [store.new_session() for _ in range(5)]
    for sid in sids:
        store.set(sid, {"n": sid})
    assert len(store) == 3
    assert store.get(sids[0]) is None and store.get(sids[1]) is None
    assert store.get(sids[4]) == {"n": sids[4]}


def test_store_expires_slots_after_ttl() -> None:
    clock = _Clock()
    store = SessionScoreStore(max_sessions=10, ttl_seconds=60, clock=clock)
    sid = store.new_session()
    store.set(sid, {"x": 1})
    clock.t = 59
    assert store.get(sid) == {"x": 1}
    clock.t = 61
    assert store.get(sid) is None
    assert not store.has(sid)


def test_store_refuses_to_write_an_unminted_id() -> None:
    store = SessionScoreStore()
    assert store.set("never-minted", {"x": 1}) is False
    assert store.get("never-minted") is None
