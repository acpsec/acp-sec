"""Abuse hardening across the API (audit follow-ups).

- POST /api/leaderboard/auth is rate limited (password guessing)
- leaderboard sessions are pruned and bounded
- GET /api/report never writes (no directory creation on read)
- request bodies are capped (413), with or without Content-Length
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from acpsec_api.deps import get_reports_dir, get_score_store
from acpsec_api.main import MAX_BODY_BYTES, app
from acpsec_api.rate_limit import LIMITS, RATE_LIMITED_ERROR
from acpsec_api.sessions import LbSessions
from acpsec_api.store import SessionScoreStore


def test_leaderboard_auth_is_rate_limited(fastapi_client, monkeypatch) -> None:
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "correct horse")
    for _ in range(LIMITS["leaderboard_auth"].per_client):
        assert fastapi_client.post("/api/leaderboard/auth", json={"password": "guess"}).status_code == 401
    locked = fastapi_client.post("/api/leaderboard/auth", json={"password": "correct horse"})
    assert locked.status_code == 429
    assert locked.json() == {"ok": False, "error": RATE_LIMITED_ERROR}


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


def test_lb_sessions_prune_expired_on_create() -> None:
    clock = _Clock()
    sessions = LbSessions(clock=clock)
    old = [sessions.create() for _ in range(3)]
    clock.now += timedelta(days=8)  # past the 7-day expiry
    fresh = sessions.create()
    assert len(sessions) == 1
    assert sessions.valid(fresh) and not any(sessions.valid(t) for t in old)


def test_lb_sessions_are_bounded() -> None:
    sessions = LbSessions(max_sessions=2, clock=_Clock())
    first, second, third = (sessions.create() for _ in range(3))
    assert len(sessions) == 2
    assert not sessions.valid(first) and sessions.valid(second) and sessions.valid(third)


def test_report_get_is_read_only(tmp_path) -> None:
    missing = tmp_path / "no-reports-yet"
    app.dependency_overrides[get_reports_dir] = lambda: missing
    try:
        resp = TestClient(app).get("/api/report/someagent")
    finally:
        app.dependency_overrides.pop(get_reports_dir, None)
    assert resp.status_code == 404
    assert not missing.exists()


@pytest.fixture
def score_client():
    store = SessionScoreStore()
    app.dependency_overrides[get_score_store] = lambda: store
    try:
        yield TestClient(app, base_url="https://testserver")
    finally:
        app.dependency_overrides.pop(get_score_store, None)


def _json_of_size(n: int) -> bytes:
    """A valid JSON score payload of exactly ``n`` bytes."""
    prefix, suffix = '{"agent_name": "big", "controls": [], "pad": "', '"}'
    body = (prefix + "x" * (n - len(prefix) - len(suffix)) + suffix).encode()
    assert len(body) == n
    return body


def test_body_over_the_cap_is_413(score_client) -> None:
    resp = score_client.post(
        "/api/score", content=_json_of_size(MAX_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json() == {"ok": False, "error": "request body too large"}


def test_body_exactly_at_the_cap_is_accepted(score_client) -> None:
    resp = score_client.post(
        "/api/score", content=_json_of_size(MAX_BODY_BYTES),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code != 413


def test_chunked_body_over_the_cap_is_413(score_client) -> None:
    body = _json_of_size(MAX_BODY_BYTES + 1)
    chunks = (body[i:i + 65536] for i in range(0, len(body), 65536))  # no Content-Length
    resp = score_client.post("/api/score", content=chunks, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413


def test_realistic_report_body_still_accepted(score_client) -> None:
    # The largest seeded report is ~36 KB; a 200 KB payload is comfortably in.
    body = _json_of_size(200_000).replace(b'"controls": []', b'"controls": [{"ctrl": "AUTH-01", "score": 3, "max": 3}]')
    resp = score_client.post("/api/score", content=body, headers={"Content-Type": "application/json"})
    assert resp.status_code == 200


def test_body_cap_applies_to_pydantic_endpoints_too(fastapi_client) -> None:
    resp = fastapi_client.post(
        "/api/b20/scan", content=_json_of_size(MAX_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
