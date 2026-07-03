"""Parity + contract tests for leaderboard endpoints (Task 2.4).

Contracts (from dashboard/serve.py):
    GET  /api/leaderboard        -> 200 {ok, updated, checks_per_scan, count, agents[]}
    GET  /api/report/{id}        -> 200 {ok:True, data} | 404 report_not_found | 400 invalid
    POST /api/leaderboard/auth   -> open {ok,token:"open"} | 401 wrong | 200 {ok} + cookie

Parity note: the real dashboard/leaderboard.json + dashboard/reports/ are seeded,
so full parity uses the default (real-file-backed) client on BOTH apps — they read
the same files. Empty / seeded-shape assertions use an isolated temp-backed client.
"""

from __future__ import annotations

import json

from tests.api.conftest import assert_parity

_REAL_AGENT = "aixbt"  # exists in dashboard/reports/aixbt.json


def _parse_cookie(header: str) -> dict:
    """Parse a Set-Cookie header into {name, value, <lowercased attrs>}."""
    parts = [p.strip() for p in header.split(";")]
    name, _, value = parts[0].partition("=")
    attrs: dict = {"__name__": name, "__value__": value}
    for p in parts[1:]:
        if "=" in p:
            k, _, v = p.partition("=")
            attrs[k.lower()] = v
        else:
            attrs[p.lower()] = True
    return attrs


def _assert_lb_cookie(header: str) -> None:
    c = _parse_cookie(header)
    assert c["__name__"] == "lb_session"
    assert c["__value__"].startswith("lb_")
    assert c.get("max-age") == "604800"
    assert c.get("httponly") is True
    assert str(c.get("samesite", "")).lower() == "lax"
    assert "secure" not in c
    assert c.get("path") == "/"


# --- GET /api/leaderboard -------------------------------------------------

def test_leaderboard_empty(leaderboard_client) -> None:
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.get("/api/leaderboard")
    assert resp.status_code == 200
    assert resp.json() == {
        "ok": True,
        "updated": "",
        "checks_per_scan": 38,
        "count": 0,
        "agents": [],
    }


def test_leaderboard_populated(leaderboard_client) -> None:
    client, store, _reports, _sessions = leaderboard_client
    store.save({
        "updated": "2026-07-01",
        "checks_per_scan": 38,
        "agents": [
            {"name": "Alpha", "score": 80, "previous_score": 70, "tier": "SECURE"},
            {"name": "Bravo", "score": 95, "previous_score": 95, "tier": "EXEMPLARY"},
            {"name": "Charlie", "score": 40, "previous_score": 55, "tier": "VULNERABLE"},
        ],
    })
    resp = client.get("/api/leaderboard")
    assert resp.status_code == 200
    body = resp.json()

    assert body["ok"] is True
    assert body["updated"] == "2026-07-01"
    assert body["checks_per_scan"] == 38
    assert body["count"] == 3

    agents = body["agents"]
    # Sorted by score desc → Bravo, Alpha, Charlie with ranks 1..3
    assert [a["name"] for a in agents] == ["Bravo", "Alpha", "Charlie"]
    assert [a["rank"] for a in agents] == [1, 2, 3]
    # Movement derived from previous_score
    by_name = {a["name"]: a for a in agents}
    assert by_name["Alpha"]["movement"] == "up" and by_name["Alpha"]["movement_delta"] == 10
    assert by_name["Bravo"]["movement"] == "same" and by_name["Bravo"]["movement_delta"] == 0
    assert by_name["Charlie"]["movement"] == "down" and by_name["Charlie"]["movement_delta"] == -15
    # Six-band tier field preserved from the store
    assert by_name["Bravo"]["tier"] == "EXEMPLARY"


def test_leaderboard_null_scores_handled(leaderboard_client) -> None:
    # INTENTIONAL PARITY DEVIATION: Flask 500s on agents with null scores
    # (unhandled None > None TypeError — e.g. the seeded SentryAgent entry).
    # FastAPI handles this defensively (null → 0). The deviation is deliberate:
    # a crash is not a contract. This is why there is NO populated-state Flask
    # parity test for /api/leaderboard (Flask would 500 on the real seed data).
    # Multiple agents so the score-descending sort path is exercised too — a
    # null score must not break sorting (Flask 500s before it ever sorts).
    client, store, _reports, _sessions = leaderboard_client
    store.save({
        "updated": "2026-07-03",
        "checks_per_scan": 38,
        "agents": [
            {"name": "Scored", "score": 75, "previous_score": 60, "tier": "SECURE"},
            {"name": "SentryAgent", "score": None, "previous_score": None, "tier": "COMPROMISED"},
        ],
    })
    resp = client.get("/api/leaderboard")
    assert resp.status_code == 200
    agents = resp.json()["agents"]
    by_name = {a["name"]: a for a in agents}

    # Null-score agent renders defensively and sorts last (treated as 0).
    sentry = by_name["SentryAgent"]
    assert sentry["movement"] == "same"
    assert sentry["movement_delta"] == 0
    assert sentry["rank"] == 2
    assert by_name["Scored"]["rank"] == 1


# NOTE: /api/leaderboard has no populated-state parity test on purpose — the real
# seeded dashboard/leaderboard.json contains a null-score agent that makes the
# Flask reference 500 (see test_leaderboard_null_scores_handled). Empty-state
# parity is not asserted either, since Flask's store is the always-present seed
# file (not externally emptyable). Report + auth parity below still apply.


# --- GET /api/report/{id} -------------------------------------------------

def test_report_found(leaderboard_client) -> None:
    client, _store, reports_dir, _sessions = leaderboard_client
    reports_dir.mkdir(parents=True, exist_ok=True)
    payload = {"agent": "myagent", "controls": [{"ctrl": "AUTH-01", "score": 3}]}
    (reports_dir / "myagent.json").write_text(json.dumps(payload))

    resp = client.get("/api/report/myagent")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": payload}


def test_report_not_found(leaderboard_client) -> None:
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.get("/api/report/nope")
    assert resp.status_code == 404
    assert resp.json() == {
        "ok": False,
        "error": "report_not_found",
        "message": (
            "Full report not available for this agent. "
            "Re-scan it from the Scanner page for a detailed breakdown."
        ),
        "scan_url": "/scanner",
    }


def test_report_invalid_id(leaderboard_client) -> None:
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.get("/api/report/@@@")
    assert resp.status_code == 400
    assert resp.json() == {"ok": False, "error": "invalid agent id"}


def test_report_found_parity(fastapi_client, flask_client) -> None:
    # Both read the real dashboard/reports/aixbt.json → identical.
    assert_parity(fastapi_client, flask_client, f"/api/report/{_REAL_AGENT}", "GET")


def test_report_not_found_parity(fastapi_client, flask_client) -> None:
    assert_parity(fastapi_client, flask_client, "/api/report/nonexistent_xyz", "GET")


# --- POST /api/leaderboard/auth ------------------------------------------

def test_auth_no_password_open(leaderboard_client, monkeypatch) -> None:
    monkeypatch.delenv("LEADERBOARD_PASSWORD", raising=False)
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.post("/api/leaderboard/auth", json={"password": "anything"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "token": "open"}


def test_auth_correct_password(leaderboard_client, monkeypatch) -> None:
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "s3cret")
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.post("/api/leaderboard/auth", json={"password": "s3cret"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    _assert_lb_cookie(resp.headers["set-cookie"])


def test_auth_wrong_password(leaderboard_client, monkeypatch) -> None:
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "s3cret")
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.post("/api/leaderboard/auth", json={"password": "nope"})
    assert resp.status_code == 401
    assert resp.json() == {"ok": False, "error": "Incorrect password"}
    assert "set-cookie" not in resp.headers


def test_auth_wrong_parity(fastapi_client, flask_client, monkeypatch) -> None:
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "s3cret")
    assert_parity(
        fastapi_client, flask_client, "/api/leaderboard/auth", "POST",
        json={"password": "nope"},
    )


def test_auth_correct_parity(fastapi_client, flask_client, monkeypatch) -> None:
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "s3cret")
    fa = fastapi_client.post("/api/leaderboard/auth", json={"password": "s3cret"})
    fl = flask_client.post("/api/leaderboard/auth", json={"password": "s3cret"})

    assert fa.status_code == fl.status_code == 200
    assert fa.json() == fl.get_json() == {"ok": True}

    # Cookie flags must match (token values differ by design).
    fa_c = _parse_cookie(fa.headers["set-cookie"])
    fl_c = _parse_cookie(fl.headers["Set-Cookie"])
    assert fa_c["__name__"] == fl_c["__name__"] == "lb_session"
    assert fa_c["__value__"].startswith("lb_") and fl_c["__value__"].startswith("lb_")
    assert fa_c.get("max-age") == fl_c.get("max-age") == "604800"
    assert fa_c.get("httponly") is True and fl_c.get("httponly") is True
    assert str(fa_c.get("samesite", "")).lower() == str(fl_c.get("samesite", "")).lower() == "lax"
    assert "secure" not in fa_c and "secure" not in fl_c
    assert fa_c.get("path") == fl_c.get("path") == "/"
