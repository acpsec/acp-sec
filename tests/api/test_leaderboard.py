"""Contract tests for leaderboard endpoints.

Contracts (from dashboard/serve.py):
    GET  /api/leaderboard        -> 200 {ok, updated, checks_per_scan, count, agents[]}
    GET  /api/report/{id}        -> 200 {ok:True, data} | 404 report_not_found | 400 invalid
    POST /api/leaderboard/auth   -> open {ok,token:"open"} | 401 wrong | 200 {ok} + cookie

Endpoint contracts are asserted against isolated temp-backed stores; the Flask
byte-for-byte parity oracle was retired with the Flask service.
"""

from __future__ import annotations

import json



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
    # Task 2.8 INTENTIONAL PARITY BREAK: for the split-origin deployment
    # (frontend on Vercel, API on Railway) the lb_session cookie must be sent
    # cross-origin, so the production default is now SameSite=None; Secure
    # (was SameSite=Lax; not-Secure, matching Flask). Flask is unchanged; this
    # deviation is deliberate — see test_cookie_* for the SameSite/Secure config.
    c = _parse_cookie(header)
    assert c["__name__"] == "lb_session"
    assert c["__value__"].startswith("lb_")
    assert c.get("max-age") == "604800"
    assert c.get("httponly") is True
    assert str(c.get("samesite", "")).lower() == "none"
    assert "secure" in c
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
    # (unhandled None > None TypeError). FastAPI handles this defensively
    # (null → 0). The deviation is deliberate: a crash is not a contract. This is
    # why there is NO populated-state Flask parity test for /api/leaderboard
    # (Flask would 500 on real null-score data). Multiple agents so the
    # score-descending sort path is exercised too — a null score must not break
    # sorting (Flask 500s before it ever sorts).
    client, store, _reports, _sessions = leaderboard_client
    store.save({
        "updated": "2026-07-03",
        "checks_per_scan": 38,
        "agents": [
            {"name": "Scored", "score": 75, "previous_score": 60, "tier": "SECURE"},
            {"name": "Unscored", "score": None, "previous_score": None, "tier": "COMPROMISED"},
        ],
    })
    resp = client.get("/api/leaderboard")
    assert resp.status_code == 200
    agents = resp.json()["agents"]
    by_name = {a["name"]: a for a in agents}

    # Null-score agent renders defensively and sorts last (treated as 0).
    unscored = by_name["Unscored"]
    assert unscored["movement"] == "same"
    assert unscored["movement_delta"] == 0
    assert unscored["rank"] == 2
    assert by_name["Scored"]["rank"] == 1


# /api/leaderboard populated + empty states are covered above against isolated
# temp-backed stores (test_leaderboard_populated / test_leaderboard_empty).


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


# --- POST /api/leaderboard/auth ------------------------------------------

def test_auth_no_password_open(leaderboard_client, monkeypatch) -> None:
    monkeypatch.delenv("LEADERBOARD_PASSWORD", raising=False)
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.post("/api/leaderboard/auth", json={"password": "anything"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "token": "open"}


def test_auth_correct_password(leaderboard_client, monkeypatch) -> None:
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "s3cret")
    # No cookie overrides → production defaults (SameSite=None; Secure).
    monkeypatch.delenv("ACPSEC_COOKIE_SAMESITE", raising=False)
    monkeypatch.delenv("ACPSEC_COOKIE_SECURE", raising=False)
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


# --- Cookie flag env configuration (Task 2.8) ----------------------------

def test_cookie_production_flags(leaderboard_client, monkeypatch) -> None:
    # Default (no overrides) = production: SameSite=None; Secure. Requires HTTPS
    # in the browser, which the Railway/Vercel split deployment provides.
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "s3cret")
    monkeypatch.delenv("ACPSEC_COOKIE_SAMESITE", raising=False)
    monkeypatch.delenv("ACPSEC_COOKIE_SECURE", raising=False)
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.post("/api/leaderboard/auth", json={"password": "s3cret"})
    assert resp.status_code == 200
    c = _parse_cookie(resp.headers["set-cookie"])
    assert str(c.get("samesite", "")).lower() == "none"
    assert "secure" in c


def test_cookie_dev_flags(leaderboard_client, monkeypatch) -> None:
    # Local-dev override: SameSite=Lax; not-Secure so the cookie works over plain
    # http://localhost (SameSite=None would require Secure, which localhost lacks).
    monkeypatch.setenv("LEADERBOARD_PASSWORD", "s3cret")
    monkeypatch.setenv("ACPSEC_COOKIE_SAMESITE", "lax")
    monkeypatch.setenv("ACPSEC_COOKIE_SECURE", "false")
    client, _store, _reports, _sessions = leaderboard_client
    resp = client.post("/api/leaderboard/auth", json={"password": "s3cret"})
    assert resp.status_code == 200
    c = _parse_cookie(resp.headers["set-cookie"])
    assert str(c.get("samesite", "")).lower() == "lax"
    assert "secure" not in c
