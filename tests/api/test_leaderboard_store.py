"""LeaderboardStore.upsert — persistence guards (#81 defense-in-depth).

The router refuses to persist an unrated scan (test_scanner_scan.py), but the
store itself must ALSO refuse — a future caller shouldn't be able to reintroduce
the #81 false-danger by upserting an unrated payload directly.
"""

from __future__ import annotations

from pathlib import Path

from acpsec_api.leaderboard_store import LeaderboardStore


def _store(tmp_path: Path) -> LeaderboardStore:
    return LeaderboardStore(path=tmp_path / "leaderboard.json")


def test_upsert_refuses_unrated_payload(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert({
        "agent_name": "Unreachable Agent",
        "rated": False,
        "band": "UNRATED",
        "final_score": None,
        "score_pct": None,
        "controls": [],
    })
    board = store.load()
    assert board.get("agents", []) == [], "unrated payload must not create a row"


def test_upsert_refuses_unrated_even_with_null_score(tmp_path: Path) -> None:
    # Without the guard, upsert would fall to `final_score or 0` -> 0 -> tier
    # COMPROMISED. The rated=False guard must short-circuit BEFORE that.
    store = _store(tmp_path)
    store.upsert({
        "agent_name": "No Website Agent",
        "rated": False,
        "final_score": None,
        "score_pct": None,
        "controls": [],
    })
    assert store.load().get("agents", []) == []


def test_upsert_still_persists_a_rated_scan(tmp_path: Path) -> None:
    # Regression: a normal (rated / full) scan is unchanged — rated absent is
    # treated as a full scan (back-compat), and rated=True persists.
    store = _store(tmp_path)
    store.upsert({
        "agent_name": "Good Agent",
        "score_pct": 82,
        "controls": [{"ctrl": "AUTH-01", "severity": "CRITICAL", "status": "fail"}],
    })
    agents = store.load()["agents"]
    assert len(agents) == 1
    assert agents[0]["name"] == "Good Agent"
    assert agents[0]["score"] == 82
    assert agents[0]["tier"] == "SECURE"


def test_upsert_persists_explicit_rated_true(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert({
        "agent_name": "Rated Agent",
        "rated": True,
        "score_pct": 55,
        "controls": [],
    })
    assert len(store.load()["agents"]) == 1
