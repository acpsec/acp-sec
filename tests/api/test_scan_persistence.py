"""What /api/scanner/scan and /bulk persist comes only from the server's own fetch.

Leaderboard identity is the host of the engine's final ``scan_url`` (www.
folded); an entry can only be updated by a scan of the host it is bound to
(``scan_host``). Client-supplied ``agent_name`` / ``username`` / ``scraped`` /
``x_bio`` never reach the leaderboard or the saved report — the response still
echoes them for display, unchanged. Only rated, root-mode scans are persisted.
Engine stubbed — no network.
"""

from __future__ import annotations

import copy
import json

from acpsec_api.leaderboard_store import LeaderboardStore

_SEEDED = {
    "id": "acme", "name": "acme", "x_handle": "acme_bot", "scan_host": "acme.test",
    "score": 18, "previous_score": 18, "tier": "CRITICAL", "critical_fails": 4,
    "category": "general", "token": None, "base_mcp": False, "limited_scan": False,
}


class _Engine:
    """Canned rated scan whose final URL is ``scan_url``; bio yields a token."""

    def __init__(self, scan_url: str, score: float = 77) -> None:
        self.scan_url = scan_url
        self.score = score

    def analyze_agent(self, url, agent_name="", scan_mode="root"):
        return {"ok": True, "error": None, "data": {
            "agent_name": agent_name, "scan_url": self.scan_url, "score_pct": self.score,
            "controls": [{"ctrl": "AUTH-01", "severity": "CRITICAL", "status": "fail"}],
            "token": {}, "_body_text_for_token": "",
        }}

    def extract_token_info(self, html="", x_bio=""):
        return {"has_token": bool(x_bio), "ticker": "OTHER", "contract_address": "0x" + "e" * 40}


def _seed(lb_store: LeaderboardStore) -> None:
    lb_store.save({"updated": "", "checks_per_scan": 38, "agents": [copy.deepcopy(_SEEDED)]})


def _entry(lb_store: LeaderboardStore, agent_id: str) -> dict | None:
    return next((a for a in lb_store.load()["agents"] if a["id"] == agent_id), None)


_FORGED = {
    "agent_name": "acme", "username": "acme_bot", "scraped": True,
    "x_bio": "official $OTHER token, CA 0x" + "e" * 40,
}


def test_forged_identity_cannot_touch_an_existing_entry(scan_client) -> None:
    make, lb_store, reports_dir = scan_client[:3]
    _seed(lb_store)
    client = make(_Engine("https://unrelated.example/"))
    resp = client.post("/api/scanner/scan", json={"url": "https://unrelated.example", **_FORGED})
    assert resp.status_code == 200

    assert _entry(lb_store, "acme") == _SEEDED  # untouched
    assert not (reports_dir / "acme.json").exists()

    new = _entry(lb_store, "unrelated_example")
    assert new["scan_host"] == "unrelated.example"
    assert new["name"] == "unrelated.example"
    assert new["x_handle"] == "unrelated_example"
    assert new["token"] is None  # the client-sent bio never reaches storage
    report = json.loads((reports_dir / "unrelated_example.json").read_text())
    assert report["agent_name"] == "unrelated.example"
    assert report["x_username"] == ""
    assert report["x_handle_verified"] is False
    assert report["token"] == {}


def test_forged_name_alone_cannot_overwrite_an_entry(scan_client) -> None:
    # No username: the display name used to be the leaderboard key on its own.
    make, lb_store, _reports = scan_client[:3]
    _seed(lb_store)
    client = make(_Engine("https://unrelated.example/", score=99))
    client.post("/api/scanner/scan", json={"url": "https://unrelated.example", "agent_name": "acme"})
    assert _entry(lb_store, "acme") == _SEEDED
    assert not any(a["name"] == "acme" and a["id"] != "acme" for a in lb_store.load()["agents"])


def test_forged_handle_cannot_create_an_impersonating_entry(scan_client) -> None:
    make, lb_store, _reports = scan_client[:3]
    _seed(lb_store)
    client = make(_Engine("https://unrelated.example/"))
    client.post("/api/scanner/scan", json={"url": "https://unrelated.example", **_FORGED})
    handles = [a.get("x_handle") for a in lb_store.load()["agents"]]
    assert handles.count("acme_bot") == 1  # only the curated entry carries it


def test_response_still_echoes_client_display_fields(scan_client) -> None:
    make, *_ = scan_client
    client = make(_Engine("https://unrelated.example/"))
    data = client.post("/api/scanner/scan", json={"url": "https://unrelated.example", **_FORGED}).json()["data"]
    assert data["agent_name"] == "acme"
    assert data["x_username"] == "acme_bot"
    assert data["x_handle_verified"] is True
    assert data["token"]["ticker"] == "OTHER"  # display only


def test_scan_of_the_bound_host_updates_that_entry(scan_client) -> None:
    make, lb_store, reports_dir = scan_client[:3]
    _seed(lb_store)
    client = make(_Engine("https://www.acme.test/", score=61))
    client.post("/api/scanner/scan", json={
        "url": "https://acme.test", "agent_name": "someone else", "username": "other", "scraped": True,
    })
    entry = _entry(lb_store, "acme")
    assert entry["score"] == 61 and entry["previous_score"] == 18
    assert (entry["name"], entry["x_handle"]) == ("acme", "acme_bot")  # curated, kept
    assert len(lb_store.load()["agents"]) == 1  # no duplicate entry
    report = json.loads((reports_dir / "acme.json").read_text())
    assert report["agent_name"] == "acme"
    assert report["x_username"] == ""


def test_exact_mode_scans_are_not_persisted(scan_client) -> None:
    make, lb_store, reports_dir = scan_client[:3]
    _seed(lb_store)
    client = make(_Engine("https://acme.test/some/deep/page", score=3))
    resp = client.post("/api/scanner/scan", json={"url": "https://acme.test/some/deep/page", "scan_mode": "exact"})
    assert resp.status_code == 200
    assert _entry(lb_store, "acme") == _SEEDED
    assert not reports_dir.exists() or not any(reports_dir.iterdir())


def test_rated_scan_without_a_host_is_not_persisted(scan_client) -> None:
    make, lb_store, reports_dir = scan_client[:3]
    client = make(_Engine(""))
    client.post("/api/scanner/scan", json={"url": "https://x.example", "agent_name": "nohost"})
    assert lb_store.load()["agents"] == []
    assert not reports_dir.exists() or not any(reports_dir.iterdir())


def test_bulk_usernames_never_become_identity(scan_client, monkeypatch) -> None:
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)
    make, lb_store, reports_dir = scan_client[:3]
    _seed(lb_store)

    class _PerHandle(_Engine):
        def analyze_agent(self, url, agent_name="", scan_mode="root"):
            res = super().analyze_agent(url, agent_name, scan_mode)
            res["data"]["scan_url"] = f"https://{agent_name}.example/"
            return res

    client = make(_PerHandle(""))
    resp = client.post("/api/scanner/bulk", json={"usernames": ["acme", "gamma"]})
    assert resp.status_code == 200
    assert [r["data"]["x_username"] for r in resp.json()["results"]] == ["acme", "gamma"]  # display
    assert _entry(lb_store, "acme") == _SEEDED  # username "acme" did not hit the seeded entry
    assert {a["id"] for a in lb_store.load()["agents"]} == {"acme", "acme_example", "gamma_example"}
    assert json.loads((reports_dir / "gamma_example.json").read_text())["agent_name"] == "gamma.example"


# --- Store level ---------------------------------------------------------------


def _rated(scan_url: str, score: float = 50) -> dict:
    return {"scan_url": scan_url, "score_pct": score, "controls": [], "token": {}}


def test_ids_from_colliding_hosts_are_disambiguated(tmp_path) -> None:
    store = LeaderboardStore(path=tmp_path / "lb.json")
    a = store.upsert(_rated("https://a-b.com/"))
    b = store.upsert(_rated("https://a.b.com/"))
    assert a["id"] == "a_b_com"
    assert b["id"] != a["id"] and b["id"].startswith("a_b_com_")
    assert store.upsert(_rated("https://a.b.com/", score=90))["id"] == b["id"]  # stable
    assert len(store.load()["agents"]) == 2


def test_upsert_ignores_client_identity_fields(tmp_path) -> None:
    store = LeaderboardStore(path=tmp_path / "lb.json")
    entry = store.upsert({**_rated("https://site.example/"),
                          "agent_name": "Forged", "x_username": "victim", "x_handle_verified": True})
    assert (entry["id"], entry["name"], entry["x_handle"]) == ("site_example", "site.example", "site_example")


def test_seeded_entries_are_bound_to_the_hosts_of_their_reports() -> None:
    # Continuity: every curated entry carries the host its own report was
    # scanned at, so re-scanning that site updates it instead of duplicating it.
    from pathlib import Path
    from urllib.parse import urlsplit

    root = Path(__file__).resolve().parents[2] / "data"
    for agent in json.loads((root / "leaderboard.json").read_text())["agents"]:
        report = json.loads((root / "reports" / f"{agent['id']}.json").read_text())
        host = (urlsplit(report["scan_url"]).hostname or "").removeprefix("www.")
        assert agent.get("scan_host") == host, agent["id"]
