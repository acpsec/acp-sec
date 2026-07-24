"""Parity + contract tests for POST /api/scanner/bulk (Task 2.5b-ii).

SECURITY-SENSITIVE + side effects. The heuristic engine is STUBBED in every
test — no live heuristic run, no external network — and the inter-scan
``time.sleep(5)`` throttle is patched to a no-op so the suite stays fast. All
write targets (leaderboard, reports dir) are temp-backed via the scan_client
fixture, so nothing touches the real dashboard files.

Contract (dashboard/serve.py scanner_bulk):
    gate denied          -> 401 (reuses 2.5a gate)
    not JSON             -> 415 {"error": "Content-Type must be application/json"}
    empty usernames      -> 422 {"error": "'usernames' must be a non-empty list"}
    > 10 usernames       -> 422 {"error": "Too many agents — maximum 10 per request, got N"}
    engine unavailable   -> 503 {"error": "scanner module not available"}
    success              -> 200 {ok, count, results[]} — one entry per input
                            username, each {username, ok, data?|error?}. Failures
                            (raise or ok:False) are captured per-item; the batch
                            continues. Each SUCCESSFUL item upserts the leaderboard
                            and writes a report (best-effort).
"""

from __future__ import annotations

import json

from acpsec_api.scanner_auth import SCANNER_DENIED_ERROR


class _BulkStubEngine:
    """Stand-in for dashboard/scanner — no network, canned per-username results.

    In bulk, the handler passes ``agent_name=username``, so we key canned
    behavior off ``agent_name``:
        - username in ``raise_for``  -> analyze_agent raises (per-item exception)
        - username in ``fail_for``   -> returns {ok:False} (per-item scan failure)
        - otherwise                  -> returns a passing scan for that agent
    """

    def __init__(self, fail_for=None, raise_for=None) -> None:
        self.fail_for = set(fail_for or [])
        self.raise_for = set(raise_for or [])
        self.calls: list = []

    def analyze_agent(self, url, agent_name="", scan_mode="root"):
        self.calls.append((url, agent_name, scan_mode))
        if agent_name in self.raise_for:
            raise RuntimeError(f"boom {agent_name}")
        if agent_name in self.fail_for:
            return {"ok": False, "error": f"scan failed for {agent_name}"}
        return {
            "ok": True,
            "error": None,
            "data": {
                "agent_name": agent_name,
                "score_pct": 82,
                "controls": [
                    {"ctrl": "AUTH-01", "severity": "CRITICAL", "status": "fail"},
                    {"ctrl": "CTX-01", "severity": "HIGH", "status": "pass"},
                ],
                "token": {},
            },
        }


def _no_sleep(monkeypatch) -> None:
    """Patch the inter-scan throttle so multi-item tests don't wait 5s each."""
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)


# --- Auth gate ------------------------------------------------------------

def test_bulk_denied_no_auth(scan_client, monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    make, _lb, _reports, _scan = scan_client
    client = make(_BulkStubEngine())
    resp = client.post("/api/scanner/bulk", json={"usernames": ["alpha", "beta"]})
    assert resp.status_code == 401
    assert resp.json() == {"ok": False, "error": SCANNER_DENIED_ERROR}


# --- Success (multiple) ---------------------------------------------------

def test_bulk_success_multiple(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    _no_sleep(monkeypatch)
    make, _lb, _reports, _scan = scan_client
    client = make(_BulkStubEngine())

    resp = client.post(
        "/api/scanner/bulk",
        json={"usernames": ["alpha", "beta", "gamma"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["count"] == 3
    assert len(body["results"]) == 3

    for expected, item in zip(["alpha", "beta", "gamma"], body["results"]):
        assert item["username"] == expected
        assert item["ok"] is True
        assert item["data"]["agent_name"] == expected
        # x_username is set unconditionally in bulk (no scraped gate).
        assert item["data"]["x_username"] == expected
        assert "error" not in item


# --- Count limit ----------------------------------------------------------

def test_bulk_count_limit(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(_BulkStubEngine())
    eleven = [f"agent{i}" for i in range(11)]
    resp = client.post("/api/scanner/bulk", json={"usernames": eleven})
    assert resp.status_code == 422
    assert resp.json() == {
        "error": "Too many agents — maximum 10 per request, got 11"
    }


# --- Empty list -----------------------------------------------------------

def test_bulk_empty_list(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(_BulkStubEngine())
    resp = client.post("/api/scanner/bulk", json={"usernames": []})
    assert resp.status_code == 422
    assert resp.json() == {"error": "'usernames' must be a non-empty list"}


def test_bulk_all_falsy_filtered_to_empty(scan_client, monkeypatch) -> None:
    # Falsy entries are filtered before the empty check -> same 422 as [].
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(_BulkStubEngine())
    resp = client.post("/api/scanner/bulk", json={"usernames": ["", None]})
    assert resp.status_code == 422
    assert resp.json() == {"error": "'usernames' must be a non-empty list"}


# --- Per-item failure isolation ------------------------------------------

def test_bulk_per_item_failure(scan_client, monkeypatch) -> None:
    # One username raises, one returns ok:False, one succeeds. The batch must
    # continue and surface a per-item error for the two failures.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    _no_sleep(monkeypatch)
    make, _lb, _reports, _scan = scan_client
    client = make(_BulkStubEngine(fail_for=["beta"], raise_for=["gamma"]))

    resp = client.post(
        "/api/scanner/bulk",
        json={"usernames": ["alpha", "beta", "gamma"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 3
    by_user = {item["username"]: item for item in body["results"]}

    assert by_user["alpha"]["ok"] is True
    assert "data" in by_user["alpha"]

    assert by_user["beta"]["ok"] is False
    assert by_user["beta"]["error"] == "scan failed for beta"
    assert "data" not in by_user["beta"]

    assert by_user["gamma"]["ok"] is False
    assert by_user["gamma"]["error"] == "boom gamma"
    assert "data" not in by_user["gamma"]


# --- Side effects (per successful item) -----------------------------------

def test_bulk_writes_per_item(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    _no_sleep(monkeypatch)
    make, lb_store, reports_dir, _scan = scan_client
    # beta fails -> no leaderboard entry / report for it.
    client = make(_BulkStubEngine(fail_for=["beta"]))

    resp = client.post(
        "/api/scanner/bulk",
        json={"usernames": ["alpha", "beta", "gamma"]},
    )
    assert resp.status_code == 200

    # Reports written only for the two successful items.
    assert (reports_dir / "alpha.json").exists()
    assert (reports_dir / "gamma.json").exists()
    assert not (reports_dir / "beta.json").exists()
    assert json.loads((reports_dir / "alpha.json").read_text())["agent_name"] == "alpha"

    # Leaderboard upserted for the two successful items only.
    board = lb_store.load()
    ids = {a["id"] for a in board["agents"]}
    assert ids == {"alpha", "gamma"}


# --- Contract / error paths ----------------------------------------------

def test_bulk_not_json(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(_BulkStubEngine())
    resp = client.post(
        "/api/scanner/bulk", content="x", headers={"Content-Type": "text/plain"}
    )
    assert resp.status_code == 415
    assert resp.json() == {"error": "Content-Type must be application/json"}


def test_bulk_engine_unavailable(scan_client, monkeypatch) -> None:
    # Non-empty, within-limit list but engine None -> 503 (engine check runs
    # after the empty/limit checks).
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(None)
    resp = client.post("/api/scanner/bulk", json={"usernames": ["alpha"]})
    assert resp.status_code == 503
    assert resp.json() == {"error": "scanner module not available"}
