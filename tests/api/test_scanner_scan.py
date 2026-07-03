"""Parity + contract tests for POST /api/scanner/scan (Task 2.5b-i).

SECURITY-SENSITIVE + side effects. The heuristic engine is STUBBED in every
test — no live heuristic run, no external network. All write targets
(leaderboard, reports dir, scan-store) are temp-backed via the scan_client
fixture, so nothing touches the real dashboard files.

Contract (dashboard/serve.py):
    gate denied        -> 401 (reuses 2.5a gate)
    not JSON           -> 415 {"error": "Content-Type must be application/json"}
    missing url        -> 422 {"error": "'url' is required"}   (agent_name is NOT required)
    engine unavailable -> 503 {"error": "scanner module not available"}
    engine ok:False    -> 422 <engine result verbatim>
    success            -> 200 <engine result, data enriched>  + side-effect writes
"""

from __future__ import annotations

import copy
import json

from acpsec_api.scanner_auth import SCANNER_DENIED_ERROR
from tests.api.conftest import assert_parity


class _StubEngine:
    """Stand-in for dashboard/scanner — no network, canned results."""

    def __init__(self, result: dict, token_info: dict | None = None) -> None:
        self.result = result
        self.token_info = token_info or {"has_token": False}
        self.calls: list = []

    def analyze_agent(self, url, agent_name="", scan_mode="root"):
        self.calls.append((url, agent_name, scan_mode))
        return copy.deepcopy(self.result)  # handler mutates data; protect the fixture

    def extract_token_info(self, html="", x_bio=""):
        return copy.deepcopy(self.token_info)


def _ok_result() -> dict:
    return {
        "ok": True,
        "error": None,
        "data": {
            "agent_name": "Test Agent",
            "score_pct": 82,
            "controls": [
                {"ctrl": "AUTH-01", "severity": "CRITICAL", "status": "fail"},
                {"ctrl": "CTX-01", "severity": "HIGH", "status": "pass"},
            ],
            "token": {},
        },
    }


_VALID_BODY = {"url": "https://agent.example", "agent_name": "Test Agent"}


# --- Auth gate ------------------------------------------------------------

def test_scan_denied_no_auth(scan_client, monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    make, _lb, _reports, _scan = scan_client
    client = make(_StubEngine(_ok_result()))
    resp = client.post("/api/scanner/scan", json=_VALID_BODY)
    assert resp.status_code == 401
    assert resp.json() == {"ok": False, "error": SCANNER_DENIED_ERROR}


# --- Side effects ---------------------------------------------------------

def test_scan_success_writes_report(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, reports_dir, _scan = scan_client
    client = make(_StubEngine(_ok_result()))

    resp = client.post("/api/scanner/scan", json=_VALID_BODY)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    # Report written to injected temp dir at leaderboard_key("Test Agent").
    report_file = reports_dir / "test_agent.json"
    assert report_file.exists()
    saved = json.loads(report_file.read_text())
    assert saved["agent_name"] == "Test Agent"


def test_scan_success_upserts_leaderboard(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, lb_store, _reports, _scan = scan_client
    client = make(_StubEngine(_ok_result()))

    resp = client.post("/api/scanner/scan", json=_VALID_BODY)
    assert resp.status_code == 200

    board = lb_store.load()
    agent = next(a for a in board["agents"] if a["id"] == "test_agent")
    assert agent["name"] == "Test Agent"
    assert agent["score"] == 82
    assert agent["tier"] == "SECURE"  # 70-89 in the 6-band scheme
    assert agent["critical_fails"] == 1  # one CRITICAL fail in controls
    assert agent["previous_score"] == 82  # first sighting → no movement


def test_scan_writes_scan_store(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, scan_store_path = scan_client
    client = make(_StubEngine(_ok_result()))

    client.post("/api/scanner/scan", json=_VALID_BODY)
    assert scan_store_path.exists()
    assert json.loads(scan_store_path.read_text())["agent_name"] == "Test Agent"


# --- Contract / error paths ----------------------------------------------

def test_scan_engine_failure_returns_422(scan_client, monkeypatch) -> None:
    # No explicit SSRF scheme gate in Flask: an unreachable/invalid URL makes the
    # engine return ok:False, and the handler returns that verbatim at 422.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, lb_store, reports_dir, scan_store_path = scan_client
    fail = {"ok": False, "error": "Could not fetch website: boom", "suggestion": None}
    client = make(_StubEngine(fail))

    resp = client.post("/api/scanner/scan", json={"url": "ftp://nope"})
    assert resp.status_code == 422
    assert resp.json() == fail
    # No side-effect writes on the failure path.
    assert not scan_store_path.exists()
    assert not (reports_dir / "test_agent.json").exists()
    assert lb_store.load()["agents"] == []


def test_scan_missing_url(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(_StubEngine(_ok_result()))
    resp = client.post("/api/scanner/scan", json={"agent_name": "No URL"})
    assert resp.status_code == 422
    assert resp.json() == {"error": "'url' is required"}


def test_scan_not_json(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(_StubEngine(_ok_result()))
    resp = client.post(
        "/api/scanner/scan", content="x", headers={"Content-Type": "text/plain"}
    )
    assert resp.status_code == 415
    assert resp.json() == {"error": "Content-Type must be application/json"}


def test_scan_engine_unavailable(scan_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(None)  # engine None → 503
    resp = client.post("/api/scanner/scan", json=_VALID_BODY)
    assert resp.status_code == 503
    assert resp.json() == {"error": "scanner module not available"}


def test_scan_enriches_data_fields(scan_client, monkeypatch) -> None:
    # scraped=True → x_username set + x_handle_verified True.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    make, _lb, _reports, _scan = scan_client
    client = make(_StubEngine(_ok_result()))
    resp = client.post(
        "/api/scanner/scan",
        json={"url": "https://a.example", "agent_name": "Test Agent",
              "username": "agentx", "scraped": True},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["x_username"] == "agentx"
    assert data["x_handle_verified"] is True


# --- Parity (denial path only) -------------------------------------------

def test_scan_parity_denial(fastapi_client, flask_client, monkeypatch) -> None:
    # Gate rejects before the engine runs → no network, no writes. Safe to parity.
    # Success-path parity would trigger the real heuristic engine, so it is only
    # asserted FastAPI-only via the stubbed engine above.
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    assert_parity(
        fastapi_client, flask_client, "/api/scanner/scan", "POST",
        json=_VALID_BODY,
    )
