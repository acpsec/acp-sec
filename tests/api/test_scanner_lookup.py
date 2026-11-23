"""Parity + contract tests for POST /api/scanner/lookup (Task 2.5a).

SECURITY-SENSITIVE: the auth gate and the external Nitter fetch. Every test
mocks the scraper — there are NO live network calls in this suite.

Auth truth table (SCANNER_TOKEN set): allow iff valid X-Scanner-Token; else
401. Origin/Host are ignored (the Flask same-origin shortcut was a bypass).
SCANNER_TOKEN unset or blank → open.

Contract:
    gate denied           -> 401 {"ok": False, "error": <denial>}
    not JSON              -> 415 {"error": "Content-Type must be application/json"}
    empty username        -> 422 {"error": "'username' is required"}
    scraper unavailable   -> 503 {"error": "scanner module not available"}
    success               -> 200 {"ok": True, "data": <profile>}
"""

from __future__ import annotations

from acpsec_api.scanner_auth import SCANNER_DENIED_ERROR
from acpsec_api.scanner_lookup import NITTER_INSTANCES

_MOCK_PROFILE = {
    "username": "agentx",
    "display_name": "Agent X",
    "bio": "Autonomous trading agent",
    "website": "https://agentx.example",
    "avatar_url": "https://img.example/x.png",
    "source": "nitter",
    "nitter_url": "https://nitter.poast.org/agentx",
    "error": None,
    "fetch_status": "ok",
    "nitter_instance": "https://nitter.poast.org",
    "instance_errors": [],
}

_MOCK_FAILURE = {
    "username": "agentx",
    "display_name": "",
    "bio": "",
    "website": "",
    "avatar_url": "",
    "source": "failed",
    "error": (
        "Could not reach any Nitter instance — X is blocking scrapers. "
        "Please fill in the agent name and website URL manually."
    ),
    "fetch_status": "all_failed",
    "nitter_instance": None,
    "instance_errors": [
        {"instance": i, "error": "ConnectionError: timed out"}
        for i in NITTER_INSTANCES
    ],
}


def _mock_scraper(profile: dict):
    def _scrape(username: str) -> dict:  # noqa: ARG001 — canned, no network
        return profile
    return _scrape


# --- Auth gate ------------------------------------------------------------

def test_lookup_denied_no_token_no_origin(scanner_client, monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    client = scanner_client()  # scraper never reached — gate rejects first
    resp = client.post("/api/scanner/lookup", json={"username": "agentx"})
    assert resp.status_code == 401
    assert resp.json() == {"ok": False, "error": SCANNER_DENIED_ERROR}


def test_lookup_denied_wrong_token(scanner_client, monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    client = scanner_client()
    resp = client.post(
        "/api/scanner/lookup",
        json={"username": "agentx"},
        headers={"X-Scanner-Token": "wrong"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"ok": False, "error": SCANNER_DENIED_ERROR}


def test_lookup_allowed_with_token(scanner_client, monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    client = scanner_client(_mock_scraper(_MOCK_PROFILE))
    resp = client.post(
        "/api/scanner/lookup",
        json={"username": "agentx"},
        headers={"X-Scanner-Token": "sekret"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": _MOCK_PROFILE}


def test_lookup_denied_spoofed_same_origin(scanner_client, monkeypatch) -> None:
    # Regression: Origin host == Host header used to skip the token. Any
    # non-browser client can forge Origin, so it must NOT grant access.
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    client = scanner_client()  # scraper never reached — gate rejects first
    # Starlette TestClient's default Host is "testserver".
    resp = client.post(
        "/api/scanner/lookup",
        json={"username": "agentx"},
        headers={"Origin": "http://testserver"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"ok": False, "error": SCANNER_DENIED_ERROR}


def test_lookup_open_when_token_blank(scanner_client, monkeypatch) -> None:
    # A whitespace-only token counts as unset (open) — and /api/health reports
    # scanner_protected=False for it (see test_health), so the two agree.
    monkeypatch.setenv("SCANNER_TOKEN", "   ")
    client = scanner_client(_mock_scraper(_MOCK_PROFILE))
    resp = client.post("/api/scanner/lookup", json={"username": "agentx"})
    assert resp.status_code == 200


def test_lookup_non_ascii_token_denied_not_crash(scanner_client, monkeypatch) -> None:
    # compare_digest rejects non-ASCII str; the gate compares the raw header
    # bytes with the token's UTF-8 bytes, so a mismatch is a clean 401 (no 500)
    # and a UTF-8 client sending the right token passes.
    monkeypatch.setenv("SCANNER_TOKEN", "sëkret")
    client = scanner_client(_mock_scraper(_MOCK_PROFILE))
    wrong = client.post(
        "/api/scanner/lookup",
        json={"username": "agentx"},
        headers={"X-Scanner-Token": "sekret"},
    )
    assert wrong.status_code == 401
    right = client.post(
        "/api/scanner/lookup",
        json={"username": "agentx"},
        headers={"X-Scanner-Token": "sëkret".encode("utf-8")},
    )
    assert right.status_code == 200


def test_lookup_open_when_token_unset(scanner_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = scanner_client(_mock_scraper(_MOCK_PROFILE))
    resp = client.post("/api/scanner/lookup", json={"username": "agentx"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": _MOCK_PROFILE}


# --- Lookup contract ------------------------------------------------------

def test_lookup_success_shape(scanner_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = scanner_client(_mock_scraper(_MOCK_PROFILE))
    resp = client.post("/api/scanner/lookup", json={"username": "@agentx"})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert set(data) >= {"username", "display_name", "bio", "website", "avatar_url", "source"}
    assert data == _MOCK_PROFILE


def test_lookup_upstream_failure(scanner_client, monkeypatch) -> None:
    # A scrape failure is still HTTP 200 — the failure lives in data.source.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = scanner_client(_mock_scraper(_MOCK_FAILURE))
    resp = client.post("/api/scanner/lookup", json={"username": "agentx"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": _MOCK_FAILURE}
    assert resp.json()["data"]["source"] == "failed"


def test_lookup_missing_username(scanner_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = scanner_client(_mock_scraper(_MOCK_PROFILE))
    resp = client.post("/api/scanner/lookup", json={"username": "   "})
    assert resp.status_code == 422
    assert resp.json() == {"error": "'username' is required"}


def test_lookup_not_json(scanner_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = scanner_client(_mock_scraper(_MOCK_PROFILE))
    resp = client.post(
        "/api/scanner/lookup", content="nope", headers={"Content-Type": "text/plain"}
    )
    assert resp.status_code == 415
    assert resp.json() == {"error": "Content-Type must be application/json"}


def test_lookup_scanner_unavailable(scanner_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = scanner_client(None)  # scraper unavailable → 503
    resp = client.post("/api/scanner/lookup", json={"username": "agentx"})
    assert resp.status_code == 503
    assert resp.json() == {"error": "scanner module not available"}
