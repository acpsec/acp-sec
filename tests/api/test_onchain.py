"""Parity + contract tests for POST /api/onchain/check (Task 2.6).

SECURITY-SENSITIVE: same auth gate as /api/scanner/* (SSRF/RPC abuse). The
on-chain checker is mocked in EVERY test — there are NO live Base RPC calls in
this suite.

Contract (ported verbatim from dashboard/serve.py):
    gate denied          -> 401 {"ok": False, "error": <denial>}
    not JSON             -> 415 {"error": "Content-Type must be application/json"}
    empty wallet         -> 422 {"ok": False, "error": "'wallet' is required"}
    checker unavailable  -> 503 {"ok": False, "error": "acpsec.onchain not available"}
    success              -> 200 {"ok": True, "data": <ACPCheckResult>}

Note vs /api/scanner/lookup: the 422 and 503 bodies here carry ``ok: False``,
and the 503 message is "acpsec.onchain not available".
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from acpsec_api.deps import get_onchain_checker
from acpsec_api.main import app as fastapi_app
from acpsec_api.scanner_auth import SCANNER_DENIED_ERROR


def _result(registered, *, error=None, log_count=0):
    """A canned ACPCheckResult, shaped like acpsec.onchain.check_acp_registration."""
    return {
        "contract": "0xACPCORE",
        "wallet": "0x1111111111111111111111111111111111111111",
        "rpc_url": "https://mainnet.base.org",
        "registered": registered,
        "log_count": log_count,
        "block_from": 100 if registered is not None else None,
        "block_to": 200 if registered is not None else None,
        "error": error,
    }


def _mock_checker(result, *, spy=None):
    """Build a checker matching check_acp_registration(wallet, *, rpc_url=None).

    If ``spy`` (a dict) is given, records the call args so tests can assert
    the wallet + rpc_url flow through unchanged.
    """
    def _check(wallet, *, rpc_url=None):
        if spy is not None:
            spy["wallet"] = wallet
            spy["rpc_url"] = rpc_url
        return result
    return _check


@pytest.fixture
def onchain_client():
    """Factory yielding a TestClient with the on-chain checker overridden.

    Usage: ``client = onchain_client(mock_fn)`` where ``mock_fn`` is a callable
    ``(wallet, *, rpc_url=None) -> dict`` (or ``None`` to exercise the 503 path).
    Keeps ALL Base RPC calls out of the suite — no live network.
    """
    _sentinel = object()

    def _make(checker=_sentinel):
        if checker is not _sentinel:
            fastapi_app.dependency_overrides[get_onchain_checker] = lambda: checker
        return TestClient(fastapi_app)

    try:
        yield _make
    finally:
        fastapi_app.dependency_overrides.pop(get_onchain_checker, None)


# --- Auth gate ------------------------------------------------------------

def test_onchain_denied_no_auth(onchain_client, monkeypatch) -> None:
    # Token required, no header, no origin → gate rejects before the checker.
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    client = onchain_client()  # checker never reached
    resp = client.post("/api/onchain/check", json={"wallet": "0xabc"})
    assert resp.status_code == 401
    assert resp.json() == {"ok": False, "error": SCANNER_DENIED_ERROR}


def test_onchain_allowed_with_token(onchain_client, monkeypatch) -> None:
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    client = onchain_client(_mock_checker(_result(False)))
    resp = client.post(
        "/api/onchain/check",
        json={"wallet": "0x1111111111111111111111111111111111111111"},
        headers={"X-Scanner-Token": "sekret"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": _result(False)}


# --- Request validation ---------------------------------------------------

def test_onchain_missing_wallet(onchain_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = onchain_client(_mock_checker(_result(False)))
    resp = client.post("/api/onchain/check", json={})
    assert resp.status_code == 422
    assert resp.json() == {"ok": False, "error": "'wallet' is required"}


def test_onchain_blank_wallet(onchain_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = onchain_client(_mock_checker(_result(False)))
    resp = client.post("/api/onchain/check", json={"wallet": "   "})
    assert resp.status_code == 422
    assert resp.json() == {"ok": False, "error": "'wallet' is required"}


def test_onchain_not_json(onchain_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = onchain_client(_mock_checker(_result(False)))
    resp = client.post(
        "/api/onchain/check", content="nope", headers={"Content-Type": "text/plain"}
    )
    assert resp.status_code == 415
    assert resp.json() == {"error": "Content-Type must be application/json"}


def test_onchain_invalid_wallet_passthrough(onchain_client, monkeypatch) -> None:
    # The handler does NO format check — a non-hex wallet is passed straight to
    # the checker, which returns registered=None + an error. Still HTTP 200.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    bad = _result(None, error="invalid wallet address (expected 0x… 40-hex)")
    client = onchain_client(_mock_checker(bad))
    resp = client.post("/api/onchain/check", json={"wallet": "notahexwallet"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": bad}


# --- Checker outcomes -----------------------------------------------------

def test_onchain_registered_true(onchain_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    spy: dict = {}
    result = _result(True, log_count=3)
    client = onchain_client(_mock_checker(result, spy=spy))
    resp = client.post(
        "/api/onchain/check",
        json={"wallet": "0x2222222222222222222222222222222222222222"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": result}
    assert resp.json()["data"]["registered"] is True
    # Wallet flows through unchanged; rpc_url defaults to None (no BASE_RPC_URL).
    assert spy["wallet"] == "0x2222222222222222222222222222222222222222"
    assert spy["rpc_url"] is None


def test_onchain_registered_false(onchain_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    result = _result(False)
    client = onchain_client(_mock_checker(result))
    resp = client.post(
        "/api/onchain/check",
        json={"wallet": "0x3333333333333333333333333333333333333333"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": result}
    assert resp.json()["data"]["registered"] is False


def test_onchain_registered_null(onchain_client, monkeypatch) -> None:
    # RPC failure → registered=None, inconclusive, but still HTTP 200.
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    result = _result(None, error="RuntimeError: RPC unreachable")
    client = onchain_client(_mock_checker(result))
    resp = client.post(
        "/api/onchain/check",
        json={"wallet": "0x4444444444444444444444444444444444444444"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": result}
    assert resp.json()["data"]["registered"] is None


def test_onchain_rpc_url_from_env(onchain_client, monkeypatch) -> None:
    # BASE_RPC_URL, when set, is forwarded to the checker (parity with Flask).
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    monkeypatch.setenv("BASE_RPC_URL", "https://custom.rpc.example")
    spy: dict = {}
    client = onchain_client(_mock_checker(_result(False), spy=spy))
    resp = client.post(
        "/api/onchain/check",
        json={"wallet": "0x5555555555555555555555555555555555555555"},
    )
    assert resp.status_code == 200
    assert spy["rpc_url"] == "https://custom.rpc.example"


# --- Availability ---------------------------------------------------------

def test_onchain_checker_unavailable(onchain_client, monkeypatch) -> None:
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = onchain_client(None)  # get_onchain_checker → None → 503
    resp = client.post(
        "/api/onchain/check",
        json={"wallet": "0x6666666666666666666666666666666666666666"},
    )
    assert resp.status_code == 503
    assert resp.json() == {"ok": False, "error": "acpsec.onchain not available"}
