"""B20 router — LIVE-RPC integration smoke (Task 7.3-1).

Unlike ``tests/api/test_b20.py`` (fully mocked via ``dependency_overrides``),
these tests exercise the REAL path: no overrides, so the endpoint constructs a
real ``RpcClient`` and reads a real deployed token over the public Base RPC
(``sepolia.base.org`` / ``mainnet.base.org`` — hardcoded per chain in
``acpsec_api/b20/constants.py``; there is no RPC-URL env var to set).

**Opt-in only.** Marked ``network`` and gated on the ``B20_LIVE_RPC`` env flag:

    B20_LIVE_RPC=1 .venv/bin/pytest tests/ -m network

Without the flag they SKIP (never fail); the default ``pytest tests/`` suite is
unaffected. Assertions check *shape + ground-truth fields*, never the exact
``trust_score`` (the engine may evolve).

Real-world fixture pair (validated against live chains):
- Positive: ``0xb20000000000000000000037670bd90fedb52901`` on Base Sepolia
  (84532) — a real B20 token "fixb20"/"FIXB20", supplyCap 1e27 (capped).
- Negative: ``0xb200faf3827258193fb18c24b43aa138c3dcc08c`` on Base mainnet
  (8453) — a ClankerToken with a vanity CREATE2 prefix mimicking B20; not B20.
"""

import os

import pytest
from fastapi.testclient import TestClient

from acpsec_api.main import app as fastapi_app

# Opt-in flag. The engine's RPC URL is a public constant (no URL env var), so
# this is purely an execution gate, not a URL source.
_LIVE_ENV = "B20_LIVE_RPC"

pytestmark = [
    pytest.mark.network,
    pytest.mark.skipif(
        not os.getenv(_LIVE_ENV),
        reason=f"live-RPC test; set {_LIVE_ENV}=1 to run (hits public Base RPC).",
    ),
]

FIXB20_SEPOLIA = "0xb20000000000000000000037670bd90fedb52901"
CLANKER_MAINNET = "0xb200faf3827258193fb18c24b43aa138c3dcc08c"

_DIMENSIONS = {
    "issuer_authority",
    "supply_integrity",
    "transfer_policy",
    "variant_config",
    "origin_transparency",
}


def _post(address: str, chain_id: int):
    # No dependency_overrides → real read_token + real RpcClient + real network.
    return TestClient(fastapi_app).post(
        "/api/b20/scan", json={"address": address, "chain_id": chain_id}
    )


def test_live_fixb20_sepolia_returns_full_rated_payload():
    r = _post(FIXB20_SEPOLIA, 84532)
    assert r.status_code == 200, r.text
    body = r.json()

    # Identity echoes + ground-truth metadata. NB: the B20 reader does NOT
    # surface ERC-20 name/symbol (both come back null on-chain for this token —
    # verified live), so we assert the fields the engine actually populates.
    assert body["token"].lower() == FIXB20_SEPOLIA.lower()
    assert body["chain_id"] == 84532
    assert body["variant"] == "ASSET"
    assert body["decimals"] == 18

    # A real, rated scan across all five engine dimensions.
    assert body["rated"] is True
    assert set(body["dimensions"].keys()) == _DIMENSIONS
    assert body["grade"] in {"A", "B", "C", "D", "F"}

    # On-chain ground truth: capped supply of 1e27 (compare by value, not format).
    supply_cap = body["issuer_powers"]["supply_cap"]
    assert supply_cap is not None
    assert int(supply_cap) == 10**27


def test_live_clanker_vanity_mainnet_is_not_b20():
    r = _post(CLANKER_MAINNET, 8453)
    assert r.status_code == 400, r.text
    body = r.json()
    assert set(body.keys()) == {"error", "detail"}
    assert body["error"] == "not_b20"
