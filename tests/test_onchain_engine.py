"""Engine-level tests for acpsec.onchain.check_acp_registration.

The JSON-RPC transport (``_rpc``) is monkeypatched in every test that gets
past wallet validation — NO live Base RPC calls.

Pinned here: the result echoes only the RPC endpoint's origin. Provider URLs
commonly carry an API key in the path/query/userinfo, and this dict is returned
verbatim by POST /api/onchain/check, so the key must never ride along — not in
``rpc_url`` and not inside an ``error`` string that quotes the URL.
"""

from __future__ import annotations

from acpsec import onchain

_KEYED_URL = "https://user:pw-SECRET@base-mainnet.example.com/v2/KEY-SECRET?apikey=Q-SECRET"
_WALLET = "0x1111111111111111111111111111111111111111"


def test_rpc_url_reports_origin_only() -> None:
    # Malformed wallet → early return, before any network call.
    out = onchain.check_acp_registration("not-a-wallet", rpc_url=_KEYED_URL)
    assert out["rpc_url"] == "https://base-mainnet.example.com"
    assert "SECRET" not in repr(out)


def test_rpc_url_keeps_non_default_port() -> None:
    out = onchain.check_acp_registration("not-a-wallet", rpc_url="http://127.0.0.1:8545/k")
    assert out["rpc_url"] == "http://127.0.0.1:8545"


def test_default_rpc_url_unchanged() -> None:
    out = onchain.check_acp_registration("not-a-wallet")
    assert out["rpc_url"] == onchain.DEFAULT_BASE_RPC_URL


def test_error_string_never_quotes_the_keyed_url(monkeypatch) -> None:
    # urllib quotes the URL in some errors (e.g. ValueError "unknown url type").
    def _boom(url, method, params, timeout=8.0):
        raise ValueError(f"unknown url type: {url!r}")

    monkeypatch.setattr(onchain, "_rpc", _boom)
    out = onchain.check_acp_registration(_WALLET, rpc_url=_KEYED_URL)
    assert out["registered"] is None
    assert out["error"].startswith("ValueError: unknown url type:")
    assert "SECRET" not in repr(out)


def test_rpc_still_called_with_the_full_url(monkeypatch) -> None:
    # Redaction is display-only: the transport must get the real endpoint.
    seen = []

    def _rpc(url, method, params, timeout=8.0):
        seen.append(url)
        return "0x10" if method == "eth_blockNumber" else []

    monkeypatch.setattr(onchain, "_rpc", _rpc)
    out = onchain.check_acp_registration(_WALLET, rpc_url=_KEYED_URL)
    assert out["registered"] is False
    assert seen and all(u == _KEYED_URL for u in seen)
