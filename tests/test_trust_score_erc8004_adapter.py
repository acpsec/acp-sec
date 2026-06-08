"""Tests for acpsec/trust_score/data/erc8004_adapter.py — TDD (RED → GREEN)."""

import pytest

from acpsec.trust_score.dimensions.identity import IdentityInput


# ---------------------------------------------------------------------------
# Injectable helpers
# ---------------------------------------------------------------------------

def _rpc_registered(tx_count: int = 50, block_number: int = 5000, contract_age_blocks: int = 2000):
    """RPC where registry exists and agent address IS registered (returns >0)."""
    def rpc(method: str, params: list):
        if method == "eth_getCode":
            return "0x6060604052"  # registry has code
        if method == "eth_call":
            # balanceOf-like: return non-zero → registered
            return "0x" + "0" * 63 + "1"
        if method == "eth_getTransactionCount":
            return hex(tx_count)
        if method == "eth_blockNumber":
            return hex(block_number)
        return "0x0"
    return rpc


def _rpc_not_registered(tx_count: int = 50, block_number: int = 5000):
    """RPC where registry exists but agent address is NOT registered (returns 0)."""
    def rpc(method: str, params: list):
        if method == "eth_getCode":
            return "0x6060604052"  # registry has code
        if method == "eth_call":
            return "0x" + "0" * 64  # zero → not registered
        if method == "eth_getTransactionCount":
            return hex(tx_count)
        if method == "eth_blockNumber":
            return hex(block_number)
        return "0x0"
    return rpc


def _rpc_no_registry():
    """RPC where registry address has no code deployed."""
    def rpc(method: str, params: list):
        if method == "eth_getCode":
            return "0x"  # no code
        if method == "eth_call":
            return "0x" + "0" * 64
        if method == "eth_getTransactionCount":
            return hex(50)
        if method == "eth_blockNumber":
            return hex(5000)
        return "0x0"
    return rpc


def _rpc_fresh_wallet(tx_count: int = 3, block_number: int = 1000, contract_deploy_block: int = 100):
    """RPC where agent address has few txns and the 'contract' is very recent."""
    def rpc(method: str, params: list):
        if method == "eth_getCode":
            return "0x6060604052"
        if method == "eth_call":
            return "0x" + "0" * 63 + "1"  # registered
        if method == "eth_getTransactionCount":
            # "earliest" → deploy block simulation via tx_count
            return hex(tx_count)
        if method == "eth_blockNumber":
            return hex(block_number)
        return "0x0"
    return rpc


def _rpc_failing():
    """Always raises."""
    def rpc(method: str, params: list):
        raise RuntimeError("RPC unavailable")
    return rpc


def _fetch_url_ok(owner: str = "0xABCD", has_handle: bool = True, endpoint: str = "https://agent.example.com"):
    """Returns an injectable HTTP fetcher that returns a valid agent card."""
    card = {"owner": owner, "endpoint": endpoint}
    if has_handle:
        card["handle"] = "my-agent"
    def fetch(url: str) -> dict:
        return card
    return fetch


def _fetch_url_missing_handle(owner: str = "0xABCD", endpoint: str = "https://agent.example.com"):
    return _fetch_url_ok(owner=owner, has_handle=False, endpoint=endpoint)


def _fetch_url_http_endpoint(owner: str = "0xABCD"):
    return _fetch_url_ok(owner=owner, has_handle=True, endpoint="http://agent.example.com")


def _fetch_url_failing():
    def fetch(url: str) -> dict:
        raise RuntimeError("HTTP fetch failed")
    return fetch


def _adapter(rpc=None, fetch_url=None):
    from acpsec.trust_score.data.erc8004_adapter import ERC8004Adapter
    return ERC8004Adapter(
        _rpc=rpc or _rpc_registered(),
        _fetch_url=fetch_url,
    )


AGENT_ADDR = "0xABCD"
CARD_URL = "https://agent.example.com/.well-known/agent.json"


# ---------------------------------------------------------------------------
# 1. Basic return type
# ---------------------------------------------------------------------------

class TestReturnType:
    def test_returns_identity_input(self):
        result = _adapter().fetch(AGENT_ADDR)
        assert isinstance(result, IdentityInput)


# ---------------------------------------------------------------------------
# 2-3. ERC-8004 registration detection
# ---------------------------------------------------------------------------

class TestERC8004Registration:
    def test_not_registered_sets_no_erc8004_true(self):
        result = _adapter(rpc=_rpc_not_registered()).fetch(AGENT_ADDR)
        assert result.no_erc8004 is True

    def test_registered_sets_no_erc8004_false(self):
        result = _adapter(rpc=_rpc_registered()).fetch(AGENT_ADDR)
        assert result.no_erc8004 is False

    def test_no_registry_deployed_sets_no_erc8004_true(self):
        result = _adapter(rpc=_rpc_no_registry()).fetch(AGENT_ADDR)
        assert result.no_erc8004 is True


# ---------------------------------------------------------------------------
# 4-5. Sybil signals
# ---------------------------------------------------------------------------

class TestSybilSignals:
    def test_fresh_wallet_few_txns_recent_contract_sybil_true(self):
        # < 10 txns and block_number - some measure < 1000 blocks → sybil
        result = _adapter(rpc=_rpc_fresh_wallet(tx_count=3, block_number=500)).fetch(AGENT_ADDR)
        assert result.sybil_signals is True

    def test_established_wallet_many_txns_sybil_false(self):
        result = _adapter(rpc=_rpc_registered(tx_count=100, block_number=10000)).fetch(AGENT_ADDR)
        assert result.sybil_signals is False


# ---------------------------------------------------------------------------
# 6-7. Agent card owner matching
# ---------------------------------------------------------------------------

class TestOwnerMatching:
    def test_matching_owner_owner_mismatch_false(self):
        result = _adapter(
            fetch_url=_fetch_url_ok(owner=AGENT_ADDR)
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert result.owner_mismatch is False

    def test_mismatching_owner_owner_mismatch_true(self):
        result = _adapter(
            fetch_url=_fetch_url_ok(owner="0xDEAD")
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert result.owner_mismatch is True

    def test_owner_match_is_case_insensitive(self):
        result = _adapter(
            fetch_url=_fetch_url_ok(owner=AGENT_ADDR.lower())
        ).fetch(AGENT_ADDR.upper(), agent_card_url=CARD_URL)
        assert result.owner_mismatch is False


# ---------------------------------------------------------------------------
# 8-9. Handle verification
# ---------------------------------------------------------------------------

class TestHandleVerification:
    def test_missing_handle_sets_handle_unverified_true(self):
        result = _adapter(
            fetch_url=_fetch_url_missing_handle(owner=AGENT_ADDR)
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert result.handle_unverified is True

    def test_present_handle_sets_handle_unverified_false(self):
        result = _adapter(
            fetch_url=_fetch_url_ok(owner=AGENT_ADDR)
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert result.handle_unverified is False


# ---------------------------------------------------------------------------
# 10-11. TLS endpoint check
# ---------------------------------------------------------------------------

class TestEndpointTLS:
    def test_http_endpoint_sets_tls_mismatch_true(self):
        result = _adapter(
            fetch_url=_fetch_url_http_endpoint(owner=AGENT_ADDR)
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert result.endpoint_tls_mismatch is True

    def test_https_endpoint_sets_tls_mismatch_false(self):
        result = _adapter(
            fetch_url=_fetch_url_ok(owner=AGENT_ADDR, endpoint="https://agent.example.com")
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert result.endpoint_tls_mismatch is False


# ---------------------------------------------------------------------------
# 12. No agent card URL
# ---------------------------------------------------------------------------

class TestNoAgentCardUrl:
    def test_no_card_url_handle_unverified_true(self):
        result = _adapter().fetch(AGENT_ADDR, agent_card_url=None)
        assert result.handle_unverified is True

    def test_no_card_url_owner_mismatch_false(self):
        result = _adapter().fetch(AGENT_ADDR, agent_card_url=None)
        assert result.owner_mismatch is False


# ---------------------------------------------------------------------------
# 13-14. Failure resilience
# ---------------------------------------------------------------------------

class TestFailureResilience:
    def test_rpc_failure_returns_identity_input_without_raising(self):
        result = _adapter(rpc=_rpc_failing()).fetch(AGENT_ADDR)
        assert isinstance(result, IdentityInput)

    def test_rpc_failure_conservative_no_erc8004_true(self):
        result = _adapter(rpc=_rpc_failing()).fetch(AGENT_ADDR)
        assert result.no_erc8004 is True

    def test_rpc_failure_sybil_false(self):
        result = _adapter(rpc=_rpc_failing()).fetch(AGENT_ADDR)
        assert result.sybil_signals is False

    def test_http_fetch_failure_returns_identity_input_without_raising(self):
        result = _adapter(
            fetch_url=_fetch_url_failing()
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert isinstance(result, IdentityInput)

    def test_http_fetch_failure_handle_unverified_true(self):
        result = _adapter(
            fetch_url=_fetch_url_failing()
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert result.handle_unverified is True

    def test_http_fetch_failure_owner_mismatch_false(self):
        result = _adapter(
            fetch_url=_fetch_url_failing()
        ).fetch(AGENT_ADDR, agent_card_url=CARD_URL)
        assert result.owner_mismatch is False
