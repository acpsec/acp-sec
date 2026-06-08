"""Tests for acpsec/trust_score/chains.py — TDD."""

import pytest

from acpsec.trust_score.chains import (
    CHAINS,
    DEFAULT_CHAIN_ID,
    ChainConfig,
    ReferenceContracts,
    UnknownChainError,
    get_chain,
    reference_contracts,
)

ACP_CORE = "0x238E541BfefD82238730D00a2208E5497F1832E0"
FUND_HOOK = "0x90717828D78731313CB350D6a58b0f91668Ea702"


# ---------------------------------------------------------------------------
# Registry contents
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_base_mainnet_present(self):
        assert 8453 in CHAINS

    def test_base_sepolia_present(self):
        assert 84532 in CHAINS

    def test_default_chain_is_base_mainnet(self):
        assert DEFAULT_CHAIN_ID == 8453

    def test_base_mainnet_name(self):
        assert get_chain(8453).name == "Base Mainnet"

    def test_base_sepolia_name(self):
        assert get_chain(84532).name == "Base Sepolia"

    def test_only_base_chains_supported(self):
        assert set(CHAINS) == {8453, 84532}


# ---------------------------------------------------------------------------
# get_chain() — resolution by id or name alias
# ---------------------------------------------------------------------------

class TestGetChain:
    def test_get_by_int_id(self):
        assert get_chain(8453).chain_id == 8453

    def test_get_by_name_alias(self):
        assert get_chain("base").chain_id == 8453

    def test_get_by_name_alias_case_insensitive(self):
        assert get_chain("Base-Sepolia").chain_id == 84532

    def test_returns_chain_config(self):
        assert isinstance(get_chain(8453), ChainConfig)

    def test_unknown_name_raises(self):
        with pytest.raises(UnknownChainError):
            get_chain("ethereum")

    def test_bsc_no_longer_supported(self):
        with pytest.raises(UnknownChainError):
            get_chain(97)

    def test_unsupported_id_raises(self):
        with pytest.raises(UnknownChainError):
            get_chain(1)


# ---------------------------------------------------------------------------
# Conformance reference contracts
# ---------------------------------------------------------------------------

class TestReferenceContracts:
    def test_base_mainnet_acp_core(self):
        assert reference_contracts(8453).acp_core == ACP_CORE

    def test_base_mainnet_fund_transfer_hook(self):
        assert reference_contracts(8453).fund_transfer_hook == FUND_HOOK

    def test_testnet_references_default_none(self):
        refs = reference_contracts(84532)
        assert refs.acp_core is None
        assert refs.fund_transfer_hook is None

    def test_reference_contracts_by_name(self):
        assert reference_contracts("base").acp_core == ACP_CORE

    def test_returns_reference_contracts(self):
        assert isinstance(reference_contracts(8453), ReferenceContracts)


# ---------------------------------------------------------------------------
# ChainConfig shape
# ---------------------------------------------------------------------------

class TestChainConfigShape:
    def test_has_nonempty_rpc_url(self):
        assert get_chain(8453).rpc_url

    def test_base_mainnet_rpc_matches_existing(self):
        assert get_chain(8453).rpc_url == "https://mainnet.base.org"
