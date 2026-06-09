"""Tests for acpsec/trust_score/data/basescan.py — TDD RED."""

import json
import pytest


# ---------------------------------------------------------------------------
# Helpers — stub fetcher that returns controlled API responses
# ---------------------------------------------------------------------------

def _make_source_response(
    source_code: str = "pragma solidity ^0.8.0;",
    abi: str = '[{"type":"function","name":"foo"}]',
    contract_name: str = "MyAgent",
    compiler_version: str = "v0.8.20+commit.a1b79de6",
) -> dict:
    return {
        "status": "1",
        "message": "OK",
        "result": [{
            "SourceCode": source_code,
            "ABI": abi,
            "ContractName": contract_name,
            "CompilerVersion": compiler_version,
        }],
    }


def _unverified_response() -> dict:
    return {
        "status": "1",
        "message": "OK",
        "result": [{
            "SourceCode": "",
            "ABI": "Contract source code not verified",
            "ContractName": "",
            "CompilerVersion": "",
        }],
    }


def _error_response(message: str = "NOTOK") -> dict:
    return {"status": "0", "message": message, "result": "Error!"}


def _fetcher_for(response: dict):
    """Returns a fetcher callable that always returns the given response dict."""
    def fetcher(url: str) -> dict:
        return response
    return fetcher


def _capturing_fetcher(response: dict) -> tuple:
    """Returns (fetcher, calls_list) — calls_list collects URLs fetched."""
    calls = []
    def fetcher(url: str) -> dict:
        calls.append(url)
        return response
    return fetcher, calls


# ---------------------------------------------------------------------------
# ContractData — data shape
# ---------------------------------------------------------------------------

class TestContractData:
    def test_has_expected_fields(self):
        from acpsec.trust_score.data.basescan import ContractData
        c = ContractData(
            address="0xABCD",
            source_verified=True,
            contract_name="MyAgent",
            abi=[],
            source_code="pragma solidity ^0.8.0;",
            compiler_version="v0.8.20",
        )
        assert c.address == "0xABCD"
        assert c.source_verified is True
        assert c.contract_name == "MyAgent"
        assert c.abi == []
        assert c.compiler_version == "v0.8.20"


# ---------------------------------------------------------------------------
# BasescanClient.get_contract — happy path
# ---------------------------------------------------------------------------

class TestGetContractVerified:
    def _client(self, response: dict):
        from acpsec.trust_score.data.basescan import BasescanClient
        return BasescanClient(api_key="TEST", chain_id=8453, _fetcher=_fetcher_for(response))

    def test_returns_contract_data(self):
        client = self._client(_make_source_response())
        result = client.get_contract("0x1234")
        from acpsec.trust_score.data.basescan import ContractData
        assert isinstance(result, ContractData)

    def test_verified_contract_has_source_verified_true(self):
        client = self._client(_make_source_response(source_code="pragma solidity ^0.8.0;"))
        result = client.get_contract("0x1234")
        assert result.source_verified is True

    def test_address_stored_on_result(self):
        client = self._client(_make_source_response())
        result = client.get_contract("0xABCD1234")
        assert result.address == "0xABCD1234"

    def test_contract_name_parsed(self):
        client = self._client(_make_source_response(contract_name="AgentCore"))
        result = client.get_contract("0x1234")
        assert result.contract_name == "AgentCore"

    def test_compiler_version_parsed(self):
        client = self._client(_make_source_response(compiler_version="v0.8.20+commit.abc"))
        result = client.get_contract("0x1234")
        assert result.compiler_version == "v0.8.20+commit.abc"

    def test_abi_parsed_from_json_string(self):
        abi_json = '[{"type":"function","name":"withdraw"}]'
        client = self._client(_make_source_response(abi=abi_json))
        result = client.get_contract("0x1234")
        assert isinstance(result.abi, list)
        assert result.abi[0]["name"] == "withdraw"

    def test_source_code_stored(self):
        client = self._client(_make_source_response(source_code="pragma solidity ^0.8.0;"))
        result = client.get_contract("0x1234")
        assert "solidity" in result.source_code


# ---------------------------------------------------------------------------
# BasescanClient.get_contract — unverified contract
# ---------------------------------------------------------------------------

class TestGetContractUnverified:
    def _client(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        return BasescanClient(api_key="TEST", chain_id=8453, _fetcher=_fetcher_for(_unverified_response()))

    def test_unverified_has_source_verified_false(self):
        assert self._client().get_contract("0x1234").source_verified is False

    def test_unverified_abi_is_empty_list(self):
        assert self._client().get_contract("0x1234").abi == []

    def test_unverified_source_code_is_empty_string(self):
        assert self._client().get_contract("0x1234").source_code == ""


# ---------------------------------------------------------------------------
# BasescanClient.get_contract — API errors
# ---------------------------------------------------------------------------

class TestGetContractErrors:
    def test_api_status_0_raises_basescan_error(self):
        from acpsec.trust_score.data.basescan import BasescanClient, BasescanError
        client = BasescanClient(api_key="TEST", chain_id=8453, _fetcher=_fetcher_for(_error_response()))
        with pytest.raises(BasescanError):
            client.get_contract("0x1234")

    def test_empty_result_list_raises_basescan_error(self):
        from acpsec.trust_score.data.basescan import BasescanClient, BasescanError
        client = BasescanClient(
            api_key="TEST",
            chain_id=8453,
            _fetcher=_fetcher_for({"status": "1", "message": "OK", "result": []}),
        )
        with pytest.raises(BasescanError):
            client.get_contract("0x1234")


# ---------------------------------------------------------------------------
# URL construction — API key and address are included
# ---------------------------------------------------------------------------

class TestURLConstruction:
    def test_api_key_included_in_request_url(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        fetcher, calls = _capturing_fetcher(_make_source_response())
        client = BasescanClient(api_key="MY_SECRET_KEY", chain_id=8453, _fetcher=fetcher)
        client.get_contract("0xDEAD")
        assert any("MY_SECRET_KEY" in url for url in calls)

    def test_address_included_in_request_url(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        fetcher, calls = _capturing_fetcher(_make_source_response())
        client = BasescanClient(api_key="KEY", chain_id=8453, _fetcher=fetcher)
        client.get_contract("0xDEADBEEF")
        assert any("0xDEADBEEF" in url for url in calls)

    def test_custom_base_url_used(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        fetcher, calls = _capturing_fetcher(_make_source_response())
        client = BasescanClient(
            api_key="KEY",
            chain_id=8453,
            base_url="https://api.example.io/api",
            _fetcher=fetcher,
        )
        client.get_contract("0x1234")
        assert any("example.io" in url for url in calls)


# ---------------------------------------------------------------------------
# Etherscan V2 unified endpoint — single endpoint + chainid param
# (V1 chain-specific endpoints were sunset 2025-08-15)
# ---------------------------------------------------------------------------

class TestEtherscanV2:
    def test_default_base_url_is_etherscan_v2(self):
        from acpsec.trust_score.data.basescan import DEFAULT_BASE_URL
        assert DEFAULT_BASE_URL == "https://api.etherscan.io/v2/api"

    def test_v2_url_used_for_base_mainnet(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        fetcher, calls = _capturing_fetcher(_make_source_response())
        BasescanClient(api_key="KEY", chain_id=8453, _fetcher=fetcher).get_contract("0x1")
        assert any("api.etherscan.io/v2/api" in url for url in calls)

    def test_v2_url_used_for_base_sepolia(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        fetcher, calls = _capturing_fetcher(_make_source_response())
        BasescanClient(api_key="KEY", chain_id=84532, _fetcher=fetcher).get_contract("0x1")
        assert any("api.etherscan.io/v2/api" in url for url in calls)

    def test_chainid_8453_in_query_for_base_mainnet(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        fetcher, calls = _capturing_fetcher(_make_source_response())
        BasescanClient(api_key="KEY", chain_id=8453, _fetcher=fetcher).get_contract("0x1")
        assert any("chainid=8453" in url for url in calls)

    def test_chainid_84532_in_query_for_base_sepolia(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        fetcher, calls = _capturing_fetcher(_make_source_response())
        BasescanClient(api_key="KEY", chain_id=84532, _fetcher=fetcher).get_contract("0x1")
        assert any("chainid=84532" in url for url in calls)

    def test_same_api_key_works_for_both_chains(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        fetcher_m, calls_m = _capturing_fetcher(_make_source_response())
        fetcher_s, calls_s = _capturing_fetcher(_make_source_response())
        BasescanClient(api_key="ONEKEY", chain_id=8453, _fetcher=fetcher_m).get_contract("0x1")
        BasescanClient(api_key="ONEKEY", chain_id=84532, _fetcher=fetcher_s).get_contract("0x1")
        assert any("ONEKEY" in url for url in calls_m)
        assert any("ONEKEY" in url for url in calls_s)

    def test_chain_id_is_required(self):
        from acpsec.trust_score.data.basescan import BasescanClient
        with pytest.raises(TypeError):
            BasescanClient(api_key="KEY")  # missing chain_id
