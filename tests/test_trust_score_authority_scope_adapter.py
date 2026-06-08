"""Tests for acpsec/trust_score/data/authority_scope_adapter.py — TDD RED."""

import pytest

from acpsec.trust_score.data.basescan import ContractData
from acpsec.trust_score.dimensions.authority_scope import AuthorityScopeInput


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _abi(*fn_names: str) -> list[dict]:
    """Build a minimal ABI list from function names."""
    return [{"type": "function", "name": name, "inputs": [], "outputs": []} for name in fn_names]


def _abi_with_inputs(name: str, inputs: list[dict]) -> dict:
    return {"type": "function", "name": name, "inputs": inputs, "outputs": []}


def _contract(abi: list | None = None, address: str = "0xABCD") -> ContractData:
    return ContractData(
        address=address,
        source_verified=True,
        contract_name="TestAgent",
        abi=abi or [],
        source_code="pragma solidity ^0.8.0;",
        compiler_version="v0.8.20",
    )


def _rpc_returning(owner_address: str = "0x" + "0" * 40, owner_has_code: bool = False):
    """Returns an injectable _rpc callable with canned responses."""
    code = "0x" if not owner_has_code else "0x6060604052"
    padded_owner = "0x" + owner_address.lower().removeprefix("0x").zfill(64)

    def rpc(method: str, params: list):
        if method == "eth_call":
            return padded_owner
        if method == "eth_getCode":
            return code
        return "0x0"

    return rpc


def _rpc_failing():
    """Returns an injectable _rpc that always raises."""
    def rpc(method: str, params: list):
        raise RuntimeError("RPC unavailable")
    return rpc


def _adapter(rpc=None):
    from acpsec.trust_score.data.authority_scope_adapter import AuthorityScopeAdapter
    return AuthorityScopeAdapter(_rpc=rpc or _rpc_returning())


class _FakeSigner:
    def __init__(self, mode):
        self._mode = mode

    def read_signer_mode(self, address):
        return self._mode


class _FakeVirtuals:
    def __init__(self, value):
        self._value = value

    def get_agent_card_no_spend_limit(self, address):
        return self._value


def _adapter_with(rpc=None, signer=None, virtuals=None):
    from acpsec.trust_score.data.authority_scope_adapter import AuthorityScopeAdapter
    return AuthorityScopeAdapter(
        _rpc=rpc or _rpc_returning(),
        _signer_reader=signer,
        _virtuals_client=virtuals,
    )


# ---------------------------------------------------------------------------
# ABI analysis — pure flag detection
# ---------------------------------------------------------------------------

class TestABIAnalysis:
    def _analyze(self, abi: list) -> dict:
        from acpsec.trust_score.data.authority_scope_adapter import analyze_abi
        return analyze_abi(abi)

    def test_empty_abi_all_false(self):
        flags = self._analyze([])
        assert not any(flags.values())

    def test_withdraw_fn_detected(self):
        assert self._analyze(_abi("withdraw"))["has_withdrawal"]

    def test_withdrawall_fn_detected(self):
        assert self._analyze(_abi("withdrawAll"))["has_withdrawal"]

    def test_claim_fn_detected(self):
        assert self._analyze(_abi("claim"))["has_withdrawal"]

    def test_pull_fn_detected(self):
        assert self._analyze(_abi("pullFunds"))["has_withdrawal"]

    def test_unrelated_fn_not_withdrawal(self):
        assert not self._analyze(_abi("transfer", "balanceOf"))["has_withdrawal"]

    def test_setcap_detected_as_spending_cap(self):
        assert self._analyze(_abi("setCap"))["has_spending_cap"]

    def test_setlimit_detected_as_spending_cap(self):
        assert self._analyze(_abi("setLimit"))["has_spending_cap"]

    def test_setbudget_detected_as_spending_cap(self):
        assert self._analyze(_abi("setBudget"))["has_spending_cap"]

    def test_spendingcap_fn_detected(self):
        assert self._analyze(_abi("spendingCap"))["has_spending_cap"]

    def test_pause_detected(self):
        assert self._analyze(_abi("pause"))["has_pause"]

    def test_unpause_detected(self):
        assert self._analyze(_abi("unpause"))["has_pause"]

    def test_emergencystop_detected(self):
        assert self._analyze(_abi("emergencyStop"))["has_pause"]

    def test_timelock_keyword_detected(self):
        assert self._analyze(_abi("queueTransaction"))["has_timelock"]

    def test_execute_with_delay_detected(self):
        assert self._analyze(_abi("executeAfterDelay"))["has_timelock"]

    def test_eta_fn_detected_as_timelock(self):
        assert self._analyze(_abi("getEta"))["has_timelock"]

    def test_transferownership_detected_as_key_rotation(self):
        assert self._analyze(_abi("transferOwnership"))["has_key_rotation"]

    def test_setowner_detected_as_key_rotation(self):
        assert self._analyze(_abi("setOwner"))["has_key_rotation"]

    def test_changeowner_detected_as_key_rotation(self):
        assert self._analyze(_abi("changeOwner"))["has_key_rotation"]

    def test_approve_with_two_inputs_detected_as_token_approval(self):
        abi = [_abi_with_inputs("approve", [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ])]
        assert self._analyze(abi)["has_token_approval"]

    def test_approve_with_wrong_signature_not_detected(self):
        abi = [_abi_with_inputs("approve", [{"name": "x", "type": "uint256"}])]
        assert not self._analyze(abi)["has_token_approval"]

    def test_approve_no_inputs_not_detected(self):
        assert not self._analyze(_abi("approve"))["has_token_approval"]


# ---------------------------------------------------------------------------
# On-chain reads — with injectable RPC
# ---------------------------------------------------------------------------

class TestChainReads:
    def test_owner_address_extracted(self):
        owner = "0xDeAdBeEf" + "0" * 32
        result = _adapter(_rpc_returning(owner_address=owner)).fetch(_contract())
        # We can't check the address directly from AuthorityScopeInput,
        # but we can verify the owner_multisig flag is correctly derived
        # (EOA → False, contract → True)
        assert result.owner_multisig is False  # EOA by default

    def test_eoa_owner_sets_multisig_false(self):
        rpc = _rpc_returning(owner_has_code=False)
        result = _adapter(rpc).fetch(_contract(_abi("withdraw")))
        assert result.owner_multisig is False

    def test_contract_owner_sets_multisig_true(self):
        rpc = _rpc_returning(owner_has_code=True)
        result = _adapter(rpc).fetch(_contract(_abi("withdraw")))
        assert result.owner_multisig is True

    def test_rpc_failure_does_not_raise(self):
        result = _adapter(_rpc_failing()).fetch(_contract())
        assert isinstance(result, AuthorityScopeInput)

    def test_rpc_failure_defaults_to_conservative(self):
        # On RPC failure, owner assumed EOA (conservative — don't hide the risk)
        result = _adapter(_rpc_failing()).fetch(_contract(_abi("withdraw")))
        assert result.owner_multisig is False


# ---------------------------------------------------------------------------
# Mapping: ABI + chain flags → AuthorityScopeInput
# ---------------------------------------------------------------------------

class TestMapping:
    def test_withdrawal_fn_plus_eoa_owner_sets_gated_eoa(self):
        result = _adapter(_rpc_returning(owner_has_code=False)).fetch(_contract(_abi("withdraw")))
        assert result.withdrawal_gated_eoa is True

    def test_withdrawal_fn_plus_contract_owner_still_gated(self):
        # Owner is multisig, but withdrawal path still exists — gated_eoa=True, owner_multisig=True
        result = _adapter(_rpc_returning(owner_has_code=True)).fetch(_contract(_abi("withdraw")))
        assert result.withdrawal_gated_eoa is True
        assert result.owner_multisig is True

    def test_no_withdrawal_fn_gated_eoa_false(self):
        result = _adapter().fetch(_contract(_abi("balanceOf")))
        assert result.withdrawal_gated_eoa is False

    def test_no_spending_cap_sets_flag(self):
        result = _adapter().fetch(_contract(_abi("withdraw")))
        assert result.no_spending_budget is True

    def test_has_spending_cap_clears_flag(self):
        result = _adapter().fetch(_contract(_abi("setCap")))
        assert result.no_spending_budget is False

    def test_no_pause_sets_flag(self):
        result = _adapter().fetch(_contract(_abi("withdraw")))
        assert result.no_emergency_stop is True

    def test_has_pause_clears_flag(self):
        result = _adapter().fetch(_contract(_abi("pause")))
        assert result.no_emergency_stop is False

    def test_no_timelock_sets_flag(self):
        result = _adapter().fetch(_contract())
        assert result.no_timelock is True

    def test_has_timelock_clears_flag(self):
        result = _adapter().fetch(_contract(_abi("queueTransaction")))
        assert result.no_timelock is False

    def test_approve_sets_infinite_approvals(self):
        abi = [_abi_with_inputs("approve", [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ])]
        result = _adapter().fetch(_contract(abi))
        assert result.infinite_token_approvals is True

    def test_no_approve_clears_infinite_approvals(self):
        result = _adapter().fetch(_contract(_abi("transfer")))
        assert result.infinite_token_approvals is False

    def test_no_key_rotation_sets_flag(self):
        result = _adapter().fetch(_contract(_abi("balanceOf")))
        assert result.no_key_rotation is True

    def test_has_transfer_ownership_clears_flag(self):
        result = _adapter().fetch(_contract(_abi("transferOwnership")))
        assert result.no_key_rotation is False

    def test_mpc_threshold_always_false(self):
        result = _adapter().fetch(_contract())
        assert result.owner_mpc_threshold is False

    def test_can_move_arbitrary_funds_always_false(self):
        result = _adapter().fetch(_contract())
        assert result.can_move_arbitrary_funds is False


# ---------------------------------------------------------------------------
# Full fetch — returns AuthorityScopeInput
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Signer-mode integration (SmartAccountPermissionReader → signer_unrestricted)
# ---------------------------------------------------------------------------

class TestSignerModeIntegration:
    def test_unrestricted_maps_true(self):
        result = _adapter_with(signer=_FakeSigner("Unrestricted")).fetch(_contract())
        assert result.signer_unrestricted is True

    def test_restricted_maps_false(self):
        result = _adapter_with(signer=_FakeSigner("Restricted")).fetch(_contract())
        assert result.signer_unrestricted is False

    def test_none_maps_unrated(self):
        result = _adapter_with(signer=_FakeSigner(None)).fetch(_contract())
        assert result.signer_unrestricted is None

    def test_default_signer_is_unrated(self):
        # No MA v2 ABI wired by default → signer mode Unrated.
        result = _adapter().fetch(_contract(_abi("withdraw")))
        assert result.signer_unrestricted is None


# ---------------------------------------------------------------------------
# Spend-limit integration (VirtualsClient → agent_card_no_spend_limit)
# ---------------------------------------------------------------------------

class TestSpendLimitIntegration:
    def test_no_limit_maps_true(self):
        result = _adapter_with(virtuals=_FakeVirtuals(True)).fetch(_contract())
        assert result.agent_card_no_spend_limit is True

    def test_limit_set_maps_false(self):
        result = _adapter_with(virtuals=_FakeVirtuals(False)).fetch(_contract())
        assert result.agent_card_no_spend_limit is False

    def test_unrated_maps_none(self):
        result = _adapter_with(virtuals=_FakeVirtuals(None)).fetch(_contract())
        assert result.agent_card_no_spend_limit is None

    def test_default_external_scan_is_unrated(self):
        # Default scan_mode is external → private spend limit not reachable.
        result = _adapter().fetch(_contract(_abi("withdraw")))
        assert result.agent_card_no_spend_limit is None


class TestFetch:
    def test_returns_authority_scope_input(self):
        result = _adapter().fetch(_contract())
        assert isinstance(result, AuthorityScopeInput)

    def test_empty_abi_eoa_owner_conservative_defaults(self):
        # No ABI → no withdrawal detected → gated_eoa=False even with EOA owner
        result = _adapter(_rpc_returning(owner_has_code=False)).fetch(_contract([]))
        assert result.withdrawal_gated_eoa is False
        assert result.no_spending_budget is True
        assert result.no_emergency_stop is True
        assert result.no_timelock is True
        assert result.no_key_rotation is True
