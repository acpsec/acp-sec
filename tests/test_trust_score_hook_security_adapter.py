"""Tests for acpsec/trust_score/data/hook_security_adapter.py — TDD RED."""

import pytest

from acpsec.trust_score.dimensions.hook_security import HookSecurityInput


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slither_returning(findings: list[dict]):
    """Returns an injectable _slither_run callable with canned SlitherFindings."""
    from acpsec.trust_score.data.slither_runner import SlitherFinding

    def runner(target: str):
        return [
            SlitherFinding(
                check=f["check"],
                impact=f["impact"],
                confidence="Medium",
                description="",
            )
            for f in findings
        ]

    return runner


def _slither_with_desc(findings: list[dict]):
    """Like _slither_returning but lets each finding carry a description string."""
    from acpsec.trust_score.data.slither_runner import SlitherFinding

    def runner(target: str):
        return [
            SlitherFinding(
                check=f["check"],
                impact=f.get("impact", "High"),
                confidence="Medium",
                description=f.get("description", ""),
            )
            for f in findings
        ]

    return runner


def _slither_not_available():
    """Returns an injectable _slither_run that raises SlitherNotAvailable."""
    from acpsec.trust_score.data.slither_runner import SlitherNotAvailable

    def runner(target: str):
        raise SlitherNotAvailable("not installed")

    return runner


def _slither_erroring():
    """Returns an injectable _slither_run that raises SlitherError (compile/fetch failure)."""
    from acpsec.trust_score.data.slither_runner import SlitherError

    def runner(target: str):
        raise SlitherError("compilation failed")

    return runner


def _rpc_returning(owner_has_code: bool = False):
    """Returns an injectable _rpc callable with canned owner responses."""
    code = "0x" if not owner_has_code else "0x6060604052"
    owner_address = "0xdeadbeef" + "0" * 32
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


def _adapter(rpc=None, slither=None):
    from acpsec.trust_score.data.hook_security_adapter import HookSecurityAdapter
    return HookSecurityAdapter(
        _rpc=rpc or _rpc_returning(owner_has_code=False),
        _slither_run=slither or _slither_returning([]),
    )


HOOK_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"


# ---------------------------------------------------------------------------
# Test 1: fetch() returns HookSecurityInput
# ---------------------------------------------------------------------------

class TestReturnType:
    def test_returns_hook_security_input(self):
        result = _adapter().fetch(HOOK_ADDRESS)
        assert isinstance(result, HookSecurityInput)


# ---------------------------------------------------------------------------
# Test 2: No Slither findings + EOA owner → hook_upgradeable_by_eoa=True
# ---------------------------------------------------------------------------

class TestEOAOwner:
    def test_no_findings_eoa_owner_upgradeable_true(self):
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=False),
            slither=_slither_returning([]),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_upgradeable_by_eoa is True

    def test_no_findings_eoa_owner_rest_false(self):
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=False),
            slither=_slither_returning([]),
        ).fetch(HOOK_ADDRESS)
        assert result.unauthorized_caller is False
        assert result.permissions_over_scoped is False
        assert result.hook_reentrancy is False
        assert result.can_block_settlement is False
        assert result.dynamic_fee_manipulation is False


# ---------------------------------------------------------------------------
# Test 3: No Slither findings + contract owner → hook_upgradeable_by_eoa=False
# ---------------------------------------------------------------------------

class TestContractOwner:
    def test_no_findings_contract_owner_not_upgradeable(self):
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=True),
            slither=_slither_returning([]),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_upgradeable_by_eoa is False


# ---------------------------------------------------------------------------
# Test 4: Slither access-control → unauthorized_caller=True
# ---------------------------------------------------------------------------

class TestAccessControl:
    def test_access_control_sets_unauthorized_caller(self):
        result = _adapter(
            slither=_slither_returning([{"check": "access-control", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.unauthorized_caller is True


# ---------------------------------------------------------------------------
# Test 5: Slither unprotected-upgrade → unauthorized_caller=True AND hook_upgradeable_by_eoa=True
# ---------------------------------------------------------------------------

class TestUnprotectedUpgrade:
    def test_unprotected_upgrade_sets_unauthorized_caller(self):
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=True),  # contract owner, no EOA signal
            slither=_slither_returning([{"check": "unprotected-upgrade", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.unauthorized_caller is True

    def test_unprotected_upgrade_sets_hook_upgradeable_by_eoa(self):
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=True),  # contract owner, no EOA signal
            slither=_slither_returning([{"check": "unprotected-upgrade", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_upgradeable_by_eoa is True


# ---------------------------------------------------------------------------
# Test 6: Slither reentrancy-eth → hook_reentrancy=True
# ---------------------------------------------------------------------------

class TestReentrancy:
    def test_reentrancy_eth_sets_hook_reentrancy(self):
        result = _adapter(
            slither=_slither_returning([{"check": "reentrancy-eth", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_reentrancy is True

    def test_reentrancy_no_eth_sets_hook_reentrancy(self):
        result = _adapter(
            slither=_slither_returning([{"check": "reentrancy-no-eth", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_reentrancy is True


# ---------------------------------------------------------------------------
# Test 7: Slither controlled-delegatecall → permissions_over_scoped=True
# ---------------------------------------------------------------------------

class TestControlledDelegatecall:
    def test_controlled_delegatecall_sets_permissions_over_scoped(self):
        result = _adapter(
            slither=_slither_returning([{"check": "controlled-delegatecall", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.permissions_over_scoped is True

    def test_controlled_delegatecall_also_sets_can_block_settlement(self):
        result = _adapter(
            slither=_slither_returning([{"check": "controlled-delegatecall", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.can_block_settlement is True


# ---------------------------------------------------------------------------
# Test 8: Slither arbitrary-send-eth → dynamic_fee_manipulation=True
# ---------------------------------------------------------------------------

class TestArbitrarySendEth:
    def test_arbitrary_send_eth_sets_dynamic_fee_manipulation(self):
        result = _adapter(
            slither=_slither_returning([{"check": "arbitrary-send-eth", "impact": "Medium"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.dynamic_fee_manipulation is True

    def test_arbitrary_send_eth_also_sets_permissions_over_scoped(self):
        result = _adapter(
            slither=_slither_returning([{"check": "arbitrary-send-eth", "impact": "Medium"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.permissions_over_scoped is True


# ---------------------------------------------------------------------------
# Test 9: No Slither findings + contract owner → all False (clean hook)
# ---------------------------------------------------------------------------

class TestCleanHook:
    def test_clean_hook_all_false(self):
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=True),
            slither=_slither_returning([]),
        ).fetch(HOOK_ADDRESS)
        assert result.unauthorized_caller is False
        assert result.permissions_over_scoped is False
        assert result.hook_reentrancy is False
        assert result.can_block_settlement is False
        assert result.dynamic_fee_manipulation is False
        assert result.hook_upgradeable_by_eoa is False


# ---------------------------------------------------------------------------
# Test 10: Slither raises SlitherNotAvailable → returns HookSecurityInput (no raise)
# ---------------------------------------------------------------------------

class TestSlitherNotAvailable:
    def test_slither_not_available_does_not_raise(self):
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=False),
            slither=_slither_not_available(),
        ).fetch(HOOK_ADDRESS)
        assert isinstance(result, HookSecurityInput)

    def test_slither_not_available_still_uses_rpc_signals(self):
        # EOA owner still detected via RPC even when Slither unavailable
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=False),
            slither=_slither_not_available(),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_upgradeable_by_eoa is True

    def test_slither_not_available_contract_owner_upgradeable_false(self):
        # No Slither, contract owner → upgradeable_by_eoa should be False
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=True),
            slither=_slither_not_available(),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_upgradeable_by_eoa is False


# ---------------------------------------------------------------------------
# Test 11: RPC failure → returns HookSecurityInput without raising
# ---------------------------------------------------------------------------

class TestRPCFailure:
    def test_rpc_failure_does_not_raise(self):
        result = _adapter(
            rpc=_rpc_failing(),
            slither=_slither_returning([]),
        ).fetch(HOOK_ADDRESS)
        assert isinstance(result, HookSecurityInput)

    def test_rpc_failure_with_slither_findings_still_maps(self):
        result = _adapter(
            rpc=_rpc_failing(),
            slither=_slither_returning([{"check": "reentrancy-eth", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_reentrancy is True

    def test_rpc_failure_defaults_upgradeable_to_false(self):
        # Conservative: on RPC failure we can't determine owner, default False
        result = _adapter(
            rpc=_rpc_failing(),
            slither=_slither_returning([]),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_upgradeable_by_eoa is False


# ---------------------------------------------------------------------------
# Test 12: Multiple Slither findings → all mapped correctly
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    def test_all_findings_mapped(self):
        findings = [
            {"check": "access-control", "impact": "High"},
            {"check": "reentrancy-eth", "impact": "High"},
            {"check": "controlled-delegatecall", "impact": "High"},
            {"check": "arbitrary-send-eth", "impact": "Medium"},
        ]
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=True),  # contract owner
            slither=_slither_returning(findings),
        ).fetch(HOOK_ADDRESS)

        assert result.unauthorized_caller is True
        assert result.hook_reentrancy is True
        assert result.permissions_over_scoped is True
        assert result.can_block_settlement is True
        assert result.dynamic_fee_manipulation is True

    def test_unprotected_upgrade_plus_contract_owner_upgradeable_true(self):
        # Slither says unprotected-upgrade → override even if contract owner
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=True),
            slither=_slither_returning([{"check": "unprotected-upgrade", "impact": "High"}]),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_upgradeable_by_eoa is True
        assert result.unauthorized_caller is True

    def test_all_slither_checks_plus_eoa_owner(self):
        findings = [
            {"check": "unprotected-upgrade", "impact": "High"},
            {"check": "reentrancy-no-eth", "impact": "Medium"},
            {"check": "arbitrary-send-eth", "impact": "High"},
        ]
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=False),
            slither=_slither_returning(findings),
        ).fetch(HOOK_ADDRESS)

        assert result.unauthorized_caller is True
        assert result.hook_upgradeable_by_eoa is True
        assert result.hook_reentrancy is True
        assert result.permissions_over_scoped is True
        assert result.dynamic_fee_manipulation is True


# ---------------------------------------------------------------------------
# Test 13: CRITICAL hook_diverts_escrow — corroborated assessment only
# ---------------------------------------------------------------------------

class TestEscrowDiversionAssessment:
    def test_a_diversion_in_callback_is_critical(self):
        # Dangerous primitive reachable from a callback AND moving escrow funds.
        findings = [{
            "check": "arbitrary-send-eth", "impact": "High",
            "description": "Hook.afterAction() sends eth via call{value: amount} "
                           "transferring escrow principal to attacker",
        }]
        result = _adapter(slither=_slither_with_desc(findings)).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is True

    def test_a_delegatecall_in_callback_fund_path_is_critical(self):
        findings = [{
            "check": "controlled-delegatecall", "impact": "High",
            "description": "Hook.beforeAction() delegatecall to attacker-controlled "
                           "target which can transfer escrow balance",
        }]
        result = _adapter(slither=_slither_with_desc(findings)).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is True

    def test_b_benign_library_delegatecall_not_critical(self):
        # delegatecall to a known/immutable library → downgrade, not CRITICAL.
        findings = [{
            "check": "controlled-delegatecall", "impact": "High",
            "description": "Proxy.exec() uses delegatecall to immutable library MathLib",
        }]
        result = _adapter(slither=_slither_with_desc(findings)).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is False
        # Over-scoped High penalty still applies (the downgrade target).
        assert result.permissions_over_scoped is True

    def test_c_indeterminate_fund_move_outside_callback_is_unrated(self):
        # Fund movement present but not clearly in a callback path → can't confirm.
        findings = [{
            "check": "arbitrary-send-eth", "impact": "High",
            "description": "Contract.adminWithdraw() transfers funds to owner",
        }]
        result = _adapter(slither=_slither_with_desc(findings)).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is None

    def test_c_uninformative_description_is_unrated(self):
        # Dangerous primitive flagged but description gives no localization.
        findings = [{"check": "arbitrary-send-eth", "impact": "High", "description": ""}]
        result = _adapter(slither=_slither_with_desc(findings)).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is None

    def test_no_dangerous_primitive_is_false(self):
        # Successful scan, no diversion primitive → ruled out (clean), not Unrated.
        result = _adapter(slither=_slither_returning([])).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is False

    def test_non_dangerous_findings_only_is_false(self):
        findings = [{"check": "reentrancy-eth", "impact": "High"}]
        result = _adapter(slither=_slither_returning(findings)).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is False

    def test_slither_unavailable_is_unrated(self):
        result = _adapter(slither=_slither_not_available()).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is None

    def test_divert_wins_over_indeterminate(self):
        findings = [
            {"check": "arbitrary-send-eth", "impact": "High", "description": ""},  # indeterminate
            {"check": "controlled-delegatecall", "impact": "High",
             "description": "Hook.afterAction() delegatecall then transfer escrow funds"},  # divert
        ]
        result = _adapter(slither=_slither_with_desc(findings)).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is True


# ---------------------------------------------------------------------------
# Test 14: SlitherError degrades gracefully (like SlitherNotAvailable) instead
# of propagating and nuking the whole dimension to Unrated.
# ---------------------------------------------------------------------------

class TestSlitherErrorDegrades:
    def test_slither_error_does_not_raise(self):
        result = _adapter(slither=_slither_erroring()).fetch(HOOK_ADDRESS)
        assert isinstance(result, HookSecurityInput)

    def test_slither_error_leaves_diverts_escrow_unrated(self):
        result = _adapter(slither=_slither_erroring()).fetch(HOOK_ADDRESS)
        assert result.hook_diverts_escrow is None

    def test_slither_error_still_uses_rpc_signals(self):
        result = _adapter(
            rpc=_rpc_returning(owner_has_code=False),
            slither=_slither_erroring(),
        ).fetch(HOOK_ADDRESS)
        assert result.hook_upgradeable_by_eoa is True


# ---------------------------------------------------------------------------
# Test 15: adapter accepts network + api_key (threaded to its internal Slither)
# ---------------------------------------------------------------------------

class TestNetworkAndApiKey:
    def test_constructor_accepts_network_and_api_key(self):
        from acpsec.trust_score.data.hook_security_adapter import HookSecurityAdapter
        adapter = HookSecurityAdapter(
            rpc_url="https://sepolia.base.org",
            network="sepolia.base",
            api_key="KEY",
            _rpc=_rpc_returning(owner_has_code=False),
            _slither_run=_slither_returning([]),
        )
        assert isinstance(adapter.fetch(HOOK_ADDRESS), HookSecurityInput)
