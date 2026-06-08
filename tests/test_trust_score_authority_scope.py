"""Tests for acpsec/trust_score/dimensions/authority_scope.py — TDD RED."""

import pytest

from acpsec.trust_score.models import DimScore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(**kwargs):
    from acpsec.trust_score.dimensions.authority_scope import AuthorityScopeInput, run
    return run(AuthorityScopeInput(**kwargs))


def _severities(result: DimScore) -> list[str]:
    return [f.severity for f in result.findings]


# ---------------------------------------------------------------------------
# Clean baseline
# ---------------------------------------------------------------------------

class TestClean:
    def test_clean_scores_100(self):
        assert _run().score == 100

    def test_clean_has_no_findings(self):
        assert _run().findings == []

    def test_dimension_name(self):
        assert _run().name == "authority_scope"

    def test_dimension_weight_is_0_20(self):
        assert _run().weight == pytest.approx(0.20)

    def test_dimension_is_rated(self):
        assert _run().rated is True


# ---------------------------------------------------------------------------
# CRITICAL — no dimension penalty, finding emitted
# ---------------------------------------------------------------------------

class TestCritical:
    def test_arbitrary_fund_movement_emits_critical(self):
        result = _run(can_move_arbitrary_funds=True)
        assert "CRITICAL" in _severities(result)

    def test_arbitrary_fund_movement_no_dim_penalty(self):
        result = _run(can_move_arbitrary_funds=True)
        assert result.score == 100


# ---------------------------------------------------------------------------
# High — withdrawal gated by EOA (with mitigations)
# ---------------------------------------------------------------------------

class TestWithdrawalGatedEOA:
    def test_eoa_gated_no_mitigation_subtracts_20(self):
        result = _run(withdrawal_gated_eoa=True)
        assert result.score == 80

    def test_eoa_gated_no_mitigation_emits_high_finding(self):
        result = _run(withdrawal_gated_eoa=True)
        assert "High" in _severities(result)

    def test_eoa_gated_multisig_subtracts_5(self):
        result = _run(withdrawal_gated_eoa=True, owner_multisig=True)
        assert result.score == 95

    def test_eoa_gated_multisig_still_emits_finding(self):
        # Partially mitigated — still worth flagging, just at reduced penalty
        result = _run(withdrawal_gated_eoa=True, owner_multisig=True)
        assert len(result.findings) == 1

    def test_eoa_gated_mpc_threshold_no_penalty(self):
        result = _run(withdrawal_gated_eoa=True, owner_mpc_threshold=True)
        assert result.score == 100

    def test_eoa_gated_mpc_threshold_no_finding(self):
        # Fully mitigated — penalty is 0, no finding emitted
        result = _run(withdrawal_gated_eoa=True, owner_mpc_threshold=True)
        assert result.findings == []

    def test_multisig_without_eoa_gating_has_no_effect(self):
        # Mitigation flags are only meaningful when withdrawal_gated_eoa=True
        result = _run(owner_multisig=True)
        assert result.score == 100
        assert result.findings == []


# ---------------------------------------------------------------------------
# High — no spending budget
# ---------------------------------------------------------------------------

class TestSpendingBudget:
    def test_no_spending_budget_subtracts_25(self):
        result = _run(no_spending_budget=True)
        assert result.score == 75

    def test_no_spending_budget_emits_high_finding(self):
        result = _run(no_spending_budget=True)
        assert "High" in _severities(result)


# ---------------------------------------------------------------------------
# High — signer-key Unrestricted mode (tri-state: True / False / None=Unrated)
# ---------------------------------------------------------------------------

class TestSignerUnrestricted:
    def test_unrestricted_subtracts_25(self):
        assert _run(signer_unrestricted=True).score == 75

    def test_unrestricted_emits_high(self):
        assert "High" in _severities(_run(signer_unrestricted=True))

    def test_restricted_false_no_penalty(self):
        result = _run(signer_unrestricted=False)
        assert result.score == 100
        assert result.findings == []

    def test_restricted_false_not_unrated(self):
        assert "signer_unrestricted" not in _run(signer_unrestricted=False).unrated_checks

    def test_none_is_unrated_no_penalty(self):
        result = _run(signer_unrestricted=None)
        assert result.score == 100
        assert result.findings == []

    def test_none_recorded_in_unrated_checks(self):
        assert "signer_unrestricted" in _run(signer_unrestricted=None).unrated_checks


# ---------------------------------------------------------------------------
# Medium — Agent Card spend limit (tri-state, genuinely private → often Unrated)
# ---------------------------------------------------------------------------

class TestAgentCardSpendLimit:
    def test_no_spend_limit_subtracts_15(self):
        assert _run(agent_card_no_spend_limit=True).score == 85

    def test_no_spend_limit_emits_medium(self):
        assert "Medium" in _severities(_run(agent_card_no_spend_limit=True))

    def test_limit_set_false_no_penalty(self):
        result = _run(agent_card_no_spend_limit=False)
        assert result.score == 100
        assert result.findings == []

    def test_limit_set_false_not_unrated(self):
        assert "agent_card_no_spend_limit" not in _run(agent_card_no_spend_limit=False).unrated_checks

    def test_none_is_unrated_no_penalty(self):
        result = _run(agent_card_no_spend_limit=None)
        assert result.score == 100
        assert result.findings == []

    def test_none_recorded_in_unrated_checks(self):
        assert "agent_card_no_spend_limit" in _run(agent_card_no_spend_limit=None).unrated_checks


# ---------------------------------------------------------------------------
# Tri-state defaults — both new checks Unrated when not supplied
# ---------------------------------------------------------------------------

class TestTriStateDefaults:
    def test_both_default_to_unrated(self):
        result = _run()
        assert "signer_unrestricted" in result.unrated_checks
        assert "agent_card_no_spend_limit" in result.unrated_checks

    def test_default_unrated_does_not_penalize(self):
        assert _run().score == 100

    def test_default_unrated_emits_no_findings(self):
        assert _run().findings == []


# ---------------------------------------------------------------------------
# Medium penalties
# ---------------------------------------------------------------------------

class TestMediumPenalties:
    def test_infinite_token_approvals_subtracts_15(self):
        assert _run(infinite_token_approvals=True).score == 85

    def test_infinite_token_approvals_emits_medium(self):
        assert "Medium" in _severities(_run(infinite_token_approvals=True))

    def test_no_timelock_subtracts_10(self):
        assert _run(no_timelock=True).score == 90

    def test_no_timelock_emits_medium(self):
        assert "Medium" in _severities(_run(no_timelock=True))

    def test_no_emergency_stop_subtracts_10(self):
        assert _run(no_emergency_stop=True).score == 90

    def test_no_emergency_stop_emits_medium(self):
        assert "Medium" in _severities(_run(no_emergency_stop=True))


# ---------------------------------------------------------------------------
# Low penalty
# ---------------------------------------------------------------------------

class TestLowPenalty:
    def test_no_key_rotation_subtracts_5(self):
        assert _run(no_key_rotation=True).score == 95

    def test_no_key_rotation_emits_low(self):
        assert "Low" in _severities(_run(no_key_rotation=True))


# ---------------------------------------------------------------------------
# Accumulation, floor, and mixed cases
# ---------------------------------------------------------------------------

class TestAccumulationAndFloor:
    def test_both_high_penalties_accumulate(self):
        # EOA gating -20 + no spending budget -25 = -45 → 55
        result = _run(withdrawal_gated_eoa=True, no_spending_budget=True)
        assert result.score == 55

    def test_all_medium_accumulate(self):
        # -15 -10 -10 = -35 → 65
        result = _run(
            infinite_token_approvals=True,
            no_timelock=True,
            no_emergency_stop=True,
        )
        assert result.score == 65

    def test_all_penalties_floor_at_zero(self):
        # -20 -25 -15 -10 -10 -5 = -85 → 15 (not floored here)
        # Add more to force floor: add multisig won't help, but EOA gating already at -20
        result = _run(
            withdrawal_gated_eoa=True,
            no_spending_budget=True,
            infinite_token_approvals=True,
            no_timelock=True,
            no_emergency_stop=True,
            no_key_rotation=True,
        )
        assert result.score == 15

    def test_score_never_goes_negative(self):
        # Same as above but also add CRITICAL (no dim penalty) — confirm floor
        result = _run(
            can_move_arbitrary_funds=True,
            withdrawal_gated_eoa=True,
            no_spending_budget=True,
            infinite_token_approvals=True,
            no_timelock=True,
            no_emergency_stop=True,
            no_key_rotation=True,
        )
        assert result.score >= 0

    def test_critical_plus_high_accumulate_independently(self):
        # CRITICAL no dim penalty; High -20 -25 = -45 → score 55 + CRITICAL finding
        result = _run(
            can_move_arbitrary_funds=True,
            withdrawal_gated_eoa=True,
            no_spending_budget=True,
        )
        assert result.score == 55
        assert "CRITICAL" in _severities(result)
        assert _severities(result).count("High") == 2

    def test_multisig_mitigation_in_full_accumulation(self):
        # EOA gating + multisig → -5; no_spending_budget -25; total -30 → 70
        result = _run(
            withdrawal_gated_eoa=True,
            owner_multisig=True,
            no_spending_budget=True,
        )
        assert result.score == 70

    def test_finding_count_matches_issues_detected(self):
        result = _run(
            can_move_arbitrary_funds=True,   # CRITICAL
            withdrawal_gated_eoa=True,        # High
            no_timelock=True,                 # Medium
            no_key_rotation=True,             # Low
        )
        assert len(result.findings) == 4
