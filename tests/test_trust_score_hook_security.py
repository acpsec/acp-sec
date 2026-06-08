"""Tests for acpsec/trust_score/dimensions/hook_security.py — TDD RED."""

import pytest

from acpsec.trust_score.models import DimScore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(**kwargs):
    from acpsec.trust_score.dimensions.hook_security import HookSecurityInput, run
    return run(HookSecurityInput(**kwargs))


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
        assert _run().name == "hook_security"

    def test_dimension_weight_is_0_15(self):
        assert _run().weight == pytest.approx(0.15)

    def test_dimension_is_rated(self):
        assert _run().rated is True


# ---------------------------------------------------------------------------
# CRITICAL — no dimension penalty, finding emitted
# ---------------------------------------------------------------------------

class TestCritical:
    def test_unauthorized_caller_emits_critical(self):
        result = _run(unauthorized_caller=True)
        assert "CRITICAL" in _severities(result)

    def test_unauthorized_caller_no_dim_penalty(self):
        result = _run(unauthorized_caller=True)
        assert result.score == 100


# ---------------------------------------------------------------------------
# CRITICAL — hook diverts escrow / principal during a callback (tri-state)
# ---------------------------------------------------------------------------

class TestEscrowDiversionCritical:
    def test_diverts_escrow_true_emits_critical(self):
        assert "CRITICAL" in _severities(_run(hook_diverts_escrow=True))

    def test_diverts_escrow_true_no_dim_penalty(self):
        assert _run(hook_diverts_escrow=True).score == 100

    def test_diverts_escrow_false_no_finding(self):
        result = _run(hook_diverts_escrow=False)
        assert result.findings == []
        assert result.score == 100

    def test_diverts_escrow_false_not_unrated(self):
        assert "hook_diverts_escrow" not in _run(hook_diverts_escrow=False).unrated_checks

    def test_diverts_escrow_none_is_unrated_no_finding(self):
        result = _run(hook_diverts_escrow=None)
        assert result.findings == []
        assert "hook_diverts_escrow" in result.unrated_checks

    def test_diverts_escrow_defaults_to_unrated(self):
        assert "hook_diverts_escrow" in _run().unrated_checks


# ---------------------------------------------------------------------------
# High penalties
# ---------------------------------------------------------------------------

class TestHighPenalties:
    def test_permissions_over_scoped_subtracts_25(self):
        result = _run(permissions_over_scoped=True)
        assert result.score == 75

    def test_permissions_over_scoped_emits_high(self):
        result = _run(permissions_over_scoped=True)
        assert "High" in _severities(result)

    def test_hook_reentrancy_subtracts_20(self):
        result = _run(hook_reentrancy=True)
        assert result.score == 80

    def test_hook_reentrancy_emits_high(self):
        result = _run(hook_reentrancy=True)
        assert "High" in _severities(result)


# ---------------------------------------------------------------------------
# Medium penalties
# ---------------------------------------------------------------------------

class TestMediumPenalties:
    def test_can_block_settlement_subtracts_15(self):
        assert _run(can_block_settlement=True).score == 85

    def test_can_block_settlement_emits_medium(self):
        assert "Medium" in _severities(_run(can_block_settlement=True))

    def test_dynamic_fee_manipulation_subtracts_15(self):
        assert _run(dynamic_fee_manipulation=True).score == 85

    def test_dynamic_fee_manipulation_emits_medium(self):
        assert "Medium" in _severities(_run(dynamic_fee_manipulation=True))

    def test_hook_upgradeable_by_eoa_subtracts_15(self):
        assert _run(hook_upgradeable_by_eoa=True).score == 85

    def test_hook_upgradeable_by_eoa_emits_medium(self):
        assert "Medium" in _severities(_run(hook_upgradeable_by_eoa=True))


# ---------------------------------------------------------------------------
# Accumulation, floor, mixed cases
# ---------------------------------------------------------------------------

class TestAccumulationAndFloor:
    def test_both_high_penalties_accumulate(self):
        # -25 -20 = -45 → 55
        result = _run(permissions_over_scoped=True, hook_reentrancy=True)
        assert result.score == 55

    def test_all_medium_penalties_accumulate(self):
        # -15 -15 -15 = -45 → 55
        result = _run(
            can_block_settlement=True,
            dynamic_fee_manipulation=True,
            hook_upgradeable_by_eoa=True,
        )
        assert result.score == 55

    def test_all_high_and_medium_accumulate(self):
        # -25 -20 -15 -15 -15 = -90 → 10
        result = _run(
            permissions_over_scoped=True,
            hook_reentrancy=True,
            can_block_settlement=True,
            dynamic_fee_manipulation=True,
            hook_upgradeable_by_eoa=True,
        )
        assert result.score == 10

    def test_score_never_goes_negative(self):
        result = _run(
            unauthorized_caller=True,
            permissions_over_scoped=True,
            hook_reentrancy=True,
            can_block_settlement=True,
            dynamic_fee_manipulation=True,
            hook_upgradeable_by_eoa=True,
        )
        assert result.score >= 0

    def test_critical_plus_all_penalties_accumulate_independently(self):
        # CRITICAL no dim penalty; High -25 -20 → score 55 + CRITICAL finding
        result = _run(
            unauthorized_caller=True,
            permissions_over_scoped=True,
            hook_reentrancy=True,
        )
        assert result.score == 55
        assert "CRITICAL" in _severities(result)
        assert _severities(result).count("High") == 2

    def test_finding_count_matches_issues(self):
        result = _run(
            unauthorized_caller=True,      # CRITICAL
            permissions_over_scoped=True,  # High
            can_block_settlement=True,     # Medium
            hook_upgradeable_by_eoa=True,  # Medium
        )
        assert len(result.findings) == 4
