"""Tests for acpsec/trust_score/dimensions/acp_compliance.py — ACP v3 (TDD)."""

import pytest

from acpsec.trust_score.models import DimScore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(**kwargs):
    from acpsec.trust_score.dimensions.acp_compliance import ACPComplianceInput, run
    return run(ACPComplianceInput(**kwargs))


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
        assert _run().name == "acp_compliance"

    def test_dimension_weight_is_0_15(self):
        assert _run().weight == pytest.approx(0.15)

    def test_dimension_is_rated(self):
        assert _run().rated is True


# ---------------------------------------------------------------------------
# CRITICAL — no dimension penalty, findings emitted
# ---------------------------------------------------------------------------

class TestCritical:
    def test_escrow_drainable_emits_critical(self):
        assert "CRITICAL" in _severities(_run(escrow_drainable=True))

    def test_escrow_drainable_no_dim_penalty(self):
        assert _run(escrow_drainable=True).score == 100

    def test_can_self_settle_emits_critical(self):
        assert "CRITICAL" in _severities(_run(can_self_settle=True))

    def test_can_self_settle_no_dim_penalty(self):
        assert _run(can_self_settle=True).score == 100

    def test_both_criticals_emit_two_findings(self):
        result = _run(escrow_drainable=True, can_self_settle=True)
        assert _severities(result).count("CRITICAL") == 2


# ---------------------------------------------------------------------------
# High — missing lifecycle phases (per phase, -15 each); 5 v3 phases
# ---------------------------------------------------------------------------

class TestMissingLifecyclePhases:
    def test_zero_missing_phases_no_penalty(self):
        result = _run(missing_lifecycle_phases=0)
        assert result.score == 100
        assert result.findings == []

    def test_one_missing_phase_subtracts_15(self):
        assert _run(missing_lifecycle_phases=1).score == 85

    def test_one_missing_phase_emits_one_high_finding(self):
        result = _run(missing_lifecycle_phases=1)
        assert len(result.findings) == 1
        assert result.findings[0].severity == "High"

    def test_three_missing_phases_subtracts_45(self):
        assert _run(missing_lifecycle_phases=3).score == 55

    def test_five_missing_phases_subtracts_75(self):
        assert _run(missing_lifecycle_phases=5).score == 25


# ---------------------------------------------------------------------------
# High — no reject/refund path (renamed from no_refund_path)
# ---------------------------------------------------------------------------

class TestNoRejectRefundPath:
    def test_no_reject_refund_path_subtracts_20(self):
        assert _run(no_reject_refund_path=True).score == 80

    def test_no_reject_refund_path_emits_high(self):
        assert "High" in _severities(_run(no_reject_refund_path=True))


# ---------------------------------------------------------------------------
# High — fee split non-conformant (tri-state: True / False / None=Unrated)
# ---------------------------------------------------------------------------

class TestFeeSplitNonconformant:
    def test_nonconformant_subtracts_20(self):
        assert _run(fee_split_nonconformant=True).score == 80

    def test_nonconformant_emits_high(self):
        assert "High" in _severities(_run(fee_split_nonconformant=True))

    def test_conformant_false_no_penalty(self):
        result = _run(fee_split_nonconformant=False)
        assert result.score == 100
        assert result.findings == []

    def test_conformant_false_not_unrated(self):
        assert "fee_split_nonconformant" not in _run(fee_split_nonconformant=False).unrated_checks

    def test_none_is_unrated_no_penalty(self):
        result = _run(fee_split_nonconformant=None)
        assert result.score == 100
        assert result.findings == []

    def test_none_recorded_in_unrated_checks(self):
        assert "fee_split_nonconformant" in _run(fee_split_nonconformant=None).unrated_checks

    def test_defaults_to_unrated(self):
        assert "fee_split_nonconformant" in _run().unrated_checks


# ---------------------------------------------------------------------------
# Medium — no expiry / timeout
# ---------------------------------------------------------------------------

class TestNoExpiryTimeout:
    def test_no_expiry_timeout_subtracts_15(self):
        assert _run(no_expiry_timeout=True).score == 85

    def test_no_expiry_timeout_emits_medium(self):
        assert "Medium" in _severities(_run(no_expiry_timeout=True))


# ---------------------------------------------------------------------------
# Medium — carried-over checks
# ---------------------------------------------------------------------------

class TestMediumPenalties:
    def test_settlement_not_atomic_subtracts_15(self):
        assert _run(settlement_not_atomic=True).score == 85

    def test_settlement_not_atomic_emits_medium(self):
        assert "Medium" in _severities(_run(settlement_not_atomic=True))

    def test_nonconformant_job_struct_subtracts_10(self):
        assert _run(nonconformant_job_struct=True).score == 90

    def test_nonconformant_job_struct_emits_medium(self):
        assert "Medium" in _severities(_run(nonconformant_job_struct=True))


# ---------------------------------------------------------------------------
# Accumulation, floor, mixed cases
# ---------------------------------------------------------------------------

class TestAccumulationAndFloor:
    def test_phases_and_no_reject_accumulate(self):
        # 2 phases -30 + no_reject_refund -20 = -50 → 50
        result = _run(missing_lifecycle_phases=2, no_reject_refund_path=True)
        assert result.score == 50

    def test_two_high_checks_accumulate(self):
        # no_reject_refund -20 + fee_split -20 = -40 → 60
        result = _run(no_reject_refund_path=True, fee_split_nonconformant=True)
        assert result.score == 60

    def test_all_medium_accumulate(self):
        # no_expiry -15 + settlement -15 + job_struct -10 = -40 → 60
        result = _run(
            no_expiry_timeout=True,
            settlement_not_atomic=True,
            nonconformant_job_struct=True,
        )
        assert result.score == 60

    def test_score_floors_at_zero(self):
        result = _run(
            missing_lifecycle_phases=5,   # -75
            no_reject_refund_path=True,   # -20
            fee_split_nonconformant=True, # -20
            no_expiry_timeout=True,       # -15
        )
        assert result.score == 0

    def test_score_never_goes_negative(self):
        result = _run(
            escrow_drainable=True,
            can_self_settle=True,
            missing_lifecycle_phases=5,
            no_reject_refund_path=True,
            fee_split_nonconformant=True,
            no_expiry_timeout=True,
            settlement_not_atomic=True,
            nonconformant_job_struct=True,
        )
        assert result.score >= 0

    def test_critical_plus_penalties_accumulate_independently(self):
        result = _run(
            escrow_drainable=True,         # CRITICAL — no dim penalty
            missing_lifecycle_phases=1,    # High -15
            no_reject_refund_path=True,    # High -20
        )
        assert result.score == 65
        assert "CRITICAL" in _severities(result)
        assert _severities(result).count("High") == 2

    def test_finding_count_matches_issues(self):
        result = _run(
            escrow_drainable=True,         # 1 CRITICAL
            can_self_settle=True,          # 1 CRITICAL
            missing_lifecycle_phases=2,    # 2 High
            fee_split_nonconformant=True,  # 1 High
            settlement_not_atomic=True,    # 1 Medium
        )
        assert len(result.findings) == 6
