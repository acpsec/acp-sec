"""Tests for acpsec/trust_score/dimensions/behavioral.py — TDD RED."""

import pytest

from acpsec.trust_score.models import DimScore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(**kwargs):
    from acpsec.trust_score.dimensions.behavioral import BehavioralInput, run
    return run(BehavioralInput(**kwargs))


def _hhi(jobs: list[int]) -> float:
    from acpsec.trust_score.dimensions.behavioral import compute_hhi
    return compute_hhi(jobs)


def _severities(result: DimScore) -> list[str]:
    return [f.severity for f in result.findings]


# ---------------------------------------------------------------------------
# compute_hhi() — pure math
# ---------------------------------------------------------------------------

class TestComputeHHI:
    def test_single_counterparty_is_1_0(self):
        assert _hhi([100]) == pytest.approx(1.0)

    def test_two_equal_counterparties_is_0_5(self):
        assert _hhi([50, 50]) == pytest.approx(0.5)

    def test_four_equal_counterparties_is_0_25(self):
        assert _hhi([25, 25, 25, 25]) == pytest.approx(0.25)

    def test_80_20_split(self):
        # (0.8)^2 + (0.2)^2 = 0.64 + 0.04 = 0.68
        assert _hhi([80, 20]) == pytest.approx(0.68)

    def test_60_40_split(self):
        # (0.6)^2 + (0.4)^2 = 0.36 + 0.16 = 0.52
        assert _hhi([60, 40]) == pytest.approx(0.52)

    def test_empty_list_returns_zero(self):
        assert _hhi([]) == pytest.approx(0.0)

    def test_single_zero_job_returns_zero(self):
        assert _hhi([0]) == pytest.approx(0.0)

    def test_total_zero_returns_zero(self):
        assert _hhi([0, 0, 0]) == pytest.approx(0.0)

    def test_unequal_three_counterparties(self):
        # 50/100, 30/100, 20/100 → 0.25 + 0.09 + 0.04 = 0.38
        assert _hhi([50, 30, 20]) == pytest.approx(0.38)


# ---------------------------------------------------------------------------
# Clean baseline
# ---------------------------------------------------------------------------

class TestClean:
    def test_clean_scores_100(self):
        assert _run().score == 100

    def test_clean_has_no_findings(self):
        assert _run().findings == []

    def test_dimension_name(self):
        assert _run().name == "behavioral"

    def test_dimension_weight_is_0_10(self):
        assert _run().weight == pytest.approx(0.10)

    def test_dimension_is_rated(self):
        assert _run().rated is True

    def test_no_critical_findings_possible(self):
        # Dimension 6 has no CRITICAL items in spec
        result = _run(
            fund_loss_incident=True,
            dispute_rate=1.0,
            failed_delivery_rate=1.0,
            counterparty_jobs=[100],
            volume_spike=True,
        )
        assert "CRITICAL" not in _severities(result)


# ---------------------------------------------------------------------------
# fund_loss_incident — flat -40
# ---------------------------------------------------------------------------

class TestFundLossIncident:
    def test_fund_loss_subtracts_40(self):
        assert _run(fund_loss_incident=True).score == 60

    def test_fund_loss_emits_high_finding(self):
        assert "High" in _severities(_run(fund_loss_incident=True))

    def test_no_fund_loss_no_penalty(self):
        assert _run(fund_loss_incident=False).score == 100


# ---------------------------------------------------------------------------
# dispute_rate — penalty = min(40, rate * 200)
# ---------------------------------------------------------------------------

class TestDisputeRate:
    def test_zero_rate_no_penalty(self):
        assert _run(dispute_rate=0.0).score == 100

    def test_zero_rate_no_finding(self):
        assert _run(dispute_rate=0.0).findings == []

    def test_rate_0_10_penalty_20(self):
        # min(40, 0.10 * 200) = min(40, 20) = 20 → score 80
        assert _run(dispute_rate=0.10).score == 80

    def test_rate_0_20_penalty_40(self):
        # min(40, 0.20 * 200) = min(40, 40) = 40 → score 60
        assert _run(dispute_rate=0.20).score == 60

    def test_rate_0_50_capped_at_40(self):
        # min(40, 0.50 * 200) = min(40, 100) = 40 → score 60
        assert _run(dispute_rate=0.50).score == 60

    def test_rate_1_0_capped_at_40(self):
        assert _run(dispute_rate=1.0).score == 60

    def test_positive_rate_emits_high_finding(self):
        assert "High" in _severities(_run(dispute_rate=0.10))


# ---------------------------------------------------------------------------
# failed_delivery_rate — penalty = min(30, rate * 150)
# ---------------------------------------------------------------------------

class TestFailedDeliveryRate:
    def test_zero_rate_no_penalty(self):
        assert _run(failed_delivery_rate=0.0).score == 100

    def test_zero_rate_no_finding(self):
        assert _run(failed_delivery_rate=0.0).findings == []

    def test_rate_0_10_penalty_15(self):
        # min(30, 0.10 * 150) = min(30, 15) = 15 → score 85
        assert _run(failed_delivery_rate=0.10).score == 85

    def test_rate_0_20_penalty_30(self):
        # min(30, 0.20 * 150) = min(30, 30) = 30 → score 70
        assert _run(failed_delivery_rate=0.20).score == 70

    def test_rate_0_50_capped_at_30(self):
        # min(30, 0.50 * 150) = min(30, 75) = 30 → score 70
        assert _run(failed_delivery_rate=0.50).score == 70

    def test_positive_rate_emits_high_finding(self):
        assert "High" in _severities(_run(failed_delivery_rate=0.10))


# ---------------------------------------------------------------------------
# HHI counterparty diversity — penalty = min(25, round((HHI - 0.5) * 50))
# ---------------------------------------------------------------------------

class TestHHIDiversity:
    def test_no_counterparties_no_penalty(self):
        assert _run(counterparty_jobs=[]).score == 100

    def test_hhi_at_exactly_0_5_no_penalty(self):
        # Two equal counterparties → HHI=0.5 (not > 0.5)
        assert _run(counterparty_jobs=[50, 50]).score == 100

    def test_hhi_at_0_5_no_finding(self):
        assert _run(counterparty_jobs=[50, 50]).findings == []

    def test_four_equal_counterparties_hhi_0_25_no_penalty(self):
        assert _run(counterparty_jobs=[25, 25, 25, 25]).score == 100

    def test_single_counterparty_hhi_1_0_max_penalty_25(self):
        # HHI=1.0 → penalty = min(25, round((1.0 - 0.5) * 50)) = min(25, 25) = 25 → score 75
        assert _run(counterparty_jobs=[100]).score == 75

    def test_single_counterparty_emits_medium_finding(self):
        assert "Medium" in _severities(_run(counterparty_jobs=[100]))

    def test_80_20_split_hhi_0_68_penalty_9(self):
        # HHI=0.68 → penalty = min(25, round((0.68 - 0.5) * 50)) = min(25, round(9.0)) = 9 → score 91
        assert _run(counterparty_jobs=[80, 20]).score == 91

    def test_60_40_split_hhi_0_52_penalty_1(self):
        # HHI=0.52 → penalty = min(25, round((0.52 - 0.5) * 50)) = min(25, round(1.0)) = 1 → score 99
        assert _run(counterparty_jobs=[60, 40]).score == 99

    def test_hhi_penalty_cannot_exceed_25(self):
        # Even extreme concentration stays at 25
        result = _run(counterparty_jobs=[1000])
        assert result.score == 75


# ---------------------------------------------------------------------------
# volume_spike — flat -15
# ---------------------------------------------------------------------------

class TestVolumeSpike:
    def test_volume_spike_subtracts_15(self):
        assert _run(volume_spike=True).score == 85

    def test_volume_spike_emits_medium_finding(self):
        assert "Medium" in _severities(_run(volume_spike=True))

    def test_no_spike_no_penalty(self):
        assert _run(volume_spike=False).score == 100


# ---------------------------------------------------------------------------
# Accumulation and floor
# ---------------------------------------------------------------------------

class TestAccumulationAndFloor:
    def test_fund_loss_plus_dispute_rate(self):
        # -40 + min(40, 0.10*200)=20 = -60 → 40
        result = _run(fund_loss_incident=True, dispute_rate=0.10)
        assert result.score == 40

    def test_all_flat_penalties_accumulate(self):
        # fund_loss -40, volume_spike -15 = -55 → 45
        result = _run(fund_loss_incident=True, volume_spike=True)
        assert result.score == 45

    def test_all_penalties_floor_at_zero(self):
        # -40 (fund) + -40 (dispute capped) + -30 (delivery capped) + -25 (HHI) + -15 (spike)
        # = -150 → floor 0
        result = _run(
            fund_loss_incident=True,
            dispute_rate=1.0,
            failed_delivery_rate=1.0,
            counterparty_jobs=[100],
            volume_spike=True,
        )
        assert result.score == 0

    def test_score_never_goes_negative(self):
        result = _run(
            fund_loss_incident=True,
            dispute_rate=1.0,
            failed_delivery_rate=1.0,
            counterparty_jobs=[100],
            volume_spike=True,
        )
        assert result.score >= 0

    def test_finding_count_matches_issues(self):
        result = _run(
            fund_loss_incident=True,      # High
            dispute_rate=0.10,            # High
            failed_delivery_rate=0.10,    # High
            counterparty_jobs=[100],      # Medium (HHI)
            volume_spike=True,            # Medium
        )
        assert len(result.findings) == 5
