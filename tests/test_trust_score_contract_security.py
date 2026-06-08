"""Tests for acpsec/trust_score/dimensions/contract_security.py — TDD RED."""

import pytest

from acpsec.trust_score.models import DimScore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(**kwargs):
    from acpsec.trust_score.dimensions.contract_security import ContractSecurityInput, run
    inp = ContractSecurityInput(**kwargs)
    return run(inp)


def _clean() -> DimScore:
    return _run(source_verified=True)


def _severities(result: DimScore) -> list[str]:
    return [f.severity for f in result.findings]


def _details(result: DimScore) -> list[str]:
    return [f.detail for f in result.findings]


# ---------------------------------------------------------------------------
# Clean / no-issue baseline
# ---------------------------------------------------------------------------

class TestClean:
    def test_clean_contract_scores_100(self):
        assert _clean().score == 100

    def test_clean_contract_has_no_findings(self):
        assert _clean().findings == []

    def test_dimension_name_is_contract_security(self):
        assert _clean().name == "contract_security"

    def test_dimension_weight_is_0_25(self):
        assert _clean().weight == pytest.approx(0.25)

    def test_dimension_is_rated(self):
        assert _clean().rated is True


# ---------------------------------------------------------------------------
# CRITICAL findings — no dimension-level penalty, but Finding is emitted
# ---------------------------------------------------------------------------

class TestCriticalFindings:
    def test_unverified_source_emits_critical_finding(self):
        result = _run(source_verified=False)
        assert "CRITICAL" in _severities(result)

    def test_unverified_source_does_not_reduce_dim_score(self):
        # Penalty at composite level only (engine's CRITICAL_CAP); dim score unaffected
        result = _run(source_verified=False)
        assert result.score == 100

    def test_arbitrary_delegatecall_emits_critical_finding(self):
        result = _run(source_verified=True, has_arbitrary_delegatecall=True)
        assert "CRITICAL" in _severities(result)

    def test_arbitrary_delegatecall_does_not_reduce_dim_score(self):
        result = _run(source_verified=True, has_arbitrary_delegatecall=True)
        assert result.score == 100

    def test_unbounded_mint_emits_critical_finding(self):
        result = _run(source_verified=True, has_unbounded_mint=True)
        assert "CRITICAL" in _severities(result)

    def test_unbounded_mint_does_not_reduce_dim_score(self):
        result = _run(source_verified=True, has_unbounded_mint=True)
        assert result.score == 100

    def test_multiple_critical_conditions_each_emit_finding(self):
        result = _run(source_verified=False, has_arbitrary_delegatecall=True, has_unbounded_mint=True)
        assert _severities(result).count("CRITICAL") == 3


# ---------------------------------------------------------------------------
# High penalties
# ---------------------------------------------------------------------------

class TestHighPenalties:
    def test_reentrancy_subtracts_30(self):
        result = _run(source_verified=True, has_reentrancy=True)
        assert result.score == 70

    def test_reentrancy_emits_high_finding(self):
        result = _run(source_verified=True, has_reentrancy=True)
        assert "High" in _severities(result)

    def test_missing_access_control_subtracts_25(self):
        result = _run(source_verified=True, missing_access_control=True)
        assert result.score == 75

    def test_missing_access_control_emits_high_finding(self):
        result = _run(source_verified=True, missing_access_control=True)
        assert "High" in _severities(result)

    def test_upgradeable_proxy_eoa_admin_subtracts_20(self):
        result = _run(source_verified=True, upgradeable_proxy_eoa_admin=True)
        assert result.score == 80

    def test_upgradeable_proxy_eoa_admin_emits_high_finding(self):
        result = _run(source_verified=True, upgradeable_proxy_eoa_admin=True)
        assert "High" in _severities(result)


# ---------------------------------------------------------------------------
# Medium penalties
# ---------------------------------------------------------------------------

class TestMediumPenalties:
    def test_selfdestruct_subtracts_15(self):
        result = _run(source_verified=True, has_selfdestruct=True)
        assert result.score == 85

    def test_selfdestruct_emits_medium_finding(self):
        result = _run(source_verified=True, has_selfdestruct=True)
        assert "Medium" in _severities(result)

    def test_tx_origin_auth_subtracts_15(self):
        result = _run(source_verified=True, uses_tx_origin_auth=True)
        assert result.score == 85

    def test_tx_origin_auth_emits_medium_finding(self):
        result = _run(source_verified=True, uses_tx_origin_auth=True)
        assert "Medium" in _severities(result)

    def test_unchecked_low_level_calls_subtracts_10(self):
        result = _run(source_verified=True, unchecked_low_level_calls=True)
        assert result.score == 90

    def test_unchecked_low_level_calls_emits_medium_finding(self):
        result = _run(source_verified=True, unchecked_low_level_calls=True)
        assert "Medium" in _severities(result)

    def test_floating_pragma_subtracts_10(self):
        result = _run(source_verified=True, floating_pragma=True)
        assert result.score == 90

    def test_floating_pragma_emits_medium_finding(self):
        result = _run(source_verified=True, floating_pragma=True)
        assert "Medium" in _severities(result)


# ---------------------------------------------------------------------------
# Accumulation & floor
# ---------------------------------------------------------------------------

class TestAccumulationAndFloor:
    def test_all_high_penalties_accumulate(self):
        # reentrancy -30, missing_access -25, proxy_eoa -20 = -75 → score 25
        result = _run(
            source_verified=True,
            has_reentrancy=True,
            missing_access_control=True,
            upgradeable_proxy_eoa_admin=True,
        )
        assert result.score == 25

    def test_all_medium_penalties_accumulate(self):
        # selfdestruct -15, tx_origin -15, unchecked -10, floating -10 = -50 → score 50
        result = _run(
            source_verified=True,
            has_selfdestruct=True,
            uses_tx_origin_auth=True,
            unchecked_low_level_calls=True,
            floating_pragma=True,
        )
        assert result.score == 50

    def test_all_high_and_medium_floor_at_zero(self):
        # -30 -25 -20 -15 -15 -10 -10 = -125 → floor 0
        result = _run(
            source_verified=True,
            has_reentrancy=True,
            missing_access_control=True,
            upgradeable_proxy_eoa_admin=True,
            has_selfdestruct=True,
            uses_tx_origin_auth=True,
            unchecked_low_level_calls=True,
            floating_pragma=True,
        )
        assert result.score == 0

    def test_score_never_goes_negative(self):
        result = _run(
            source_verified=False,
            has_arbitrary_delegatecall=True,
            has_unbounded_mint=True,
            has_reentrancy=True,
            missing_access_control=True,
            upgradeable_proxy_eoa_admin=True,
            has_selfdestruct=True,
            uses_tx_origin_auth=True,
            unchecked_low_level_calls=True,
            floating_pragma=True,
        )
        assert result.score >= 0

    def test_critical_plus_high_penalties_accumulate_independently(self):
        # CRITICAL does not reduce dim score; High penalties do
        result = _run(
            source_verified=False,        # CRITICAL → no dim penalty
            has_reentrancy=True,          # High → -30
            missing_access_control=True,  # High → -25
        )
        assert result.score == 45
        assert "CRITICAL" in _severities(result)
        assert _severities(result).count("High") == 2

    def test_finding_count_matches_issues_detected(self):
        result = _run(
            source_verified=False,
            has_reentrancy=True,
            has_selfdestruct=True,
        )
        # 1 CRITICAL + 1 High + 1 Medium = 3
        assert len(result.findings) == 3
