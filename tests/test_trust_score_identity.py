"""Tests for acpsec/trust_score/dimensions/identity.py — TDD RED."""

import pytest

from acpsec.trust_score.models import DimScore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(**kwargs):
    from acpsec.trust_score.dimensions.identity import IdentityInput, run
    return run(IdentityInput(**kwargs))


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
        assert _run().name == "identity"

    def test_dimension_weight_is_0_15(self):
        assert _run().weight == pytest.approx(0.15)

    def test_dimension_is_rated(self):
        assert _run().rated is True


# ---------------------------------------------------------------------------
# CRITICAL — no dimension penalty, finding emitted
# ---------------------------------------------------------------------------

class TestCritical:
    def test_owner_mismatch_emits_critical(self):
        result = _run(owner_mismatch=True)
        assert "CRITICAL" in _severities(result)

    def test_owner_mismatch_no_dim_penalty(self):
        result = _run(owner_mismatch=True)
        assert result.score == 100


# ---------------------------------------------------------------------------
# High penalties
# ---------------------------------------------------------------------------

class TestHighPenalties:
    def test_no_erc8004_subtracts_30(self):
        result = _run(no_erc8004=True)
        assert result.score == 70

    def test_no_erc8004_emits_high_finding(self):
        result = _run(no_erc8004=True)
        assert "High" in _severities(result)

    def test_handle_unverified_subtracts_20(self):
        result = _run(handle_unverified=True)
        assert result.score == 80

    def test_handle_unverified_emits_high_finding(self):
        result = _run(handle_unverified=True)
        assert "High" in _severities(result)


# ---------------------------------------------------------------------------
# Medium penalties
# ---------------------------------------------------------------------------

class TestMediumPenalties:
    def test_endpoint_tls_mismatch_subtracts_10(self):
        assert _run(endpoint_tls_mismatch=True).score == 90

    def test_endpoint_tls_mismatch_emits_medium(self):
        assert "Medium" in _severities(_run(endpoint_tls_mismatch=True))

    def test_reputation_registry_inconsistent_subtracts_10(self):
        assert _run(reputation_registry_inconsistent=True).score == 90

    def test_reputation_registry_inconsistent_emits_medium(self):
        assert "Medium" in _severities(_run(reputation_registry_inconsistent=True))

    def test_sybil_signals_subtracts_10(self):
        assert _run(sybil_signals=True).score == 90

    def test_sybil_signals_emits_medium(self):
        assert "Medium" in _severities(_run(sybil_signals=True))


# ---------------------------------------------------------------------------
# Accumulation, floor, mixed cases
# ---------------------------------------------------------------------------

class TestAccumulationAndFloor:
    def test_both_high_penalties_accumulate(self):
        # no_erc8004 -30 + handle_unverified -20 = -50 → 50
        result = _run(no_erc8004=True, handle_unverified=True)
        assert result.score == 50

    def test_all_medium_penalties_accumulate(self):
        # -10 -10 -10 = -30 → 70
        result = _run(
            endpoint_tls_mismatch=True,
            reputation_registry_inconsistent=True,
            sybil_signals=True,
        )
        assert result.score == 70

    def test_all_penalties_accumulate(self):
        # -30 -20 -10 -10 -10 = -80 → 20
        result = _run(
            no_erc8004=True,
            handle_unverified=True,
            endpoint_tls_mismatch=True,
            reputation_registry_inconsistent=True,
            sybil_signals=True,
        )
        assert result.score == 20

    def test_score_never_goes_negative(self):
        result = _run(
            owner_mismatch=True,
            no_erc8004=True,
            handle_unverified=True,
            endpoint_tls_mismatch=True,
            reputation_registry_inconsistent=True,
            sybil_signals=True,
        )
        assert result.score >= 0

    def test_critical_plus_high_accumulate_independently(self):
        # CRITICAL no dim penalty; no_erc8004 -30 → score 70; CRITICAL finding present
        result = _run(owner_mismatch=True, no_erc8004=True)
        assert result.score == 70
        assert "CRITICAL" in _severities(result)
        assert "High" in _severities(result)

    def test_finding_count_matches_issues(self):
        result = _run(
            owner_mismatch=True,       # CRITICAL
            no_erc8004=True,           # High
            sybil_signals=True,        # Medium
        )
        assert len(result.findings) == 3
