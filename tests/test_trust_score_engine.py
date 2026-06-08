"""Tests for acpsec/trust_score/engine.py — written before implementation (TDD RED)."""

import pytest

from acpsec.trust_score.models import DimScore, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _all_clean(score: float = 100.0) -> list[DimScore]:
    """Six rated dims, no findings, all at the given score."""
    from acpsec.trust_score.weights import WEIGHTS
    return [DimScore(name=k, score=score, weight=v) for k, v in WEIGHTS.items()]


def _with_finding(dim_scores: list[DimScore], dim: str, severity: str, detail: str = "x") -> list[DimScore]:
    """Return a copy of dim_scores with a finding injected into the named dim."""
    result = []
    for d in dim_scores:
        if d.name == dim:
            result.append(DimScore(
                name=d.name, score=d.score, weight=d.weight,
                rated=d.rated, findings=[*d.findings, Finding(dim=dim, severity=severity, detail=detail)],
            ))
        else:
            result.append(d)
    return result


def _with_unrated(dim_scores: list[DimScore], dim: str) -> list[DimScore]:
    """Return a copy of dim_scores with one dim marked unrated."""
    return [
        DimScore(name=d.name, score=0.0, weight=d.weight, rated=False)
        if d.name == dim else d
        for d in dim_scores
    ]


# ---------------------------------------------------------------------------
# composite()
# ---------------------------------------------------------------------------

class TestComposite:
    def test_all_dims_at_100_gives_composite_100(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        assert engine.composite(_all_clean(100.0)) == 100

    def test_all_dims_at_0_gives_composite_0(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        assert engine.composite(_all_clean(0.0)) == 0

    def test_weighted_sum_contract_security_at_80_rest_100(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        from acpsec.trust_score.weights import WEIGHTS
        engine = TrustScoreEngine()
        dims = [
            DimScore(name=k, score=80.0 if k == "contract_security" else 100.0, weight=v)
            for k, v in WEIGHTS.items()
        ]
        # 80*0.25 + 100*0.75 = 20 + 75 = 95
        assert engine.composite(dims) == 95

    def test_weighted_sum_spec_example(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        from acpsec.trust_score.weights import WEIGHTS
        engine = TrustScoreEngine()
        subscores = {
            "contract_security": 60,
            "authority_scope": 45,
            "identity": 80,
            "hook_security": 70,
            "acp_compliance": 55,
            "behavioral": 65,
        }
        dims = [DimScore(name=k, score=subscores[k], weight=v) for k, v in WEIGHTS.items()]
        # 60*0.25 + 45*0.20 + 80*0.15 + 70*0.15 + 55*0.15 + 65*0.10
        # = 15 + 9 + 12 + 10.5 + 8.25 + 6.5 = 61.25 → 61
        assert engine.composite(dims) == 61

    def test_composite_rounds_to_nearest_int(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        from acpsec.trust_score.weights import WEIGHTS
        engine = TrustScoreEngine()
        # All dims at 50.5 → raw = 50.5, round → 50 or 51 (Python banker's rounding)
        # Just check it's an int
        dims = [DimScore(name=k, score=50.5, weight=v) for k, v in WEIGHTS.items()]
        result = engine.composite(dims)
        assert isinstance(result, int)

    def test_composite_is_int_not_float(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        result = engine.composite(_all_clean(75.0))
        assert type(result) is int


# ---------------------------------------------------------------------------
# has_critical()
# ---------------------------------------------------------------------------

class TestHasCritical:
    def test_no_findings_returns_false(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        assert engine.has_critical(_all_clean()) is False

    def test_high_finding_only_returns_false(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        dims = _with_finding(_all_clean(), "authority_scope", "High", "single EOA")
        assert engine.has_critical(dims) is False

    def test_critical_finding_returns_true(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        dims = _with_finding(_all_clean(), "contract_security", "CRITICAL", "source unverified")
        assert engine.has_critical(dims) is True

    def test_critical_in_any_dim_returns_true(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        dims = _with_finding(_all_clean(), "hook_security", "CRITICAL", "unauthorized caller")
        assert engine.has_critical(dims) is True

    def test_mix_of_high_and_critical_returns_true(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        dims = _with_finding(_all_clean(), "authority_scope", "High")
        dims = _with_finding(dims, "identity", "CRITICAL", "owner mismatch")
        assert engine.has_critical(dims) is True


# ---------------------------------------------------------------------------
# is_unrated()
# ---------------------------------------------------------------------------

class TestIsUnrated:
    def test_all_rated_returns_false(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        assert engine.is_unrated(_all_clean()) is False

    def test_one_unrated_dim_returns_true(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        dims = _with_unrated(_all_clean(), "behavioral")
        assert engine.is_unrated(dims) is True

    def test_all_unrated_returns_true(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        from acpsec.trust_score.weights import WEIGHTS
        engine = TrustScoreEngine()
        dims = [DimScore(name=k, score=0.0, weight=v, rated=False) for k, v in WEIGHTS.items()]
        assert engine.is_unrated(dims) is True


# ---------------------------------------------------------------------------
# grade_and_multiplier()
# ---------------------------------------------------------------------------

class TestGradeAndMultiplier:
    def test_score_95_is_grade_a(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        grade, mult = engine.grade_and_multiplier(95)
        assert grade == "A" and mult == pytest.approx(1.00)

    def test_score_80_is_grade_b(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        grade, mult = engine.grade_and_multiplier(80)
        assert grade == "B" and mult == pytest.approx(0.85)

    def test_score_65_is_grade_c(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        grade, mult = engine.grade_and_multiplier(65)
        assert grade == "C" and mult == pytest.approx(0.60)

    def test_score_50_is_grade_d(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        grade, mult = engine.grade_and_multiplier(50)
        assert grade == "D" and mult == pytest.approx(0.30)

    def test_score_39_is_grade_f(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        grade, mult = engine.grade_and_multiplier(39)
        assert grade == "F" and mult == pytest.approx(0.10)

    def test_score_0_is_grade_f(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        grade, mult = engine.grade_and_multiplier(0)
        assert grade == "F" and mult == pytest.approx(0.10)


# ---------------------------------------------------------------------------
# assess() — integration
# ---------------------------------------------------------------------------

class TestAssess:
    def test_clean_agent_gets_score_100_grade_a(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        result = engine.assess("0xABCD", _all_clean(100.0))
        assert result.score == 100
        assert result.grade == "A"
        assert result.multiplier == pytest.approx(1.00)
        assert result.critical is False
        assert result.rated is True

    def test_critical_finding_caps_score_at_39(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        dims = _with_finding(_all_clean(100.0), "contract_security", "CRITICAL", "source unverified")
        result = engine.assess("0xBAD", dims)
        assert result.score == 39
        assert result.grade == "F"
        assert result.multiplier == pytest.approx(0.10)
        assert result.critical is True

    def test_unrated_dim_makes_result_unrated(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        from acpsec.trust_score.weights import UNRATED_MULTIPLIER
        engine = TrustScoreEngine()
        dims = _with_unrated(_all_clean(100.0), "behavioral")
        result = engine.assess("0xNEW", dims)
        assert result.rated is False
        assert result.multiplier == pytest.approx(UNRATED_MULTIPLIER)

    def test_subscores_populated_per_dimension(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        from acpsec.trust_score.weights import WEIGHTS
        engine = TrustScoreEngine()
        raw = {
            "contract_security": 60,
            "authority_scope": 45,
            "identity": 80,
            "hook_security": 70,
            "acp_compliance": 55,
            "behavioral": 65,
        }
        dims = [DimScore(name=k, score=raw[k], weight=v) for k, v in WEIGHTS.items()]
        result = engine.assess("0x1234", dims)
        assert {k: v.score for k, v in result.subscores.items()} == raw

    def test_subscores_carry_unrated_checks(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        from acpsec.trust_score.weights import WEIGHTS
        engine = TrustScoreEngine()
        dims = [DimScore(name=k, score=80, weight=v) for k, v in WEIGHTS.items()]
        dims[4].unrated_checks = ["fee_split_nonconformant"]
        result = engine.assess("0x1234", dims)
        assert result.subscores[dims[4].name].unrated_checks == ["fee_split_nonconformant"]
        assert result.subscores["contract_security"].unrated_checks == []

    def test_top_findings_included_in_result(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        dims = _with_finding(_all_clean(80.0), "authority_scope", "High", "single EOA withdrawal")
        dims = _with_finding(dims, "acp_compliance", "High", "no refund path")
        result = engine.assess("0x5678", dims)
        assert len(result.top_findings) == 2

    def test_top_findings_sorted_critical_first(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        dims = _with_finding(_all_clean(80.0), "authority_scope", "High", "single EOA")
        dims = _with_finding(dims, "contract_security", "CRITICAL", "source unverified")
        result = engine.assess("0x5678", dims)
        assert result.top_findings[0].severity == "CRITICAL"

    def test_agent_address_stored_in_result(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        result = engine.assess("0xDEAD", _all_clean())
        assert result.agent == "0xDEAD"

    def test_erc8004_id_stored_in_result(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        result = engine.assess("0xABCD", _all_clean(), erc8004_id="myagent.eth")
        assert result.erc8004_id == "myagent.eth"

    def test_scanned_at_is_utc_iso_string(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        result = engine.assess("0xABCD", _all_clean())
        assert result.scanned_at.endswith("Z") or "+" in result.scanned_at
        assert "T" in result.scanned_at

    def test_scanner_version_default(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        result = engine.assess("0xABCD", _all_clean())
        assert result.scanner_version.startswith("acpsec-")

    def test_critical_overrides_even_perfect_underlying_score(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        # Even with all dims at 100 (composite=100), a CRITICAL caps at 39
        dims = _with_finding(_all_clean(100.0), "hook_security", "CRITICAL", "unauthorized caller")
        result = engine.assess("0xBAD", dims)
        assert result.score == 39
        assert result.grade == "F"

    def test_unrated_overrides_score_grade_not_affected(self):
        from acpsec.trust_score.engine import TrustScoreEngine
        engine = TrustScoreEngine()
        # Unrated does not change score/grade — only rated flag and multiplier
        dims = _with_unrated(_all_clean(90.0), "identity")
        result = engine.assess("0xNEW", dims)
        assert result.rated is False
        assert result.multiplier == pytest.approx(0.50)
        # grade/score are still computed from available dims
        assert result.grade is not None
        assert result.score >= 0
