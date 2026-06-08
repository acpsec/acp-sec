"""Tests for acpsec/trust_score/weights.py — written before implementation (TDD RED)."""

import pytest


class TestWeights:
    def test_weights_has_six_dimensions(self):
        from acpsec.trust_score.weights import WEIGHTS
        assert len(WEIGHTS) == 6

    def test_weights_sum_to_one(self):
        from acpsec.trust_score.weights import WEIGHTS
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

    def test_weights_has_all_required_dimension_keys(self):
        from acpsec.trust_score.weights import WEIGHTS
        expected = {
            "contract_security",
            "authority_scope",
            "identity",
            "hook_security",
            "acp_compliance",
            "behavioral",
        }
        assert set(WEIGHTS.keys()) == expected

    def test_contract_security_weight_is_0_25(self):
        from acpsec.trust_score.weights import WEIGHTS
        assert WEIGHTS["contract_security"] == pytest.approx(0.25)

    def test_authority_scope_weight_is_0_20(self):
        from acpsec.trust_score.weights import WEIGHTS
        assert WEIGHTS["authority_scope"] == pytest.approx(0.20)

    def test_behavioral_weight_is_0_10(self):
        from acpsec.trust_score.weights import WEIGHTS
        assert WEIGHTS["behavioral"] == pytest.approx(0.10)


class TestCriticalCap:
    def test_critical_cap_is_39(self):
        from acpsec.trust_score.weights import CRITICAL_CAP
        assert CRITICAL_CAP == 39

    def test_unrated_multiplier_is_0_50(self):
        from acpsec.trust_score.weights import UNRATED_MULTIPLIER
        assert UNRATED_MULTIPLIER == pytest.approx(0.50)


class TestGradeBands:
    def _lookup(self, score: int):
        from acpsec.trust_score.weights import GRADE_BANDS
        for min_score, grade, multiplier in GRADE_BANDS:
            if score >= min_score:
                return grade, multiplier
        raise ValueError(f"No band for score {score}")

    def test_grade_a_at_90(self):
        grade, mult = self._lookup(90)
        assert grade == "A"
        assert mult == pytest.approx(1.00)

    def test_grade_a_at_100(self):
        grade, mult = self._lookup(100)
        assert grade == "A"
        assert mult == pytest.approx(1.00)

    def test_grade_b_at_75(self):
        grade, mult = self._lookup(75)
        assert grade == "B"
        assert mult == pytest.approx(0.85)

    def test_grade_b_at_89(self):
        grade, mult = self._lookup(89)
        assert grade == "B"
        assert mult == pytest.approx(0.85)

    def test_grade_c_at_60(self):
        grade, mult = self._lookup(60)
        assert grade == "C"
        assert mult == pytest.approx(0.60)

    def test_grade_c_at_74(self):
        grade, mult = self._lookup(74)
        assert grade == "C"
        assert mult == pytest.approx(0.60)

    def test_grade_d_at_40(self):
        grade, mult = self._lookup(40)
        assert grade == "D"
        assert mult == pytest.approx(0.30)

    def test_grade_d_at_59(self):
        grade, mult = self._lookup(59)
        assert grade == "D"
        assert mult == pytest.approx(0.30)

    def test_grade_f_at_39(self):
        grade, mult = self._lookup(39)
        assert grade == "F"
        assert mult == pytest.approx(0.10)

    def test_grade_f_at_0(self):
        grade, mult = self._lookup(0)
        assert grade == "F"
        assert mult == pytest.approx(0.10)

    def test_critical_cap_score_lands_in_grade_f(self):
        from acpsec.trust_score.weights import CRITICAL_CAP
        grade, mult = self._lookup(CRITICAL_CAP)
        assert grade == "F"
        assert mult == pytest.approx(0.10)

    def test_grade_bands_sorted_descending(self):
        from acpsec.trust_score.weights import GRADE_BANDS
        thresholds = [min_score for min_score, _, _ in GRADE_BANDS]
        assert thresholds == sorted(thresholds, reverse=True)

    def test_grade_bands_cover_full_range_no_gaps(self):
        from acpsec.trust_score.weights import GRADE_BANDS
        # Every integer 0-100 must match exactly one band
        for score in range(101):
            matched = [
                (g, m)
                for min_score, g, m in GRADE_BANDS
                if score >= min_score
            ]
            assert len(matched) >= 1, f"Score {score} has no band"
