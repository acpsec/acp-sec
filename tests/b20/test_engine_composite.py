"""Raw composite, multiplier helpers, grade bands (task 2.1, resolved schema)."""

from acpsec_api.b20.constants import DIMENSION_WEIGHTS
from acpsec_api.b20.engine import (
    assess,
    grade_for,
    multiplier_for,
    raw_composite,
    unrated_dimension_names,
)
from acpsec_api.b20.models import DimensionResult, ScanInputs


def _dims(scores: dict[str, float], unrated: set[str] = frozenset()) -> list[DimensionResult]:
    return [
        DimensionResult(name=n, score=scores[n], weight=DIMENSION_WEIGHTS[n], rated=(n not in unrated))
        for n in DIMENSION_WEIGHTS
    ]


_SCORES = {
    "issuer_authority": 80, "supply_integrity": 90, "transfer_policy": 70,
    "variant_config": 85, "origin_transparency": 60,
}


def test_raw_composite_is_weighted_sum_no_multiplier():
    # 0.30*80 + 0.25*90 + 0.20*70 + 0.15*85 + 0.10*60 = 79.25 -> 79
    assert raw_composite(_dims(_SCORES)) == 79


def test_raw_composite_excludes_unrated_but_does_not_halve():
    # origin (0.10, 60) unrated -> sum over rated = 73.25 -> 73 (NO multiplier here)
    assert raw_composite(_dims(_SCORES, unrated={"origin_transparency"})) == 73


def test_raw_composite_floors_at_zero():
    assert raw_composite(_dims({n: 0 for n in DIMENSION_WEIGHTS})) == 0


def test_multiplier_is_one_when_all_rated():
    assert multiplier_for(_dims(_SCORES)) == 1.0


def test_multiplier_is_half_when_any_unrated():
    assert multiplier_for(_dims(_SCORES, unrated={"origin_transparency"})) == 0.5


def test_unrated_dimension_names():
    dims = _dims(_SCORES, unrated={"origin_transparency", "transfer_policy"})
    assert set(unrated_dimension_names(dims)) == {"origin_transparency", "transfer_policy"}
    assert unrated_dimension_names(_dims(_SCORES)) == []


def test_grade_bands():
    assert grade_for(100) == "A"
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(75) == "B"
    assert grade_for(74) == "C"
    assert grade_for(60) == "C"
    assert grade_for(59) == "D"
    assert grade_for(40) == "D"
    assert grade_for(39) == "F"
    assert grade_for(0) == "F"


def test_grade_band_edge_via_assess():
    # Exact grade_for() band edges (75/74/60/59/40/39) are covered above. This
    # confirms the full assess() pipeline derives the grade from the FINAL
    # trust_score, not raw_score, when the unrated multiplier crosses a band edge.
    inp = ScanInputs(
        token="0xB200", chain_id=8453, variant="ASSET", decimals=18,
        admin_is_multisig=True, supply_cap=10**24,
        can_freeze=False, can_seize=False, can_pause=False, is_paused=False,
        policy_registry_active=False, memo_required=False, asymmetric_policy=False,
        factory_is_official=True,
        # origin_transparency left fully unknown -> unrated -> x0.5 multiplier
    )
    d = assess(inp, scanned_at="2026-06-22T00:00:00Z").to_dict()
    assert d["raw_score"] == 87                        # 0.30*90+0.25*100+0.20*100+0.15*100
    assert grade_for(d["raw_score"]) == "B"            # raw alone is a B
    assert d["trust_score"] == 44                      # round(87 * 0.5)
    assert d["grade"] == "D"                           # final lands in D
    assert d["grade"] == grade_for(d["trust_score"])   # grade follows the final score
    assert d["grade"] != grade_for(d["raw_score"])     # ...not the raw score
