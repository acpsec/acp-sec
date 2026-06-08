"""Trust Score constants: dimension weights, grade bands, caps."""

from __future__ import annotations

WEIGHTS: dict[str, float] = {
    "contract_security": 0.25,
    "authority_scope":   0.20,
    "identity":          0.15,
    "hook_security":     0.15,
    "acp_compliance":    0.15,
    "behavioral":        0.10,
}

# Sorted descending by threshold — first match wins.
# (min_score_inclusive, grade_label, trust_multiplier)
GRADE_BANDS: list[tuple[int, str, float]] = [
    (90, "A", 1.00),
    (75, "B", 0.85),
    (60, "C", 0.60),
    (40, "D", 0.30),
    (0,  "F", 0.10),
]

CRITICAL_CAP: int = 39
UNRATED_MULTIPLIER: float = 0.50
