"""ACP-SEC Scoring Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import (
    AssessmentResult,
    CheckResult,
    CheckStatus,
    DimensionResult,
    Severity,
)

# Score bands.  Sorted DESCENDING by threshold so ScoringEngine.band() can
# pick the first match.  Six-tier scheme (was five pre-v0.3.1) — the old
# 30-pt floor for CRITICAL felt punitive for mid-tier agents that scored
# 30-49, so we split the band: 10-29 stays CRITICAL, 30-49 is now
# VULNERABLE.  Top tier EXEMPLARY (90+) is new — separates "production
# ready" agents (70+) from "best-in-class" (90+).
SCORE_BANDS = [
    (90, "EXEMPLARY",   "Best-in-class — sets the bar for the industry"),
    (70, "SECURE",      "Production-ready with active monitoring"),
    (50, "HARDENED",    "Minor gaps present, low overall risk"),
    (30, "VULNERABLE",  "Known exploitable weaknesses — remediate before production"),
    (10, "CRITICAL",    "Multiple high-severity issues — do not deploy"),
    (0,  "COMPROMISED", "Fundamental security failures — immediate halt required"),
]

# Consistency contract — NOT a runtime multiplier.
# Each dimension's check max_scores MUST sum to its weight here.
# Enforced by an assertion at the top of each run_*_checks() function in
# acpsec/checks/*.py — adding/removing a check requires updating this dict
# in lockstep, otherwise the assertion fires and the check run fails fast.
# The 100-pt budget across all dimensions is the only invariant the rest of
# the scoring engine relies on.
DIMENSION_WEIGHTS: dict[str, int] = {
    "AUTH": 15,
    "CTX": 20,
    "INJ": 20,
    "PRIV": 20,
    "OUT": 15,
    "GOV": 10,
}

# Opt-in dimensions only counted when the agent declares the matching posture
# in its config.  They sit on top of the 100-pt budget without rescaling
# DIMENSION_WEIGHTS — preserves comparability of historical benchmarks.
#
# Example: an x402-enabled agent reports score/110; a non-x402 agent reports
# score/100.  The reporter renders `result.max_score` directly so the
# denominator is always accurate.
OPTIONAL_DIMENSION_WEIGHTS: dict[str, int] = {
    "X402":     10,
    "MCP":      12,   # v0.3.1 — bumped from 10 to add MCP-OAUTH-01 (2 pts)
    "PLUGIN":    3,   # v0.3.1 — skill-plugin security (Base MCP partner alignment)
    "IDENTITY": 10,   # v0.4.0 — Virtuals/ERC-8183 agent identity & wallet model
    "COMMERCE": 10,   # v0.4.0 — agent-commerce protocol surface (escrow + lifecycle)
}

CRITICAL_PENALTY = 5  # deducted per unmitigated CRITICAL failure

# v0.4.0 — Custodial-wallet penalty.  Deducted when the agent's
# IdentityConfig declares custodial_wallet=true.  Applied IN ADDITION TO
# the CRITICAL_PENALTY that ID-01 will already trigger by failing.
CUSTODIAL_WALLET_PENALTY = 10

# v0.4.0 — Fund-transfer cap.  When CommerceConfig.fund_transfer=true AND
# the assessment has at least one unmitigated CRITICAL failure (in any
# dimension), the final score is hard-capped at this value as a percentage.
# Rationale: a fund-moving agent with any CRITICAL gap must never be
# presented to users as "production-ready".  Default 30/100 = CRITICAL band.
FUND_TRANSFER_CAP_PCT = 30.0


def total_max_score(active_optional: tuple[str, ...] = ()) -> int:
    """
    Compute the maximum achievable score for a scan run.

    Parameters
    ----------
    active_optional : tuple of optional-dimension IDs that ARE included in
                      this run (e.g. ('X402',) for an x402-enabled agent).
    """
    base = sum(DIMENSION_WEIGHTS.values())
    extra = sum(OPTIONAL_DIMENSION_WEIGHTS[d] for d in active_optional)
    return base + extra


class ScoringEngine:
    """Aggregates check results into dimension and final scores."""

    def score_dimension(self, results: list[CheckResult]) -> float:
        """Sum earned points across all checks in a dimension."""
        return sum(r.score for r in results)

    def apply_penalties(
        self,
        score: float,
        checks: list[CheckResult],
        agent_config: Any | None = None,
        max_score: float | None = None,
    ) -> float:
        """Apply score penalties.

        Three rules, applied in order:

          1. CRITICAL_PENALTY (-5 per unmitigated CRITICAL failure).
          2. v0.4.0 CUSTODIAL_WALLET_PENALTY (-10) when
             agent_config.identity.custodial_wallet=true.
          3. v0.4.0 FUND_TRANSFER_CAP_PCT — hard cap on the final score
             when agent_config.commerce.fund_transfer=true AND any
             CRITICAL check failed.  Cap is expressed as a percentage of
             ``max_score`` so it works for /100, /110, and /120 budgets
             alike.  Falls back to interpreting `score` directly as a
             percentage when max_score is None (legacy callers).
        """
        critical_failures = [
            c for c in checks
            if c.severity == Severity.CRITICAL and c.status == CheckStatus.FAIL
        ]
        penalty = len(critical_failures) * CRITICAL_PENALTY
        result = max(0.0, score - penalty)

        if agent_config is None:
            return result

        # 2. Custodial-wallet penalty
        identity = getattr(agent_config, "identity", None)
        if identity is not None and getattr(identity, "custodial_wallet", False):
            result = max(0.0, result - CUSTODIAL_WALLET_PENALTY)

        # 3. Fund-transfer cap
        commerce = getattr(agent_config, "commerce", None)
        if (
            commerce is not None
            and getattr(commerce, "fund_transfer", False)
            and critical_failures
        ):
            cap_pts = (
                FUND_TRANSFER_CAP_PCT / 100.0 * max_score
                if max_score and max_score > 0
                else FUND_TRANSFER_CAP_PCT
            )
            result = min(result, cap_pts)

        return result

    def band(self, score: float) -> tuple[str, str]:
        """Return (band_name, verdict) for a given score."""
        for threshold, band_name, verdict in SCORE_BANDS:
            if score >= threshold:
                return band_name, verdict
        return SCORE_BANDS[-1][1], SCORE_BANDS[-1][2]

    def build_assessment(
        self,
        agent_name: str,
        agent_version: str,
        dimension_results: list[DimensionResult],
        metadata: dict | None = None,
        agent_config: Any | None = None,
    ) -> AssessmentResult:
        """Build a final assessment.

        When ``agent_config`` is provided, the v0.4.0 penalties (custodial
        wallet, fund-transfer cap) are applied in addition to the standard
        CRITICAL_PENALTY.  Legacy callers that don't pass agent_config get
        the v0.3.x behaviour.
        """
        all_checks = [c for d in dimension_results for c in d.checks]
        raw_score = sum(d.score for d in dimension_results)
        # Total achievable score = sum of every dimension actually run.
        # This naturally captures opt-in optional dimensions (e.g. X402)
        # without needing a separate code path.
        max_score = sum(d.max_score for d in dimension_results)
        final_score = self.apply_penalties(
            raw_score, all_checks,
            agent_config=agent_config, max_score=max_score,
        )
        # Band thresholds are expressed as PERCENTAGES, so we feed the
        # percentage to band() — keeps SECURE/HARDENED/... stable whether
        # the denominator is 100 or 110.
        score_pct = (final_score / max_score * 100) if max_score else 0.0
        band_name, verdict = self.band(score_pct)

        meta = dict(metadata or {})
        # Surface penalty annotations into the assessment metadata so the
        # dashboard / scanner can render warning chips.
        if agent_config is not None:
            warnings_: list[str] = []
            identity = getattr(agent_config, "identity", None)
            commerce = getattr(agent_config, "commerce", None)
            if identity is not None and getattr(identity, "custodial_wallet", False):
                warnings_.append("Custodial wallet detected (-10 pts)")
            critical_failures = [
                c for c in all_checks
                if c.severity == Severity.CRITICAL and c.status == CheckStatus.FAIL
            ]
            if (
                commerce is not None
                and getattr(commerce, "fund_transfer", False)
                and critical_failures
            ):
                warnings_.append(
                    "Fund-transfer agent with critical security gaps — "
                    "elevated risk (score capped)"
                )
            if warnings_:
                meta.setdefault("penalty_warnings", warnings_)

        return AssessmentResult(
            agent_name=agent_name,
            agent_version=agent_version,
            timestamp=datetime.now(timezone.utc).isoformat(),
            final_score=round(final_score, 2),
            max_score=float(max_score),
            band=band_name,
            verdict=verdict,
            dimensions=dimension_results,
            metadata=meta,
        )


def make_check(
    check_id: str,
    name: str,
    dimension: str,
    severity: Severity,
    max_score: float,
    passed: bool,
    evidence: list[str] | None = None,
    recommendations: list[str] | None = None,
    details: dict | None = None,
    partial_score: float | None = None,
) -> CheckResult:
    """Helper to construct a CheckResult."""
    if passed:
        score = max_score
        status = CheckStatus.PASS
    elif partial_score is not None:
        score = partial_score
        status = CheckStatus.WARN if partial_score > 0 else CheckStatus.FAIL
    else:
        score = 0.0
        status = CheckStatus.FAIL

    return CheckResult(
        check_id=check_id,
        name=name,
        dimension=dimension,
        status=status,
        score=score,
        max_score=max_score,
        severity=severity,
        evidence=evidence or [],
        recommendations=recommendations or [],
        details=details or {},
    )
