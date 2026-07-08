"""B20 Trust Score composite engine.

Pure, no I/O. Composes dimension results into a composite score, applies the
unrated multiplier and (in ``assess``) the critical cap, and assigns a grade.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import __version__
from .constants import CRITICAL_CAP, GRADE_BANDS, UINT128_MAX, UNRATED_MULTIPLIER
from .dimensions import DIMENSION_RUNNERS
from .models import DimensionResult, IssuerPowers, ScanInputs, ScanResult

# Stable critical-reason identifiers (prefix : human-readable detail).
CRITICAL_UNCAPPED_MINT = "uncapped_mint: supply cap equals type(uint128).max (infinite mint)"
CRITICAL_NON_OFFICIAL_FACTORY = "non_official_factory: token not deployed via the official B20 factory"
CRITICAL_SINGLE_EOA_ADMIN = "single_eoa_admin: DEFAULT_ADMIN_ROLE held by a single EOA without multisig"


def detect_critical(inputs: ScanInputs) -> list[str]:
    """Return the critical-condition reasons that hold for these inputs.

    Conservative on unknowns: a condition is asserted only when the relevant
    inputs are known (not None). Unknown values lower confidence via the
    unrated multiplier elsewhere; they never *assert* a critical condition.
    """
    reasons: list[str] = []

    # (a) Infinite/uncapped mint — supply cap equals the no-cap sentinel.
    if inputs.supply_cap is not None and inputs.supply_cap == UINT128_MAX:
        reasons.append(CRITICAL_UNCAPPED_MINT)

    # (b) Not deployed via the exact official factory.
    if inputs.factory_is_official is False:
        reasons.append(CRITICAL_NON_OFFICIAL_FACTORY)

    # (c) Single-EOA admin without multisig.
    if (
        inputs.admin_holders is not None
        and len(inputs.admin_holders) == 1
        and inputs.admin_is_multisig is False
    ):
        reasons.append(CRITICAL_SINGLE_EOA_ADMIN)

    return reasons


def apply_critical_cap(score: int, *, critical: bool) -> int:
    """Cap the composite at CRITICAL_CAP (39) when any critical condition holds.

    Uses min() per the brief's "forces composite <= 39"; a critical token never
    scores above 39 (grade F) but keeps a lower score if it already had one.
    """
    return min(score, CRITICAL_CAP) if critical else score


def grade_for(score: int) -> str:
    """Map a 0-100 score to an A-F grade using the (descending) grade bands."""
    for min_score, grade in GRADE_BANDS:
        if score >= min_score:
            return grade
    return "F"


def _raw_sum(dims: list[DimensionResult]) -> float:
    """Exact weighted sum over rated dimensions (unrated contribute no weight)."""
    return sum(d.score * d.weight for d in dims if d.rated)


def raw_composite(dims: list[DimensionResult]) -> int:
    """The composite BEFORE any multiplier: rounded weighted sum, floored at 0."""
    return max(0, int(round(_raw_sum(dims))))


def multiplier_for(dims: list[DimensionResult]) -> float:
    """1.0 when every dimension is rated; UNRATED_MULTIPLIER (0.50) otherwise."""
    return UNRATED_MULTIPLIER if any(not d.rated for d in dims) else 1.0


def unrated_dimension_names(dims: list[DimensionResult]) -> list[str]:
    """Names of dimensions that could not be rated (empty when all rated)."""
    return [d.name for d in dims if not d.rated]


def _issuer_powers(inp: ScanInputs) -> IssuerPowers:
    can_mint_unbounded = (
        None if inp.supply_cap is None else inp.supply_cap == UINT128_MAX
    )
    return IssuerPowers(
        can_freeze=inp.can_freeze,
        can_seize=inp.can_seize,
        can_pause=inp.can_pause,
        can_mint_unbounded=can_mint_unbounded,
        supply_cap=None if inp.supply_cap is None else str(inp.supply_cap),
        admin_addresses=list(inp.admin_holders or []),
        admin_is_multisig=inp.admin_is_multisig,
        mint_role_holders=list(inp.mint_role_holders or []),
        pause_role_holders=list(inp.pause_role_holders or []),
    )


def assess(
    inputs: ScanInputs,
    *,
    scanned_at: str | None = None,
    scanner_version: str = __version__,
) -> ScanResult:
    """Run all five dimensions and assemble the canonical scan result.

    Final score = the more conservative (lower) of the critical-capped score and
    the multiplier-adjusted score: min( cap(raw), raw x multiplier ), where
    cap(x) = min(x, CRITICAL_CAP) when any critical condition holds. Both the
    final ``trust_score`` and the pre-multiplier ``raw_score`` are surfaced.
    """
    dims = [run(inputs) for run in DIMENSION_RUNNERS]

    critical_reasons = detect_critical(inputs)
    is_critical = bool(critical_reasons)

    raw_exact = _raw_sum(dims)
    raw_score = max(0, int(round(raw_exact)))
    multiplier = multiplier_for(dims)

    capped_exact = min(raw_exact, CRITICAL_CAP) if is_critical else raw_exact
    multiplied_exact = raw_exact * multiplier
    trust_score = max(0, int(round(min(capped_exact, multiplied_exact))))

    grade = grade_for(trust_score)
    unrated = unrated_dimension_names(dims)
    rated = not unrated

    if scanned_at is None:
        scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return ScanResult(
        token=inputs.token,
        chain_id=inputs.chain_id,
        variant=inputs.variant,
        name=inputs.name,
        symbol=inputs.symbol,
        decimals=inputs.decimals,
        currency_code=inputs.currency_code,
        trust_score=trust_score,
        raw_score=raw_score,
        grade=grade,
        is_critical=is_critical,
        critical_reasons=critical_reasons,
        rated=rated,
        multiplier=multiplier,
        unrated_dimensions=unrated,
        dimensions={d.name: d for d in dims},
        issuer_powers=_issuer_powers(inputs),
        deployed_via_factory=inputs.deployed_via_factory,
        scanner_version=scanner_version,
        scanned_at=scanned_at,
    )
