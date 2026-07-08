"""The five B20 Trust Score dimensions (pure, no I/O).

Each ``run_*`` reads a source-agnostic ``ScanInputs`` and returns a
``DimensionResult`` scored from 100 down. A dimension is ``rated=False`` when
none of its inputs could be read (all None); the engine then excludes it from
the weighted sum and applies the unrated multiplier.

Penalty magnitudes are V1 judgment within the brief's high/medium/low bands and
are kept as named locals for easy tuning.
"""

from __future__ import annotations

import re

from .constants import DIMENSION_WEIGHTS, UINT128_MAX
from .models import DimensionResult, Finding, ScanInputs

_CURRENCY_CODE_RE = re.compile(r"[A-Z]+")


def _result(name: str, penalty: int, rated: bool, findings: list[Finding]) -> DimensionResult:
    return DimensionResult(
        name=name,
        score=float(max(0, 100 - penalty)),
        weight=DIMENSION_WEIGHTS[name],
        rated=rated,
        findings=findings,
    )


# --------------------------------------------------------------------------
# 2.4 Issuer Authority (0.30)
# --------------------------------------------------------------------------
def run_issuer_authority(inp: ScanInputs) -> DimensionResult:
    name = "issuer_authority"
    findings: list[Finding] = []
    penalty = 0

    rated = any(v is not None for v in (
        inp.admin_roles_revoked, inp.admin_is_multisig,
        inp.admin_holders, inp.pause_role_holders,
    ))

    # Admin governance quality: revoked (best) > multisig > single/EOA (worst).
    if inp.admin_roles_revoked is True:
        penalty += 0
    elif inp.admin_is_multisig is True:
        penalty += 10  # multisig still holds power, but distributed
    elif inp.admin_is_multisig is False:
        # High band: single-EOA admin is the worst non-critical authority state
        penalty += 55
        findings.append(Finding("High", "admin role controlled by a non-multisig EOA"))

    # Pause power held by a non-multisig EOA — explicit high-penalty item.
    if inp.pause_role_holders and inp.pause_holder_is_multisig is False:
        # High band: pause power on an EOA = unilateral kill switch over transfers
        penalty += 25
        findings.append(Finding("High", "pause power held by a non-multisig EOA"))

    return _result(name, penalty, rated, findings)


# --------------------------------------------------------------------------
# 2.5 Supply Integrity (0.25)
# --------------------------------------------------------------------------
def run_supply_integrity(inp: ScanInputs) -> DimensionResult:
    name = "supply_integrity"
    findings: list[Finding] = []
    penalty = 0

    rated = any(v is not None for v in (
        inp.supply_cap, inp.multiplier_active, inp.burn_enabled,
    ))

    if inp.supply_cap is not None and inp.supply_cap == UINT128_MAX:
        # High band: uncapped supply lets the issuer dilute holders without limit
        # (also trips the uncapped-mint critical condition, which caps composite)
        penalty += 60
        findings.append(Finding("High", "uncapped supply: cap equals type(uint128).max (infinite mint)"))

    if inp.multiplier_active is True:
        # Medium band: a rebasing multiplier can silently change holder balances
        penalty += 15
        findings.append(Finding("Medium", "rebasing multiplier is active"))

    if inp.burn_enabled is True:
        penalty += 10
        findings.append(Finding("Low", "burn is enabled"))

    return _result(name, penalty, rated, findings)


# --------------------------------------------------------------------------
# 2.6 Transfer Policy Risk (0.20)
# --------------------------------------------------------------------------
def run_transfer_policy(inp: ScanInputs) -> DimensionResult:
    name = "transfer_policy"
    findings: list[Finding] = []
    penalty = 0

    rated = any(v is not None for v in (
        inp.policy_registry_active, inp.can_freeze, inp.can_seize, inp.can_pause,
        inp.is_paused, inp.memo_required, inp.asymmetric_policy,
    ))

    freeze = inp.can_freeze is True
    seize = inp.can_seize is True
    transparency = inp.public_docs is True or inp.verified_entity is True

    if freeze and seize:
        if not transparency:
            # High band: freeze+seize without disclosure = opaque issuer power over funds
            penalty += 40
            findings.append(Finding("High", "freeze+seize active with no public issuer docs / transparency"))
        else:
            # Medium band: freeze+seize is disclosed, so the power is at least transparent
            penalty += 20
            findings.append(Finding("Medium", "freeze+seize active (disclosed)"))
    else:
        if freeze:
            # Medium band: freeze alone can lock funds but not take them
            penalty += 15
            findings.append(Finding("Medium", "freeze capability active"))
        if seize:
            # Medium band: seize capability is a direct holder-fund risk
            penalty += 15
            findings.append(Finding("Medium", "seize capability active"))

    if inp.can_pause is True:
        penalty += 10
        findings.append(Finding("Medium", "pause capability present"))
    if inp.is_paused is True:
        # High band: token is actively paused right now — transfers are blocked
        penalty += 15
        findings.append(Finding("High", "token is currently paused"))

    if inp.policy_registry_active is True:
        penalty += 10
        findings.append(Finding("Medium", "PolicyRegistry active (transfers gated)"))
    if inp.asymmetric_policy is True:
        penalty += 10
        findings.append(Finding("Medium", "asymmetric transfer policy (block-only vs allow-only)"))
    if inp.memo_required is True:
        penalty += 5
        findings.append(Finding("Low", "memo required on transfers"))

    return _result(name, penalty, rated, findings)


# --------------------------------------------------------------------------
# 2.7 Variant & Config (0.15)
# --------------------------------------------------------------------------
def run_variant_config(inp: ScanInputs) -> DimensionResult:
    name = "variant_config"
    findings: list[Finding] = []
    penalty = 0

    rated = any(v is not None for v in (
        inp.variant, inp.decimals, inp.currency_code,
        inp.factory_is_official, inp.deployed_via_factory,
    ))

    if inp.factory_is_official is False:
        # High band: non-official factory = potential spoof / unrecognized issuer
        penalty += 60
        findings.append(Finding("High", "not deployed via the official B20 factory"))

    if inp.variant == "ASSET":
        if inp.decimals is not None and not (6 <= inp.decimals <= 18):
            # Medium band: decimals outside the Asset 6-18 range signal misconfiguration
            penalty += 20
            findings.append(Finding("Medium", "decimals out of range (expected 6-18) for Asset variant"))
    elif inp.variant == "STABLECOIN":
        if inp.decimals is not None and inp.decimals != 6:
            # Medium band: a Stablecoin must use exactly 6 decimals
            penalty += 20
            findings.append(Finding("Medium", "Stablecoin decimals must be 6"))
        if inp.currency_code is not None and not _CURRENCY_CODE_RE.fullmatch(inp.currency_code):
            # Medium band: a malformed currency code signals misconfiguration
            penalty += 15
            findings.append(Finding("Medium", "invalid Stablecoin currency code (must be uppercase A-Z)"))

    return _result(name, penalty, rated, findings)


# --------------------------------------------------------------------------
# 2.8 Origin & Transparency (0.10)
# --------------------------------------------------------------------------
def run_origin_transparency(inp: ScanInputs) -> DimensionResult:
    name = "origin_transparency"
    findings: list[Finding] = []
    penalty = 0

    rated = any(v is not None for v in (
        inp.issuer_wallet_age_days, inp.issuer_has_history,
        inp.verified_entity, inp.public_docs, inp.announcement_events,
    ))

    if inp.issuer_wallet_age_days is not None and inp.issuer_wallet_age_days < 30:
        # Medium band: a fresh issuer wallet has no track record
        penalty += 20
        findings.append(Finding("Medium", "fresh issuer wallet (< 30 days old)"))
    if inp.issuer_has_history is False:
        penalty += 10
        findings.append(Finding("Low", "issuer wallet has no prior history"))
    if inp.public_docs is False:
        # Medium band: no public docs reduces issuer accountability
        penalty += 15
        findings.append(Finding("Medium", "no public issuer documentation"))
    if inp.announcement_events is False:
        penalty += 10
        findings.append(Finding("Low", "no on-chain announcement events"))

    return _result(name, penalty, rated, findings)


# Ordered registry the engine iterates (weight order, high to low).
DIMENSION_RUNNERS = (
    run_issuer_authority,
    run_supply_integrity,
    run_transfer_policy,
    run_variant_config,
    run_origin_transparency,
)
