"""The five B20 Trust Score dimensions (pure, no I/O).

Each ``run_*`` reads a source-agnostic ``ScanInputs`` and returns a
``DimensionResult`` scored from 100 down. A dimension is ``rated=False`` when a
*load-bearing* input — the signal a High/critical finding turns on — could not
be read; a readable secondary sibling does NOT keep it rated (guarding against
the "absent -> infer" bug where a failed read is silently scored as a pass).
Each ``run_*`` documents its load-bearing input(s) inline. The engine then
excludes an unrated dimension from the weighted sum and applies the unrated
multiplier.

Penalty magnitudes are V1 judgment within the brief's high/medium/low bands and
are kept as named locals for easy tuning.
"""

from __future__ import annotations

import re

from .constants import DIMENSION_WEIGHTS, EFFECTIVELY_UNCAPPED_MIN, OFFICIAL_TOKENIZED_STOCKS
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

    # Load-bearing: the admin governance posture. The dominant single-EOA-admin
    # High (and the single-EOA-admin critical) turns on admin_is_multisig;
    # admin_roles_revoked=True is the clean-clear. Knowing only the holder count
    # (admin_holders) or the pause sub-signal cannot place the token on the
    # revoked > multisig > single-EOA ladder — so a readable sibling must NOT
    # keep the dimension rated when the governance posture itself is unknown.
    rated = inp.admin_is_multisig is not None or inp.admin_roles_revoked is not None

    # Admin governance quality: revoked (best) > multisig > single/EOA (worst).
    if inp.admin_roles_revoked is True:
        penalty += 0
    elif inp.admin_is_multisig is True:
        penalty += 10  # multisig still holds power, but distributed
    elif inp.admin_is_multisig is False:
        # High band: single-EOA admin is the worst non-critical authority state
        penalty += 55
        findings.append(Finding("High", "admin role controlled by a non-multisig EOA"))
        if inp.admin_is_delegated_eoa is True:
            # EIP-7702: the admin EOA has delegated to a smart-account impl. Honest
            # framing — a delegation is set and cleared by the key itself, so it is
            # STILL one key; it neither adds nor removes multisig protection.
            findings.append(Finding(
                "Info", "admin EOA carries an EIP-7702 smart-account delegation — still "
                        "a single key (the delegation is key-controlled and revocable)"))

    # Pause power held by a non-multisig EOA — explicit high-penalty item.
    if inp.pause_role_holders and inp.pause_holder_is_multisig is False:
        # High band: pause power on an EOA = unilateral kill switch over transfers
        penalty += 25
        findings.append(Finding("High", "pause power held by a non-multisig EOA"))

    # #69 mint-authority distribution. Mint is an authority question — a MINT_ROLE
    # holder can dilute holders up to the cap — so it composes here with the admin
    # governance ladder. The signal is EOA-ness + admin∩mint overlap, NOT count
    # (all 10 legit tokenized stocks = a single SEPARATED CONTRACT mint holder, so
    # count does not discriminate). Contributes only when mint holders are readable;
    # a silent zero-event token (mint_role_holders None or []) emits nothing and does
    # NOT newly unrate the dimension (#70 doctrine: silent != unread). Classification
    # is honest — mint_holders_eoa is eth_getCode-derived; findings say "non-multisig
    # EOA" / "not a bare EOA", never "safe" (a contract can be a single-key proxy).
    mint = inp.mint_role_holders
    if mint:
        eoa = inp.mint_holders_eoa                       # None=unclassified; []=all contracts
        eoa_set = {a.lower() for a in (eoa or [])}
        overlap = {m.lower() for m in mint} & {a.lower() for a in (inp.admin_holders or [])}

        if eoa_set:
            # High band: a bare (non-multisig EOA) mint key can unilaterally dilute
            # supply up to the cap. Verified status does NOT excuse a naked key.
            penalty += 25
            findings.append(Finding(
                "High", "mint role held by a non-multisig EOA (a bare key can dilute supply to the cap)"))
            if len(eoa_set) >= 2:
                # Medium band: multiple bare mint keys = larger key-compromise surface
                penalty += 10
                findings.append(Finding("Medium", "multiple mint keys held by non-multisig EOAs"))

        if overlap:
            # No separation of duties: one address holds mint AND admin. Worse when
            # that shared address is itself a bare EOA (a single naked key rules both).
            if overlap & eoa_set:
                penalty += 25
                findings.append(Finding(
                    "Medium", "a single EOA holds both mint and admin roles (no separation of duties)"))
            else:
                penalty += 15
                findings.append(Finding(
                    "Medium", "the same address holds both mint and admin roles (no separation of duties)"))
        elif inp.official_ticker_status == "verified" and eoa is not None and not eoa_set:
            # #55 verified gate: a separated CONTRACT mint on a verified 1:1-backed
            # tokenized stock is EXPECTED design -> Info, no penalty. "not a bare EOA"
            # is honest (a contract can still be a single-key proxy), never "safe".
            findings.append(Finding(
                "Info", "mint controlled by a separated contract key — expected for a "
                        "verified tokenized stock (not a bare EOA)"))

    return _result(name, penalty, rated, findings)


# --------------------------------------------------------------------------
# 2.5 Supply Integrity (0.25)
# --------------------------------------------------------------------------
def run_supply_integrity(inp: ScanInputs) -> DimensionResult:
    name = "supply_integrity"
    findings: list[Finding] = []
    penalty = 0

    # Load-bearing: supply_cap (the uncapped-mint High + critical driver). A None
    # here cannot be inferred safe, so the dimension is unrated regardless of the
    # secondary multiplier/burn signals. Note multiplier_active is legitimately
    # None for stablecoins (no rebasing multiplier), so it must NOT gate rating.
    rated = inp.supply_cap is not None

    # Effectively uncapped: cap in the top half of the uint128 range (#67). Severity
    # is gated on verification (#55): for a VERIFIED 1:1-backed tokenized stock,
    # uncapped supply is EXPECTED design -> surface it as INFO with context, no
    # penalty (honesty: report the fact, don't hide, don't penalize). For any other
    # issuer it is an unbounded-dilution risk -> High + penalty (and the engine's
    # uncapped-mint critical caps the composite).
    if inp.supply_cap is not None and inp.supply_cap >= EFFECTIVELY_UNCAPPED_MIN:
        if inp.official_ticker_status == "verified":
            findings.append(Finding(
                "Info",
                "uncapped supply — expected for a verified 1:1-backed tokenized stock "
                "(supply floats with custody)",
            ))
        else:
            penalty += 60
            findings.append(Finding(
                "High",
                "uncapped supply: cap in the top half of the uint128 range "
                "(effectively infinite mint)",
            ))

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

    # Load-bearing: the coercive-power capabilities plus the live pause state.
    # can_freeze + can_seize drive the freeze+seize High; is_paused drives the
    # "currently paused" High. A None in any of the three silently drops a High
    # finding (the observed live is_paused=None case), so all three must be known
    # for the dimension to be rated. The rest (policy_registry_active, can_pause,
    # memo_required, asymmetric_policy) are Medium/Low add-ons, not load-bearing.
    rated = (
        inp.can_freeze is not None
        and inp.can_seize is not None
        and inp.is_paused is not None
    )

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

    # Load-bearing: factory_is_official AND symbol. factory_is_official is only ever
    # True (official) or None (unverified) — rate iff verified. symbol is load-bearing
    # for the #66 impersonation check hosted here: if symbol() is unreadable (None
    # after retries) the check cannot run, so the dimension is UNRATED and the
    # uncertainty hits the score via the multiplier (same doctrine as #70
    # can_seize -> transfer_policy) — never grade a token whose identity we could not
    # verify. A readable symbol (verified / impersonation / non-ticker) keeps it rated.
    rated = inp.factory_is_official is not None and inp.symbol is not None

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

    # #66/#55 tokenized-stock impersonation. The engine's CRITICAL_IMPERSONATION cap
    # does the heavy score-drop (composite -> F); this is the itemized, evidence-
    # carrying finding (claimed ticker + expected official address), plus a positive
    # signal for a verified official token.
    if inp.official_ticker_status == "impersonation":
        ticker = (inp.symbol or "").strip().upper()
        pinned = OFFICIAL_TOKENIZED_STOCKS.get(inp.chain_id, {}).get(ticker)
        if pinned:
            detail = (f"impersonation: symbol '{inp.symbol}' claims official tokenized stock "
                      f"{ticker}, but the official {ticker} is {pinned} on chain {inp.chain_id} "
                      f"(this token is {inp.token})")
        else:
            detail = (f"impersonation: symbol '{inp.symbol}' claims official tokenized stock "
                      f"{ticker}, but no official {ticker} is issued on chain {inp.chain_id}")
        penalty += 20
        findings.append(Finding("High", detail))
    elif inp.official_ticker_status == "verified":
        findings.append(Finding("Info", f"verified official Coinbase tokenized stock ({inp.symbol})"))

    return _result(name, penalty, rated, findings)


# --------------------------------------------------------------------------
# 2.8 Origin & Transparency (0.10)
# --------------------------------------------------------------------------
def run_origin_transparency(inp: ScanInputs) -> DimensionResult:
    name = "origin_transparency"
    findings: list[Finding] = []
    penalty = 0

    # Load-bearing: the two inputs the reader actually reads on-chain
    # (issuer_has_history from tx-count, announcement_events from logs). The other
    # three (issuer_wallet_age_days, verified_entity, public_docs) are
    # un-implemented placeholders the reader always leaves None — keying rated on
    # them would make this dimension permanently unrated. This is the lowest-
    # stakes dimension (no High/critical), but the no-infer discipline is the
    # same: rate only when both real reads land.
    # #68: announcements_substantive is the load-bearing announcement signal (not the
    # raw count) — None means the read failed. issuer_has_history is the other read.
    rated = inp.issuer_has_history is not None and inp.announcements_substantive is not None

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

    # #68 announcement substance. Issuer self-attestation the scanner can't verify:
    # >=1 SUBSTANTIVE announcement lifts the "no disclosure" penalty (never a bonus
    # above baseline); junk (empty/duplicate/too short) is neutral. For a VERIFIED
    # 1:1-backed stock, absence is expected (discloses via regulated off-chain
    # channels) -> Info, no penalty (#55 gate). Content is surfaced in
    # evidence.announcements so consumers can read what the issuer claimed.
    sub = inp.announcements_substantive
    tot = inp.announcements_total
    if sub is not None:
        if sub >= 1:
            pass  # substantive disclosure present — absence penalty lifted
        elif inp.official_ticker_status == "verified":
            findings.append(Finding(
                "Info",
                "no substantive on-chain announcements — expected for a verified "
                "tokenized stock (discloses via regulated off-chain channels)",
            ))
        elif tot and tot > 0:
            penalty += 10
            findings.append(Finding(
                "Low",
                f"{tot} announcements, none substantive (empty/duplicate/too short)",
            ))
        else:
            penalty += 10
            findings.append(Finding("Low", "no on-chain announcements"))

    return _result(name, penalty, rated, findings)


# Ordered registry the engine iterates (weight order, high to low).
DIMENSION_RUNNERS = (
    run_issuer_authority,
    run_supply_integrity,
    run_transfer_policy,
    run_variant_config,
    run_origin_transparency,
)
