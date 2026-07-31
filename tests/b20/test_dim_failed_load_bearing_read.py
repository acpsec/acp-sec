"""A failed *load-bearing* read must UNRATE the dimension — never score it as a pass.

Regression tests for the "absent -> infer" bug: the old ``rated = any(inp is not
None ...)`` predicate let a readable *sibling* input keep a dimension "rated"
while its load-bearing signal (the one a High/critical finding turns on) failed
to read. The per-input finding was then silently skipped, so the dimension
scored 100 and — the dangerous end state — an uncapped-mint token that should be
grade F was graded A the moment its supplyCap read failed.

House rule: absent -> skip / unrated, never infer. Each dimension is rated only
when its *load-bearing* input(s) are known; a None there marks the dimension
unrated (dropped from the weighted sum, trips the unrated multiplier, and is
listed in ``unrated_dimensions``) rather than counting as a passing 100.
"""

from acpsec_api.b20.dimensions import (
    run_issuer_authority,
    run_origin_transparency,
    run_supply_integrity,
    run_transfer_policy,
    run_variant_config,
)
from acpsec_api.b20.engine import assess
from acpsec_api.b20.models import ScanInputs


def _inp(**kw) -> ScanInputs:
    return ScanInputs(token="0xB200", chain_id=8453, **kw)


# --------------------------------------------------------------------------
# Dimension-level: a failed load-bearing read + a readable sibling -> UNRATED
# (each case is rated=True under the old any() predicate — that is the bug).
# --------------------------------------------------------------------------
def test_supply_unrated_when_cap_read_fails_though_multiplier_read_succeeds():
    # supply_cap (uncapped-mint High+critical) is load-bearing; multiplier_active
    # is a readable sibling that must NOT keep the dimension rated.
    r = run_supply_integrity(_inp(supply_cap=None, multiplier_active=False))
    assert r.rated is False


def test_issuer_unrated_when_admin_class_read_fails_though_holders_read_succeeds():
    # Knowing there is one admin (holders) but not whether it is a multisig or
    # revoked cannot rate the single-EOA-admin risk.
    r = run_issuer_authority(
        _inp(admin_holders=["0xa"], admin_is_multisig=None, admin_roles_revoked=None)
    )
    assert r.rated is False


def test_transfer_unrated_when_is_paused_read_fails_though_freeze_seize_succeed():
    # The live mainnet case: is_paused=None while can_freeze/can_seize read fine.
    # The "currently paused" High finding would otherwise be silently skipped.
    r = run_transfer_policy(_inp(can_freeze=False, can_seize=False, is_paused=None))
    assert r.rated is False


def test_variant_unrated_when_factory_read_fails_though_variant_read_succeeds():
    # factory_is_official (non-official-factory High+critical) is load-bearing;
    # a readable variant/decimals must not clear it.
    r = run_variant_config(_inp(variant="ASSET", decimals=18, factory_is_official=None))
    assert r.rated is False


def test_origin_unrated_when_announcement_read_fails_though_history_read_succeeds():
    # Both real reads (issuer_has_history, announcement_events) are load-bearing;
    # the other three inputs are un-implemented placeholders (always None).
    r = run_origin_transparency(_inp(issuer_has_history=True, announcement_events=None))
    assert r.rated is False


# --------------------------------------------------------------------------
# Engine-level headline: an uncapped ASSET whose supplyCap read FAILED must not
# be rewarded with a false grade A. Reproduces the validation finding (F -> A).
# --------------------------------------------------------------------------
def _uncapped_but_unread_asset(**over) -> ScanInputs:
    """Otherwise-clean ASSET whose supplyCap read FAILED (supply_cap=None).

    In reality this token is uncapped (supply_cap would be type(uint128).max);
    the scanner cannot see that because the read failed. Every *other* dimension
    reads cleanly, so under the old any() predicate supply stayed "rated" (via
    the readable multiplier_active sibling) and scored 100 -> the whole token
    graded A.
    """
    base = dict(
        variant="ASSET",
        decimals=18,
        factory_is_official=True,
        admin_holders=["0xadmin"],
        admin_is_multisig=True,
        can_freeze=False,
        can_seize=False,
        is_paused=False,
        issuer_has_history=True,
        announcement_events=True,
        supply_cap=None,          # the failed load-bearing read
        multiplier_active=False,  # a readable sibling (kept it "rated" under any())
    )
    base.update(over)
    return _inp(**base)


def test_failed_supply_read_does_not_produce_a_false_grade_A():
    res = assess(_uncapped_but_unread_asset())
    # unrated, listed as such, weight dropped from the composite (0.5 multiplier)...
    assert res.dimensions["supply_integrity"].rated is False
    assert "supply_integrity" in res.unrated_dimensions
    assert res.multiplier == 0.5
    # ...and, crucially, a failed read must never look pristine.
    assert res.grade != "A"


# --------------------------------------------------------------------------
# Control: a genuinely clean token with ALL reads succeeding must still be fully
# rated and score normally — the fix must not turn healthy scans into unrated
# ones. (Green before AND after the fix.)
# --------------------------------------------------------------------------
def _clean_fully_read_asset(**over) -> ScanInputs:
    base = dict(
        variant="ASSET",
        decimals=18,
        factory_is_official=True,
        supply_cap=1_000_000 * 10**18,
        multiplier_active=False,
        burn_enabled=False,
        admin_holders=["0xmultisig"],
        admin_is_multisig=True,
        can_freeze=False,
        can_seize=False,
        can_pause=False,
        is_paused=False,
        policy_registry_active=False,
        issuer_has_history=True,
        announcement_events=True,
    )
    base.update(over)
    return _inp(**base)


def test_clean_fully_read_token_stays_rated_and_scores_normally():
    res = assess(_clean_fully_read_asset())
    assert res.unrated_dimensions == []
    assert res.multiplier == 1.0
    assert all(d.rated for d in res.dimensions.values())
    assert res.rated is True
    assert res.grade in ("A", "B")
