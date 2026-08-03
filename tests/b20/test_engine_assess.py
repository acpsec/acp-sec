"""Full assembly: engine.assess -> canonical ScanResult (task 2.9, resolved schema)."""

from acpsec_api.b20.constants import DIMENSION_WEIGHTS, UINT128_MAX
from acpsec_api.b20.engine import assess
from acpsec_api.b20.models import ScanInputs

_AT = "2026-06-22T00:00:00Z"


def _good() -> ScanInputs:
    return ScanInputs(
        token="0xB200", chain_id=8453, variant="ASSET",
        name="Foo", symbol="FOO", decimals=18, currency_code=None,
        admin_holders=["0xa", "0xb"], admin_is_multisig=True,
        mint_role_holders=["0xc"],
        pause_role_holders=["0xd"], pause_holder_is_multisig=True,
        supply_cap=10**24, multiplier_active=False, burn_enabled=False,
        policy_registry_active=False, can_freeze=True, can_seize=True,
        can_pause=True, is_paused=False, memo_required=False, asymmetric_policy=False,
        deployed_via_factory="0xB20f000000000000000000000000000000000000",
        factory_is_official=True,
        issuer_wallet_age_days=400, issuer_has_history=True,
        verified_entity=True, public_docs=True, announcement_events=True,
    )


def _wipe_origin(inp: ScanInputs) -> ScanInputs:
    inp.issuer_wallet_age_days = None
    inp.issuer_has_history = None
    inp.verified_entity = None
    inp.public_docs = None
    inp.announcement_events = None
    return inp


def test_full_shape_and_score():
    d = assess(_good(), scanned_at=_AT).to_dict()

    assert set(d.keys()) == {
        "token", "chain_id", "variant", "name", "symbol", "decimals",
        "currency_code", "trust_score", "raw_score", "grade", "rated",
        "multiplier", "unrated_dimensions", "read_diagnostics", "is_critical",
        "critical_reasons", "dimensions", "issuer_powers", "deployed_via_factory",
        "scanner_version", "scanned_at",
    }
    assert set(d["dimensions"].keys()) == set(DIMENSION_WEIGHTS)
    # 0.30*90 + 0.25*100 + 0.20*70 + 0.15*100 + 0.10*100 = 91
    assert d["raw_score"] == 91
    assert d["trust_score"] == 91
    assert d["grade"] == "A"
    assert d["rated"] is True
    assert d["multiplier"] == 1.0
    assert d["unrated_dimensions"] == []
    assert d["is_critical"] is False
    assert d["scanner_version"] == "0.1.0"
    assert d["scanned_at"] == _AT


def test_issuer_powers_populated():
    p = assess(_good(), scanned_at=_AT).to_dict()["issuer_powers"]
    assert p["can_freeze"] is True
    assert p["can_seize"] is True
    assert p["can_pause"] is True
    assert p["can_mint_unbounded"] is False
    assert p["supply_cap"] == str(10**24)
    assert p["admin_addresses"] == ["0xa", "0xb"]
    assert p["admin_is_multisig"] is True
    assert p["mint_role_holders"] == ["0xc"]
    assert p["pause_role_holders"] == ["0xd"]


def test_critical_token_capped_to_f_keeps_raw_score():
    inp = _good()
    inp.supply_cap = UINT128_MAX
    d = assess(inp, scanned_at=_AT).to_dict()
    assert d["is_critical"] is True
    assert any("uncapped_mint" in r for r in d["critical_reasons"])
    assert d["raw_score"] == 76      # transparency: pre-cap composite preserved
    assert d["trust_score"] == 39    # min(min(76,39), 76*1.0) = 39
    assert d["grade"] == "F"
    assert d["issuer_powers"]["can_mint_unbounded"] is True


def test_unrated_dimension_halves_and_surfaces():
    # Wiping origin also clears public_docs/verified_entity, so transfer_policy's
    # freeze+seize becomes "no transparency" (-40) + pause (-10) -> 50.
    # raw = 0.30*90 + 0.25*100 + 0.20*50 + 0.15*100 = 77 (origin excluded).
    d = assess(_wipe_origin(_good()), scanned_at=_AT).to_dict()
    assert d["rated"] is False
    assert d["multiplier"] == 0.5
    assert d["unrated_dimensions"] == ["origin_transparency"]
    assert d["raw_score"] == 77
    assert d["trust_score"] == 38        # round(77 * 0.5)
    assert d["trust_score"] < d["raw_score"]


def test_multiple_unrated_dimensions_still_half_multiplier():
    # Multiplier is 0.5 regardless of how MANY dimensions are unrated (not 0.5^N).
    inp = _good()
    # Wipe inputs for two dimensions: origin AND supply.
    inp.issuer_wallet_age_days = None
    inp.issuer_has_history = None
    inp.verified_entity = None
    inp.public_docs = None
    inp.announcement_events = None
    inp.supply_cap = None
    inp.multiplier_active = None
    inp.burn_enabled = None
    d = assess(inp, scanned_at=_AT).to_dict()
    assert d["multiplier"] == 0.5   # not 0.25
    assert set(d["unrated_dimensions"]) == {"origin_transparency", "supply_integrity"}


def test_critical_and_unrated_take_the_lower():
    inp = _wipe_origin(_good())
    inp.supply_cap = UINT128_MAX         # critical (uncapped) AND origin unrated
    d = assess(inp, scanned_at=_AT).to_dict()
    # raw = 0.30*90 + 0.25*40 + 0.20*50 + 0.15*100 = 62 (supply uncapped -> 40;
    # transfer freeze+seize w/o transparency -> 50; origin excluded).
    assert d["is_critical"] is True
    assert d["rated"] is False
    assert d["multiplier"] == 0.5
    assert d["raw_score"] == 62
    # min( cap=min(62,39)=39 , multiplied=62*0.5=31 ) = 31  (more conservative)
    assert d["trust_score"] == 31
    assert d["trust_score"] < 39
    assert d["grade"] == "F"
