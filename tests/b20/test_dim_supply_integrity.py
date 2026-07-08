"""Supply Integrity dimension (task 2.5)."""

from acpsec_api.b20.constants import UINT128_MAX
from acpsec_api.b20.dimensions import run_supply_integrity
from acpsec_api.b20.models import ScanInputs


def _inp(**kw) -> ScanInputs:
    return ScanInputs(token="0xB200", chain_id=8453, **kw)


def test_uncapped_supply_is_severely_penalized():
    r = run_supply_integrity(_inp(supply_cap=UINT128_MAX))
    assert r.name == "supply_integrity"
    assert r.weight == 0.25
    assert r.score <= 50
    assert any(f.severity in ("High", "CRITICAL") for f in r.findings)


def test_finite_cap_scores_full():
    r = run_supply_integrity(_inp(supply_cap=1_000_000 * 10**18))
    assert r.rated is True
    assert r.score == 100


def test_rebasing_multiplier_penalized():
    base = run_supply_integrity(_inp(supply_cap=10**24)).score
    r = run_supply_integrity(_inp(supply_cap=10**24, multiplier_active=True))
    assert r.score < base
    assert any("rebas" in f.detail.lower() or "multiplier" in f.detail.lower() for f in r.findings)


def test_burn_enabled_minor_penalty():
    base = run_supply_integrity(_inp(supply_cap=10**24)).score
    r = run_supply_integrity(_inp(supply_cap=10**24, burn_enabled=True))
    assert r.score < base


def test_unknown_supply_is_unrated():
    assert run_supply_integrity(_inp()).rated is False
