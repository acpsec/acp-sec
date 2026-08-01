"""Critical conditions + composite cap (task 2.2)."""

from acpsec_api.b20.constants import UINT128_MAX
from acpsec_api.b20.engine import (
    apply_critical_cap,
    detect_critical,
    grade_for,
)
from acpsec_api.b20.models import ScanInputs


def _clean() -> ScanInputs:
    """Inputs that trip none of the three critical conditions."""
    return ScanInputs(
        token="0xB200", chain_id=8453,
        supply_cap=1_000_000 * 10**18,
        factory_is_official=True,
        admin_holders=["0xaaa"], admin_is_multisig=True,
    )


def test_uncapped_mint_is_critical():
    inp = _clean()
    inp.supply_cap = UINT128_MAX
    reasons = detect_critical(inp)
    assert any("uncapped_mint" in r for r in reasons)


def test_finite_cap_is_not_uncapped():
    assert not any("uncapped_mint" in r for r in detect_critical(_clean()))


def test_single_eoa_admin_is_critical():
    inp = _clean()
    inp.admin_holders = ["0xaaa"]
    inp.admin_is_multisig = False
    assert any("single_eoa_admin" in r for r in detect_critical(inp))


def test_multisig_admin_not_critical():
    assert not any("single_eoa_admin" in r for r in detect_critical(_clean()))


def test_no_critical_on_clean_inputs():
    assert detect_critical(_clean()) == []


def test_unknown_values_do_not_assert_critical():
    # All-unknown inputs must not be asserted critical (no guessing from None).
    inp = ScanInputs(token="0xB200", chain_id=8453)
    assert detect_critical(inp) == []


def test_empty_admin_holders_is_not_single_eoa_critical():
    # admin_holders=[] means we know there are no admin holders (e.g. role revoked).
    # That's not the "single EOA without multisig" critical condition.
    inp = _clean()
    inp.admin_holders = []
    inp.admin_is_multisig = False
    assert not any("single_eoa_admin" in r for r in detect_critical(inp))


def test_critical_caps_score_to_39_and_grade_f():
    capped = apply_critical_cap(85, critical=True)
    assert capped == 39
    assert grade_for(capped) == "F"


def test_no_cap_when_not_critical():
    assert apply_critical_cap(85, critical=False) == 85
