"""#67 (+ uncapped slice of #55) — effectively-uncapped supply.

The uncapped-mint critical now fires on the top half of the uint128 range
(EFFECTIVELY_UNCAPPED_MIN = UINT128_MAX // 2), closing the T1 evasion (cap = max-1
scored A/100 before). Severity is gated on official_ticker_status: CRITICAL for
unverified issuers; for a VERIFIED 1:1-backed tokenized stock uncapped supply is
expected design -> INFO finding, no critical, no penalty (honesty: surface the
fact + context, don't hide, don't penalize).
"""

from acpsec_api.b20.constants import UINT128_MAX
from acpsec_api.b20.engine import assess, detect_critical, CRITICAL_UNCAPPED_MINT
from acpsec_api.b20.dimensions import run_supply_integrity
from acpsec_api.b20.models import ScanInputs

HALF = UINT128_MAX // 2


def _inp(cap, status=None):
    return ScanInputs(token="0xB200", chain_id=8453, variant="ASSET", symbol="X",
                      decimals=18, supply_cap=cap, official_ticker_status=status,
                      factory_is_official=True)


# --- threshold: closes T1, still catches the sentinel, clears real caps ----
def test_t1_max_minus_1_unverified_is_now_critical():
    assert CRITICAL_UNCAPPED_MINT in detect_critical(_inp(UINT128_MAX - 1))


def test_exact_sentinel_unverified_still_critical():
    assert CRITICAL_UNCAPPED_MINT in detect_critical(_inp(UINT128_MAX))


def test_boundary_just_below_half_not_flagged():
    assert CRITICAL_UNCAPPED_MINT not in detect_critical(_inp(HALF - 1))


def test_boundary_at_half_flagged():
    assert CRITICAL_UNCAPPED_MINT in detect_critical(_inp(HALF))


def test_real_fixed_cap_1e27_not_flagged():
    assert CRITICAL_UNCAPPED_MINT not in detect_critical(_inp(10**27))
    dim = run_supply_integrity(_inp(10**27))
    assert dim.score == 100.0
    assert not any(("uncapped" in f.detail.lower() or "infinite" in f.detail.lower())
                   for f in dim.findings)


# --- verified gate: uncapped becomes INFO, no critical, no penalty ---------
def test_verified_sentinel_no_uncapped_critical():
    assert CRITICAL_UNCAPPED_MINT not in detect_critical(_inp(UINT128_MAX, status="verified"))


def test_verified_uncapped_emits_info_no_penalty():
    dim = run_supply_integrity(_inp(UINT128_MAX, status="verified"))
    assert dim.score == 100.0   # no penalty
    assert any(f.severity == "Info" and "expected" in f.detail.lower() for f in dim.findings)


def test_unverified_uncapped_emits_high_penalty():
    dim = run_supply_integrity(_inp(UINT128_MAX - 1))   # T1 value, unverified
    assert dim.score == 40.0    # 100 - 60
    assert any(f.severity == "High" for f in dim.findings)


# --- assess-level: verified uncapped stock is no longer forced critical ----
def test_verified_uncapped_not_critical_via_assess():
    r = assess(_inp(UINT128_MAX, status="verified")).to_dict()
    assert not any("uncapped_mint" in x for x in r["critical_reasons"])
