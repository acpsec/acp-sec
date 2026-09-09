"""#70 — capability() doctrine restoration.

A SUCCESSFUL but empty role replay is *proof of absence* (`can_X = False`), not
`unknown` (`None`). `None` is reserved for a FAILED read (`holders is None`). This
lifts the 0.5 unrated floor that `can_seize = None` was imposing on every
event-emitting B20 token via an unrated `transfer_policy`.

Semantic shift (see docs/deploy-runbook.md, scanner 0.7.0): pre-0.7.0 an empty
replay read `None`; from 0.7.0 an empty replay reads `False`. `None` now means
only "read failed". NOTE the deliberate Option-A tradeoff: a genuinely SILENT
token whose role getLogs SUCCEEDS-but-empty now resolves `False` too (see the
silent-token guard test below and the runbook caveat).
"""

import json
import pathlib

from tests.b20.conftest import FakeRpc  # noqa: F401  (kept for parity/imports)
from tests.b20.test_reader_integration import (
    ASSET,
    _asset_without_seize_events,
    _no_role_events_asset,
)

from acpsec_api.b20 import reader as R
from acpsec_api.b20.engine import assess

HOLDER = "0x" + "cd" * 20


# --------------------------------------------------------------------------
# capability() unit tests (now module-level, #70)
# --------------------------------------------------------------------------
def test_capability_returns_false_when_role_never_granted():
    # doctrine: a successful empty replay is proven absence -> False
    assert R.capability([], False) is False, "doctrine: absence proven -> False"


def test_capability_returns_false_when_read_confirmed_no_holders():
    # granted-then-revoked (granted_ever=True) already resolved False; a plain
    # successful empty read must ALSO be False under the restored doctrine.
    assert R.capability([], True) is False, "read succeeded, zero holders -> False"


def test_capability_none_only_when_read_failed():
    # None is reserved for a genuinely FAILED read (holders is None); a
    # successful read (empty or not) is NEVER None.
    assert R.capability(None, False) is None      # read failed -> unknown
    assert R.capability(None, True) is None        # read failed -> unknown
    assert R.capability([], False) is not None     # read succeeded, empty -> not None
    assert R.capability([], True) is not None       # read succeeded, empty -> not None


def test_capability_true_when_role_held():
    assert R.capability([HOLDER], False) is True


# --------------------------------------------------------------------------
# Integration: the floor lifts. An event-emitting token that never granted
# SEIZE now reads can_seize=False (proven), so transfer_policy RATES.
# --------------------------------------------------------------------------
def test_never_granted_seize_on_event_emitting_token_rates_transfer_policy():
    inp = R.read_token(ASSET, 84532, rpc=_asset_without_seize_events())
    assert inp.can_seize is False                   # proven absence, not None
    res = assess(inp)
    assert res.dimensions["transfer_policy"].rated is True
    assert "transfer_policy" not in res.to_dict()["unrated_dimensions"]


# --------------------------------------------------------------------------
# Silent-token guard (Option-A tradeoff made explicit): a token whose role
# getLogs SUCCEEDS but is empty (no events at all) also resolves False now.
# This documents the known regression flagged in the analysis + runbook.
# --------------------------------------------------------------------------
def test_silent_token_successful_empty_read_resolves_false_option_a():
    inp = R.read_token(ASSET, 84532, rpc=_no_role_events_asset())
    assert inp.can_seize is False   # Option A: successful-empty -> False, even when silent


# --------------------------------------------------------------------------
# Regression contract: the T4 fixture PAIR pins the pre/post-#70 score delta.
# --------------------------------------------------------------------------
_FIX = pathlib.Path(__file__).parent / "fixtures" / "live"


def test_t4_fixture_pair_pins_the_floor_lift():
    pre = json.loads((_FIX / "T4-nvdac-impersonation-2026-09-09.json").read_text())
    post = json.loads((_FIX / "T4-nvdac-post-70-fix.json").read_text())
    # pre-#70: transfer_policy unrated -> 0.5 floor -> F, impersonation masked
    assert pre["grade"] == "F" and pre["rated"] is False
    assert "transfer_policy" in pre["unrated_dimensions"]
    assert pre["issuer_powers"]["can_seize"] is None
    # post-#70: floor lifts -> #66 impersonation surfaces as a grade-A false-safe
    assert post["grade"] == "A" and post["rated"] is True
    assert post["unrated_dimensions"] == []
    assert post["issuer_powers"]["can_seize"] is False
    assert post["scanner_version"] == "0.7.0"
