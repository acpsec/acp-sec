"""read_token orchestration + reader->engine end-to-end (rework)."""

import pytest
from tests.b20.conftest import FakeRpc

from acpsec_api.b20 import constants as C
from acpsec_api.b20 import reader as R
from acpsec_api.b20.engine import assess
from acpsec_api.b20.models import ScanInputs

ASSET = "0x" + "b2" + "00" * 9 + "00" + "aa" * 9
ADMIN = "0x" + "a1" * 20
MINT_H = "0x" + "a2" * 20
BURN_H = "0x" + "a3" * 20
PAUSE_H = "0x" + "a4" * 20
_AT = "2026-06-26T00:00:00Z"


def _good_asset() -> FakeRpc:
    f = FakeRpc(84532)
    # preflight
    f.set_is_b20(ASSET, True)
    f.set_is_b20_initialized(ASSET, True)
    f.set_activated("ASSET", True)
    # roles (admin is a contract -> multisig)
    f.grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN, 1)
    f.set_code(ADMIN, "0x6080604052")
    f.grant_role(C.B20_ROLE_MINT, MINT_H, 2)
    f.grant_role(C.B20_ROLE_BURN, BURN_H, 3)
    f.grant_role(C.B20_ROLE_PAUSE, PAUSE_H, 4)
    # supply (finite cap, not rebasing)
    f.set_selector(C.B20_SELECTOR_SUPPLY_CAP, "0x" + R.enc_uint(10**24))
    f.set_selector(C.B20_SELECTOR_MULTIPLIER, "0x" + R.enc_uint(10**18))
    # policy: sender policy set (freeze), receiver 0 (asymmetric), not paused
    f.set_call(R.calldata(C.B20_SELECTOR_POLICY_ID, R.word(C.B20_POLICY_TRANSFER_SENDER)), "0x" + R.enc_uint(2))
    f.set_call(R.calldata(C.B20_SELECTOR_POLICY_ID, R.word(C.B20_POLICY_TRANSFER_RECEIVER)), "0x" + R.enc_uint(0))
    f.set_call(R.calldata(C.B20_SELECTOR_IS_PAUSED, R.enc_uint(C.B20_PAUSABLE_TRANSFER)), "0x" + R.enc_uint(0))
    # variant config
    f.set_selector(C.B20_SELECTOR_DECIMALS, "0x" + R.enc_uint(18))
    # origin
    f.set_txcount(ADMIN, "0x10")
    f.set_announcements(1)
    return f


def test_read_token_full_populates_scaninputs():
    inp = R.read_token(ASSET, 84532, rpc=_good_asset())
    assert isinstance(inp, ScanInputs)
    assert inp.variant == "ASSET" and inp.decimals == 18
    assert inp.admin_holders == [ADMIN] and inp.admin_is_multisig is True
    assert inp.mint_role_holders == [MINT_H]
    assert inp.supply_cap == 10**24 and inp.multiplier_active is False
    assert inp.burn_enabled is True          # BURN_ROLE has a holder
    assert inp.can_pause is True             # PAUSE_ROLE has a holder
    assert inp.can_seize is False            # no BURN_BLOCKED_ROLE holder
    assert inp.can_freeze is True            # sender policy != 0
    assert inp.asymmetric_policy is True
    assert inp.is_paused is False
    assert inp.factory_is_official is True
    assert inp.deployed_via_factory == C.OFFICIAL_FACTORY_ADDRESS[84532]
    assert inp.issuer_has_history is True and inp.announcement_events is True
    assert inp.memo_required is None         # dropped in the rework


def test_read_token_passes_creation_block_to_role_scan(monkeypatch):
    # read_token looks up the token's creation block and threads it into the
    # role-holder scan as from_block (bounding the getLogs range).
    f = _good_asset()
    f.set_creation_code(ASSET, 1, "0xef")  # token gains code at block 1
    captured = {}
    real = R.role_holders

    def spy(rpc, token, role, chain_id, from_block=0):
        captured["from_block"] = from_block
        return real(rpc, token, role, chain_id, from_block=from_block)

    monkeypatch.setattr(R, "role_holders", spy)
    R.read_token(ASSET, 84532, rpc=f)
    assert captured["from_block"] == 1


def test_read_token_raises_when_not_a_b20_token():
    f = FakeRpc(84532).set_is_b20(ASSET, False)
    with pytest.raises(R.B20Unavailable):
        R.read_token(ASSET, 84532, rpc=f)


def test_read_token_raises_when_not_initialized():
    f = FakeRpc(84532).set_is_b20(ASSET, True).set_is_b20_initialized(ASSET, False)
    with pytest.raises(R.B20Unavailable):
        R.read_token(ASSET, 84532, rpc=f)


def test_read_token_raises_when_feature_not_activated():
    f = (FakeRpc(84532).set_is_b20(ASSET, True)
         .set_is_b20_initialized(ASSET, True).set_activated("ASSET", False))
    with pytest.raises(R.B20Unavailable):
        R.read_token(ASSET, 84532, rpc=f)


def test_read_token_unknown_preflight_proceeds_unrated():
    # Nothing programmed: isB20/init/activation all None (no raise); RPC reads fail.
    f = FakeRpc(84532).set_logs_fail()
    inp = R.read_token(ASSET, 84532, rpc=f)
    assert inp.variant == "ASSET"            # pure decode still works
    assert inp.admin_holders is None         # getLogs failed -> unknown
    assert inp.supply_cap is None and inp.decimals is None
    assert inp.factory_is_official is None
    assert inp.announcement_events is None


def test_reader_to_engine_end_to_end():
    inp = R.read_token(ASSET, 84532, rpc=_good_asset())
    d = assess(inp, scanned_at=_AT).to_dict()
    assert set(d["dimensions"].keys()) == set(C.DIMENSION_WEIGHTS)
    assert isinstance(d["trust_score"], int)
    assert d["rated"] is True
    assert d["issuer_powers"]["can_freeze"] is True
    assert d["issuer_powers"]["admin_is_multisig"] is True
