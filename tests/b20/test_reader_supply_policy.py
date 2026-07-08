"""Supply + transfer-policy reads on the real B20 interface (rework)."""

from tests.b20.conftest import FakeRpc

from acpsec_api.b20 import constants as C
from acpsec_api.b20 import reader as R

ASSET = "0x" + "b2" + "00" * 9 + "00" + "aa" * 9
STABLE = "0x" + "b2" + "00" * 9 + "01" + "bb" * 9


def _pid_call(scope: str, value: int) -> tuple[str, str]:
    return R.calldata(C.B20_SELECTOR_POLICY_ID, R.word(scope)), "0x" + R.enc_uint(value)


# --- supply ---------------------------------------------------------------
def test_uncapped_supply_returns_sentinel():
    f = FakeRpc().set_selector(C.B20_SELECTOR_SUPPLY_CAP, "0x" + R.enc_uint(C.UINT128_MAX))
    assert R.read_supply(f, ASSET, "ASSET")["supply_cap"] == C.UINT128_MAX


def test_finite_cap_exact():
    f = FakeRpc().set_selector(C.B20_SELECTOR_SUPPLY_CAP, "0x" + R.enc_uint(10**24))
    assert R.read_supply(f, ASSET, "ASSET")["supply_cap"] == 10**24


def test_multiplier_active_when_not_wad():
    f = FakeRpc().set_selector(C.B20_SELECTOR_MULTIPLIER, "0x" + R.enc_uint(2 * 10**18))
    assert R.read_supply(f, ASSET, "ASSET")["multiplier_active"] is True


def test_multiplier_inactive_when_wad():
    f = FakeRpc().set_selector(C.B20_SELECTOR_MULTIPLIER, "0x" + R.enc_uint(10**18))
    assert R.read_supply(f, ASSET, "ASSET")["multiplier_active"] is False


def test_multiplier_none_for_stablecoin():
    f = FakeRpc().set_selector(C.B20_SELECTOR_MULTIPLIER, "0x" + R.enc_uint(2 * 10**18))
    assert R.read_supply(f, STABLE, "STABLECOIN")["multiplier_active"] is None


def test_supply_rpc_fail_none():
    out = R.read_supply(FakeRpc(), ASSET, "ASSET")
    assert out["supply_cap"] is None
    assert out["multiplier_active"] is None


# --- transfer policy ------------------------------------------------------
def test_can_freeze_when_sender_policy_nonzero():
    f = FakeRpc().set_call(*_pid_call(C.B20_POLICY_TRANSFER_SENDER, 5))
    assert R.read_transfer_policy(f, ASSET)["can_freeze"] is True


def test_can_freeze_false_when_sender_policy_zero():
    f = FakeRpc().set_call(*_pid_call(C.B20_POLICY_TRANSFER_SENDER, 0))
    assert R.read_transfer_policy(f, ASSET)["can_freeze"] is False


def test_asymmetric_when_sender_set_receiver_zero():
    f = FakeRpc()
    f.set_call(*_pid_call(C.B20_POLICY_TRANSFER_SENDER, 5))
    f.set_call(*_pid_call(C.B20_POLICY_TRANSFER_RECEIVER, 0))
    out = R.read_transfer_policy(f, ASSET)
    assert out["asymmetric_policy"] is True
    assert out["policy_registry_active"] is True


def test_symmetric_all_zero():
    f = FakeRpc()
    for scope in (
        C.B20_POLICY_TRANSFER_SENDER, C.B20_POLICY_TRANSFER_RECEIVER,
        C.B20_POLICY_TRANSFER_EXECUTOR, C.B20_POLICY_MINT_RECEIVER,
    ):
        f.set_call(*_pid_call(scope, 0))
    out = R.read_transfer_policy(f, ASSET)
    assert out["asymmetric_policy"] is False
    assert out["policy_registry_active"] is False
    assert out["can_freeze"] is False


def test_is_paused_true():
    f = FakeRpc().set_call(
        R.calldata(C.B20_SELECTOR_IS_PAUSED, R.enc_uint(C.B20_PAUSABLE_TRANSFER)),
        "0x" + R.enc_uint(1),
    )
    assert R.read_transfer_policy(f, ASSET)["is_paused"] is True


def test_policy_rpc_fail_all_none():
    out = R.read_transfer_policy(FakeRpc(), ASSET)
    assert out["can_freeze"] is None
    assert out["asymmetric_policy"] is None
    assert out["policy_registry_active"] is None
    assert out["is_paused"] is None
