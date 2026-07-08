"""Variant decode + isB20/isB20Initialized/activation preflight (rework)."""

from tests.b20.conftest import FakeRpc

from acpsec_api.b20 import reader as R

ASSET = "0x" + "b2" + "00" * 9 + "00" + "aa" * 9
STABLE = "0x" + "b2" + "00" * 9 + "01" + "bb" * 9


# --- variant decode (pure, from address byte[10]) -------------------------
def test_variant_asset():
    assert R.decode_variant(ASSET) == "ASSET"


def test_variant_stablecoin():
    assert R.decode_variant(STABLE) == "STABLECOIN"


def test_variant_unknown_byte():
    assert R.decode_variant("0x" + "b2" + "00" * 9 + "05" + "bb" * 9) is None


def test_variant_non_b2_prefix():
    assert R.decode_variant("0x" + "ab" * 20) is None


def test_variant_bad_length():
    assert R.decode_variant("0xb200") is None


# --- factory.isB20 / isB20Initialized -------------------------------------
def test_is_b20_true():
    f = FakeRpc(84532).set_is_b20(ASSET, True)
    assert R.factory_is_b20(f, ASSET, 84532) is True


def test_is_b20_false():
    f = FakeRpc(84532).set_is_b20(ASSET, False)
    assert R.factory_is_b20(f, ASSET, 84532) is False


def test_is_b20_rpc_fail_none():
    assert R.factory_is_b20(FakeRpc(84532), ASSET, 84532) is None


def test_is_b20_initialized_true():
    f = FakeRpc(84532).set_is_b20_initialized(ASSET, True)
    assert R.factory_is_b20_initialized(f, ASSET, 84532) is True


# --- activation gate ------------------------------------------------------
def test_is_activated_true():
    f = FakeRpc(84532).set_activated("ASSET", True)
    assert R.is_activated(f, "ASSET") is True


def test_is_activated_false():
    f = FakeRpc(84532).set_activated("STABLECOIN", False)
    assert R.is_activated(f, "STABLECOIN") is False


def test_is_activated_unknown_variant_none():
    assert R.is_activated(FakeRpc(84532), None) is None
