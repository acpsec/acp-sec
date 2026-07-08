"""Origin & transparency reads (rework: chunked announcement logs)."""

from tests.b20.conftest import FakeRpc

from acpsec_api.b20 import reader as R

ASSET = "0x" + "b2" + "00" * 9 + "00" + "aa" * 9
ADMIN = "0x" + "a1" * 20


def test_issuer_has_history_true():
    f = FakeRpc(84532).set_txcount(ADMIN, "0x5")
    assert R.read_origin(f, ASSET, [ADMIN], 84532)["issuer_has_history"] is True


def test_issuer_has_history_false_when_zero():
    f = FakeRpc(84532).set_txcount(ADMIN, "0x0")
    assert R.read_origin(f, ASSET, [ADMIN], 84532)["issuer_has_history"] is False


def test_issuer_has_history_none_no_admin():
    assert R.read_origin(FakeRpc(84532), ASSET, None, 84532)["issuer_has_history"] is None


def test_announcement_true_when_logs_present():
    f = FakeRpc(84532).set_announcements(2)
    assert R.read_origin(f, ASSET, [ADMIN], 84532)["announcement_events"] is True


def test_announcement_false_when_none():
    f = FakeRpc(84532)  # zero announcements
    assert R.read_origin(f, ASSET, [ADMIN], 84532)["announcement_events"] is False


def test_announcement_none_on_getlogs_failure():
    f = FakeRpc(84532).set_logs_fail()
    assert R.read_origin(f, ASSET, [ADMIN], 84532)["announcement_events"] is None


def test_v1_placeholders_are_none():
    out = R.read_origin(FakeRpc(84532), ASSET, [ADMIN], 84532)
    assert out["issuer_wallet_age_days"] is None
    assert out["verified_entity"] is None
    assert out["public_docs"] is None
