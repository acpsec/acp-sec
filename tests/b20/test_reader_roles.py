"""Role-holder reconstruction via RoleGranted/RoleRevoked log replay (rework)."""

from tests.b20.conftest import FakeRpc

from acpsec_api.b20 import constants as C
from acpsec_api.b20 import reader as R

ASSET = "0x" + "b2" + "00" * 9 + "00" + "aa" * 9
A1 = "0x" + "a1" * 20
A2 = "0x" + "a2" * 20
ADMIN = C.B20_ROLE_DEFAULT_ADMIN
MINT = C.B20_ROLE_MINT


def test_single_grant_is_holder():
    f = FakeRpc(84532).grant_role(ADMIN, A1, block=5)
    assert R.role_holders(f, ASSET, ADMIN, 84532) == [A1]


def test_grant_then_revoke_is_empty():
    f = FakeRpc(84532).grant_role(MINT, A1, 5).revoke_role(MINT, A1, 6)
    assert R.role_holders(f, ASSET, MINT, 84532) == []


def test_grant_revoke_regrant_is_holder():
    f = FakeRpc(84532).grant_role(MINT, A1, 5).revoke_role(MINT, A1, 6).grant_role(MINT, A1, 7)
    assert R.role_holders(f, ASSET, MINT, 84532) == [A1]


def test_duplicate_grants_deduplicated():
    f = FakeRpc(84532).grant_role(MINT, A1, 5).grant_role(MINT, A1, 6)
    assert R.role_holders(f, ASSET, MINT, 84532) == [A1]


def test_two_distinct_holders():
    f = FakeRpc(84532).grant_role(ADMIN, A1, 5).grant_role(ADMIN, A2, 6)
    assert set(R.role_holders(f, ASSET, ADMIN, 84532)) == {A1, A2}


def test_no_events_is_empty_list():
    assert R.role_holders(FakeRpc(84532), ASSET, MINT, 84532) == []


def test_getlogs_failure_yields_none():
    assert R.role_holders(FakeRpc(84532).set_logs_fail(), ASSET, MINT, 84532) is None


def test_block_number_failure_yields_none():
    f = FakeRpc(84532)
    f.block_number = None  # eth_block_number -> None
    assert R.role_holders(f, ASSET, MINT, 84532) is None


def test_chunked_aggregates_across_windows():
    # chain 84532 chunk = 2000; latest 5000 -> 3 windows; holders span windows 1 & 3
    f = FakeRpc(84532).set_block_number(5000)
    f.grant_role(MINT, A1, block=100)
    f.grant_role(MINT, A2, block=4500)
    assert set(R.role_holders(f, ASSET, MINT, 84532)) == {A1, A2}


def test_read_roles_reads_all_five():
    f = FakeRpc(84532)
    f.grant_role(C.B20_ROLE_DEFAULT_ADMIN, A1, 1)
    f.grant_role(C.B20_ROLE_MINT, A2, 2)
    f.grant_role(C.B20_ROLE_BURN, A1, 3)
    f.grant_role(C.B20_ROLE_BURN_BLOCKED, A2, 4)
    f.grant_role(C.B20_ROLE_PAUSE, A1, 5)
    roles = R.read_roles(f, ASSET, 84532)
    assert roles["admin"] == [A1]
    assert roles["mint"] == [A2]
    assert roles["burn"] == [A1]
    assert roles["burn_blocked"] == [A2]
    assert roles["pause"] == [A1]


def test_from_block_excludes_earlier_grants():
    # Grants before from_block must not be scanned/counted; only later ones are.
    f = FakeRpc(84532).grant_role(MINT, A1, block=10).grant_role(MINT, A2, block=100)
    assert R.role_holders(f, ASSET, MINT, 84532, from_block=50) == [A2]


def test_classify_multisig_eoa_vs_contract():
    f = FakeRpc(84532)
    f.set_code(A1, "0x")           # EOA
    f.set_code(A2, "0x60016002")   # contract
    assert R._classify_multisig(f, [A1]) is False
    assert R._classify_multisig(f, [A2]) is True
    assert R._classify_multisig(f, None) is None
    assert R._classify_multisig(f, []) is None
