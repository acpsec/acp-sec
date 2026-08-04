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
    # chain 84532 chunk = 2000; latest 5000 -> 3 windows; holders span windows 1 & 3.
    # Cap the provider at 2000 so the full-first query is rejected and the chunk
    # walk is the path actually exercised (mirrors public base.org's 2000 cap).
    f = FakeRpc(84532).set_block_number(5000).set_max_getlogs_range(2000)
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


# ── merged single getLogs for all roles + full-first→chunk fallback ──────────
def test_read_roles_uses_one_merged_getlogs():
    # All five roles come from ONE getLogs (topic0 [Granted,Revoked], no role
    # filter), demuxed client-side — not five separate queries.
    f = FakeRpc(84532)
    f.grant_role(C.B20_ROLE_DEFAULT_ADMIN, A1, 1)
    f.grant_role(C.B20_ROLE_MINT, A2, 2)
    f.grant_role(C.B20_ROLE_PAUSE, A1, 3)
    roles = R.read_roles(f, ASSET, 84532)
    assert roles["admin"] == [A1] and roles["mint"] == [A2] and roles["pause"] == [A1]
    assert roles["burn"] == [] and roles["burn_blocked"] == []   # known-empty, not None
    assert len(f.getlogs_calls) == 1


def test_role_holders_all_demuxes_by_role_with_first_grantee():
    f = FakeRpc(84532)
    f.grant_role(C.B20_ROLE_MINT, A1, 5).grant_role(C.B20_ROLE_MINT, A2, 6)
    f.grant_role(C.B20_ROLE_BURN, A1, 7).revoke_role(C.B20_ROLE_MINT, A1, 8)
    allr = R.role_holders_all(f, ASSET, 84532)
    assert allr[C.B20_ROLE_MINT.lower()][0] == [A2]         # A1 granted then revoked
    assert allr[C.B20_ROLE_BURN.lower()][0] == [A1]
    assert allr[C.B20_ROLE_MINT.lower()][1] == A1           # first grantee (pre-revoke)


def test_merged_rpc_failure_yields_none_for_all_roles():
    roles = R.read_roles(FakeRpc(84532).set_logs_fail(), ASSET, 84532)
    assert roles["admin"] is None and roles["mint"] is None and roles["pause"] is None
    assert roles["admin_first_grantee"] is None


def test_full_first_single_query_when_provider_ungated():
    # No cap → the whole [from,latest] range in ONE getLogs, no chunk walk.
    f = FakeRpc(84532).set_block_number(50000)
    f.grant_role(MINT, A1, 40000)
    assert R.role_holders(f, ASSET, MINT, 84532) == [A1]
    assert len(f.getlogs_calls) == 1


def test_range_cap_falls_back_to_chunk_walk_and_recovers_all():
    # Full query rejected with the exact provider range-cap error → chunk walk at
    # the fixed per-chain size recovers holders spanning multiple windows.
    f = FakeRpc(84532).set_block_number(5000).set_max_getlogs_range(2000)
    f.grant_role(MINT, A1, 100)
    f.grant_role(MINT, A2, 4500)
    assert set(R.role_holders(f, ASSET, MINT, 84532)) == {A1, A2}
    assert len(f.getlogs_calls) >= 2                        # 1 failed full + windows


def test_permanent_range_cap_yields_honest_none():
    # Even the chunk windows exceed the cap → honest None (never a fabricated pass).
    f = FakeRpc(84532).set_block_number(5000).set_max_getlogs_range(0)
    f.grant_role(MINT, A1, 100)
    assert R.role_holders(f, ASSET, MINT, 84532) is None


def test_non_range_cap_failure_does_not_chunk():
    # A non-range-cap getLogs failure must NOT trigger the chunk fallback.
    f = FakeRpc(84532).set_block_number(5000).set_logs_fail()
    assert R.role_holders(f, ASSET, MINT, 84532) is None
    assert len(f.getlogs_calls) == 1


def test_classify_multisig_eoa_vs_contract():
    f = FakeRpc(84532)
    f.set_code(A1, "0x")           # EOA
    f.set_code(A2, "0x60016002")   # contract
    assert R._classify_multisig(f, [A1]) is False
    assert R._classify_multisig(f, [A2]) is True
    assert R._classify_multisig(f, None) is None
    assert R._classify_multisig(f, []) is None


# ── B20_GETLOGS_CHUNK_<chain_id>: fallback chunk-size env override ────────────
# The full-first→chunk fallback (PR #32) walked at the hardcoded public-endpoint
# size. A provider that allows wider ranges than the public cap (e.g. CDP: 100k)
# should be able to walk in bigger windows — far fewer getLogs — via env, with
# zero-config unchanged.
def test_resolve_getlogs_chunk_env_override(monkeypatch):
    monkeypatch.setenv("B20_GETLOGS_CHUNK_8453", "100000")
    assert R.resolve_getlogs_chunk(8453) == 100_000


def test_resolve_getlogs_chunk_zero_config_is_todays_default(monkeypatch):
    monkeypatch.delenv("B20_GETLOGS_CHUNK_8453", raising=False)
    monkeypatch.delenv("B20_GETLOGS_CHUNK_84532", raising=False)
    assert R.resolve_getlogs_chunk(8453) == 10_000    # _LOG_BLOCK_CHUNK mainnet
    assert R.resolve_getlogs_chunk(84532) == 2_000    # _LOG_BLOCK_CHUNK sepolia


def test_resolve_getlogs_chunk_invalid_value_falls_back(monkeypatch):
    monkeypatch.setenv("B20_GETLOGS_CHUNK_8453", "not-an-int")
    assert R.resolve_getlogs_chunk(8453) == 10_000
    monkeypatch.setenv("B20_GETLOGS_CHUNK_8453", "0")   # non-positive -> default
    assert R.resolve_getlogs_chunk(8453) == 10_000


def test_getlogs_chunk_env_resizes_fallback_windows(monkeypatch):
    # Provider caps the full range but allows 100k windows (CDP-style): the fallback
    # walks in 100k-block windows, not the 10k public default -> ~10x fewer queries.
    monkeypatch.setenv("B20_GETLOGS_CHUNK_8453", "100000")
    f = FakeRpc(8453).set_block_number(250_000).set_max_getlogs_range(100_000)
    f.grant_role(MINT, A1, 150_000)
    assert R.role_holders(f, ASSET, MINT, 8453) == [A1]
    windows = f.getlogs_calls[1:]                      # [0] is the rejected full query
    spans = [int(w["toBlock"], 16) - int(w["fromBlock"], 16) for w in windows]
    assert spans[0] == 99_999                          # 100k chunk (size-1), not 9_999
    assert len(windows) == 3                           # ceil(250_001 / 100_000)


def test_getlogs_chunk_default_windows_when_unset(monkeypatch):
    # Guard: with no env var, the fallback keeps today's per-chain sizes exactly.
    monkeypatch.delenv("B20_GETLOGS_CHUNK_8453", raising=False)
    f = FakeRpc(8453).set_block_number(25_000).set_max_getlogs_range(10_000)
    f.grant_role(MINT, A1, 15_000)
    assert R.role_holders(f, ASSET, MINT, 8453) == [A1]
    spans = [int(w["toBlock"], 16) - int(w["fromBlock"], 16) for w in f.getlogs_calls[1:]]
    assert spans[0] == 9_999                           # today's 10k mainnet default
