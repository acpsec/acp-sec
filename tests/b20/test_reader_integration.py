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
    real = R.role_holders_all

    def spy(rpc, token, chain_id, from_block=0):
        captured["from_block"] = from_block
        return real(rpc, token, chain_id, from_block=from_block)

    monkeypatch.setattr(R, "role_holders_all", spy)
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


# --------------------------------------------------------------------------
# Over-correction regression: a fully-revoked admin is the SAFEST authority
# posture (empty holders from a SUCCESSFUL replay = a KNOWN state, not a read
# failure). The reader must record it as admin_roles_revoked=True so the
# load-bearing issuer_authority rule keeps it rated instead of wrongly unrating
# the safest token. (Driven through read_token — the fix lives in the reader.)
# --------------------------------------------------------------------------
def _revoked_admin_asset() -> FakeRpc:
    f = _good_asset()  # grants DEFAULT_ADMIN to ADMIN at block 1
    f.revoke_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN, 2)  # net admin holders -> []
    return f


def test_reader_sets_admin_roles_revoked_when_admin_fully_revoked():
    inp = R.read_token(ASSET, 84532, rpc=_revoked_admin_asset())
    assert inp.admin_holders == []
    assert inp.admin_roles_revoked is True


def test_revoked_admin_keeps_issuer_authority_rated_end_to_end():
    inp = R.read_token(ASSET, 84532, rpc=_revoked_admin_asset())
    res = assess(inp)
    assert res.dimensions["issuer_authority"].rated is True
    assert "issuer_authority" not in res.unrated_dimensions


# --------------------------------------------------------------------------
# PR 1 (#26 item 2): origin issuer-proxy fallback for fully-revoked-admin tokens.
# When net admin is [], origin falls back to the FIRST historical DEFAULT_ADMIN
# grantee — captured during the SAME role replay (no extra RPC) — so
# origin_transparency can still rate. The proxy is None only if no grant event
# ever existed, or the origin read itself fails.
# --------------------------------------------------------------------------
ADMIN2 = "0x" + "c2" * 20


def _transferred_admin_asset() -> FakeRpc:
    """Admin transferred: ADMIN granted @1 (in _good_asset), ADMIN2 granted @5,
    ADMIN revoked @6 -> net admin = [ADMIN2]; first grantee = ADMIN."""
    f = _good_asset()
    f.grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN2, 5)
    f.revoke_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN, 6)
    f.set_code(ADMIN2, "0x")       # EOA
    f.set_txcount(ADMIN2, "0x0")   # 0 txns -> issuer_has_history False (ADMIN has 16)
    return f


def test_revoked_admin_origin_uses_first_grantee_fallback():
    # RED today: issuer = admin[0] = None (revoked) -> issuer_has_history None ->
    # origin unrated. After the fix: issuer falls back to the first grantee
    # (ADMIN, txcount 16) -> issuer_has_history True -> origin rated.
    inp = R.read_token(ASSET, 84532, rpc=_revoked_admin_asset())
    assert inp.admin_holders == []
    assert inp.issuer_has_history is True
    res = assess(inp)
    assert res.dimensions["origin_transparency"].rated is True


def test_normal_token_origin_uses_current_admin_not_first_grantee():
    # Guard 1: with a non-empty admin, the issuer proxy is the CURRENT admin[0],
    # NOT the historical first grantee — behavior unchanged by the fallback.
    inp = R.read_token(ASSET, 84532, rpc=_transferred_admin_asset())
    assert inp.admin_holders == [ADMIN2]        # current admin
    assert inp.issuer_has_history is False       # ADMIN2 (0 txns), not first-grantee ADMIN (16)


def test_revoked_admin_origin_unrated_when_origin_read_fails():
    # Guard 2: a fallback issuer exists, but the origin read itself fails
    # (txcount None) -> issuer_has_history None -> origin unrated. The fallback
    # must not fabricate history.
    f = _revoked_admin_asset()
    f.set_txcount(ADMIN, None)   # the first-grantee's txcount read fails
    inp = R.read_token(ASSET, 84532, rpc=f)
    assert inp.issuer_has_history is None
    res = assess(inp)
    assert res.dimensions["origin_transparency"].rated is False


# --------------------------------------------------------------------------
# #26 item 1: keep the isB20==false REFUSAL, but enrich its message; and confirm
# isB20==None (couldn't verify) still proceeds best-effort (variant_config unrated).
# --------------------------------------------------------------------------
def test_isb20_false_refusal_message_explains_reads_dont_apply():
    f = FakeRpc(84532).set_is_b20(ASSET, False)
    with pytest.raises(R.B20Unavailable) as exc:
        R.read_token(ASSET, 84532, rpc=f)
    msg = str(exc.value).lower()
    assert "not a b20" in msg                                  # cause named
    assert "do not apply" in msg or "security" in msg          # enrichment


def test_isb20_none_proceeds_and_variant_config_unrated():
    # Guard: an UNKNOWN factory read (isB20 None, not False) must NOT refuse — it
    # proceeds best-effort, factory_is_official=None, variant_config unrated.
    f = FakeRpc(84532).set_logs_fail()   # nothing programmed: isB20 None; reads fail
    inp = R.read_token(ASSET, 84532, rpc=f)
    assert inp.factory_is_official is None
    res = assess(inp)
    assert "variant_config" in res.unrated_dimensions


# --------------------------------------------------------------------------
# #24: bounded backoff at the RPC layer turns transient rate-limits into rated
# scans. Driven through the REAL RpcClient with a JSON-RPC transport shim over a
# FakeRpc, so the actual retry path runs (FakeRpc alone bypasses it).
# --------------------------------------------------------------------------
import json  # noqa: E402
import urllib.error  # noqa: E402

from acpsec_api.b20.rpc import RpcClient  # noqa: E402


def _flaky_transport(fake: FakeRpc, fail_first: int = 2):
    """JSON-RPC transport over a FakeRpc that 429s the first ``fail_first`` times
    per distinct payload, then delegates — exercising RpcClient's real retry."""
    counts: dict[str, int] = {}

    def transport(payload):
        key = json.dumps(payload, sort_keys=True)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= fail_first:
            raise urllib.error.HTTPError("https://rpc.test", 429, "Too Many Requests", {}, None)
        method, params = payload["method"], payload["params"]
        if method == "eth_call":
            res = fake.eth_call(params[0]["to"], params[0]["data"], params[1])
        elif method == "eth_getLogs":
            res = fake.eth_get_logs(params[0])
        elif method == "eth_getCode":
            res = fake.eth_get_code(params[0], params[1])
        elif method == "eth_getTransactionCount":
            res = fake.eth_get_transaction_count(params[0], params[1])
        elif method == "eth_blockNumber":
            n = fake.eth_block_number()
            res = None if n is None else hex(n)
        else:
            res = None
        return {"jsonrpc": "2.0", "id": 1, "result": res}

    return transport


def test_transient_429s_then_success_yields_fully_rated_scan():
    # Every call 429s twice then succeeds; bounded retry recovers each read, so the
    # scan is FULLY RATED. Today (no retry) each 429 -> None -> everything unrates.
    rpc = RpcClient(84532, _transport=_flaky_transport(_good_asset()), _sleep=lambda _d: None)
    res = assess(R.read_token(ASSET, 84532, rpc=rpc))
    assert res.rated is True
    assert res.unrated_dimensions == []


# --------------------------------------------------------------------------
# #24 follow-up: a provider getLogs RANGE CAP (e.g. Alchemy Free tier's 10-block
# limit) must be surfaced in the scan response — keyed by the unrated dimension,
# provider string verbatim — so the person scanning sees WHY, not just a silent
# unrated. read_diagnostics is additive and empty on a clean scan.
# --------------------------------------------------------------------------
def test_range_cap_reads_surface_read_diagnostics_verbatim():
    # Cap getLogs so hard even the chunk windows fail → role + announcement reads
    # are honestly unrated, and the scan explains why in the provider's own words.
    f = _good_asset().set_max_getlogs_range(0)
    d = assess(R.read_token(ASSET, 84532, rpc=f)).to_dict()
    diag = d["read_diagnostics"]
    assert set(diag) >= {"issuer_authority", "transfer_policy", "origin_transparency"}
    assert "range cap" in diag["issuer_authority"].lower()
    assert "10 block range" in diag["issuer_authority"]      # verbatim provider words
    assert "supply_integrity" not in diag                    # supply read succeeded


def test_clean_scan_has_empty_read_diagnostics():
    d = assess(R.read_token(ASSET, 84532, rpc=_good_asset())).to_dict()
    assert d["read_diagnostics"] == {}


def test_permanently_rate_limited_rpc_unrates_honestly():
    # Guard: bounded retries must never MASK a real failure. A permanently-429ing
    # endpoint still yields an honestly-unrated scan (not a fabricated pass).
    def always_429(payload):
        raise urllib.error.HTTPError("https://rpc.test", 429, "Too Many Requests", {}, None)

    rpc = RpcClient(84532, _transport=always_429, _sleep=lambda _d: None)
    res = assess(R.read_token(ASSET, 84532, rpc=rpc))
    assert res.rated is False
    assert set(res.unrated_dimensions) == set(res.dimensions)  # all dimensions unrated
