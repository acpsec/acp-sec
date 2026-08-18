"""Phase 1 reader evidence: grant provenance, hasRole cross-check,
announcement EventEvidence, state evidence, read_token wiring.

See docs/b20-onchain-evidence-design-v1.md.
"""

from tests.b20.conftest import FakeRpc

from acpsec_api.b20 import constants as C
from acpsec_api.b20 import reader as R
from acpsec_api.b20.engine import assess
from acpsec_api.b20.models import EventEvidence, RoleHolderEvidence, ScanInputs, StateEvidence

ASSET = "0x" + "b2" + "00" * 9 + "00" + "aa" * 9
ADMIN_H = "0x" + "a1" * 20
MINT_H = "0x" + "a2" * 20
SEIZE_H = "0x" + "a5" * 20

TX1 = "0x" + "ab" * 32


# ── Group 1: role_holders_all carries per-holder grant evidence ──────────────

def test_role_holders_all_3tuple_carries_grant_evidence():
    """Third element of the per-role tuple maps current holders to (tx, block, log_index)."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_MINT, MINT_H, block=5, log_index=1, tx=TX1)
    allr = R.role_holders_all(f, ASSET, 84532)
    holders, first, grants = allr[C.B20_ROLE_MINT.lower()]
    assert holders == [MINT_H]
    assert grants[MINT_H] == (TX1, 5, 1)


def test_role_holders_all_revoked_holder_absent_from_grants():
    """A holder that was granted then revoked is not in holder_grants (no longer current)."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_MINT, MINT_H, 5, tx=TX1)
    f.revoke_role(C.B20_ROLE_MINT, MINT_H, 6)
    allr = R.role_holders_all(f, ASSET, 84532)
    holders, first, grants = allr[C.B20_ROLE_MINT.lower()]
    assert MINT_H not in holders
    assert MINT_H not in grants


def test_role_holders_all_absent_role_default_empty_grants():
    """A role with no events defaults to ([], None, {}) when absent from the dict."""
    allr = R.role_holders_all(FakeRpc(84532), ASSET, 84532)
    entry = allr.get(C.B20_ROLE_MINT.lower(), ([], None, {}))
    assert entry[2] == {}


def test_role_holders_all_backward_compat_index_0_and_1():
    """Existing tests that index [0] (holders) and [1] (first_grantee) still work."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_MINT, MINT_H, 5).grant_role(C.B20_ROLE_MINT, ADMIN_H, 6)
    f.revoke_role(C.B20_ROLE_MINT, MINT_H, 7)
    allr = R.role_holders_all(f, ASSET, 84532)
    entry = allr[C.B20_ROLE_MINT.lower()]
    assert entry[0] == [ADMIN_H]    # holders
    assert entry[1] == MINT_H       # first_grantee (pre-revoke grant)


# ── Group 2: read_roles returns RoleHolderEvidence ──────────────────────────

def test_read_roles_has_role_evidence_key():
    f = FakeRpc(84532).grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, 5)
    roles = R.read_roles(f, ASSET, 84532)
    assert "role_evidence" in roles


def test_read_roles_role_evidence_holder_has_grant_event():
    f = FakeRpc(84532).grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, 5, log_index=2, tx=TX1)
    roles = R.read_roles(f, ASSET, 84532)
    ev = roles["role_evidence"]
    rhe_list = ev[C.B20_ROLE_DEFAULT_ADMIN.lower()]
    assert len(rhe_list) == 1
    rhe = rhe_list[0]
    assert isinstance(rhe, RoleHolderEvidence)
    assert rhe.address == ADMIN_H
    assert rhe.grant is not None
    assert rhe.grant.tx_hash == TX1
    assert rhe.grant.block_number == 5
    assert rhe.grant.log_index == 2


def test_read_roles_no_holders_means_no_role_evidence_entry():
    """A role with no current holders is not in role_evidence."""
    f = FakeRpc(84532)  # no role events
    roles = R.read_roles(f, ASSET, 84532)
    mint_ev = roles["role_evidence"].get(C.B20_ROLE_MINT.lower(), [])
    assert mint_ev == []


def test_read_roles_multiple_holders_all_get_evidence():
    f = FakeRpc(84532)
    f.grant_role(C.B20_ROLE_MINT, ADMIN_H, 5, tx=TX1)
    f.grant_role(C.B20_ROLE_MINT, MINT_H, 6)
    roles = R.read_roles(f, ASSET, 84532)
    ev_list = roles["role_evidence"][C.B20_ROLE_MINT.lower()]
    assert len(ev_list) == 2
    addrs = {e.address for e in ev_list}
    assert addrs == {ADMIN_H, MINT_H}


def test_read_roles_failed_logs_yields_empty_role_evidence():
    """When the merged getLogs fails, role_evidence is empty (no fabricated claims)."""
    roles = R.read_roles(FakeRpc(84532).set_logs_fail(), ASSET, 84532)
    assert roles["role_evidence"] == {}


# ── Role name injection ───────────────────────────────────────────────────────

def test_read_roles_default_admin_holder_has_role_name():
    """Holders built by read_roles carry the human role name."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, 5)
    roles = R.read_roles(f, ASSET, 84532)
    rhe = roles["role_evidence"][C.B20_ROLE_DEFAULT_ADMIN.lower()][0]
    assert rhe.role_name == "DEFAULT_ADMIN"


def test_read_roles_mint_holder_has_role_name():
    f = FakeRpc(84532).grant_role(C.B20_ROLE_MINT, MINT_H, 5)
    roles = R.read_roles(f, ASSET, 84532)
    rhe = roles["role_evidence"][C.B20_ROLE_MINT.lower()][0]
    assert rhe.role_name == "MINT"


def test_read_roles_burn_role_name_resolves():
    """0xe97b...fa22 (BURN_ROLE) surfaces as 'BURN' — the hash the live scan returned."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_BURN, ADMIN_H, 5)
    roles = R.read_roles(f, ASSET, 84532)
    rhe = roles["role_evidence"][C.B20_ROLE_BURN.lower()][0]
    assert rhe.role_name == "BURN"


def test_read_roles_role_name_appears_in_serialized_output():
    """role_name flows through to_dict() so the API consumer sees it."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_SEIZE, SEIZE_H, 5)
    roles = R.read_roles(f, ASSET, 84532)
    d = roles["role_evidence"][C.B20_ROLE_SEIZE.lower()][0].to_dict()
    assert d["role"] == "SEIZE"


def test_live_fixture_three_roles_all_named():
    """Replay the three roles seen on the live mainnet token 0xb200...58b7:
    DEFAULT_ADMIN / MINT / BURN — confirms the previously unreadable BURN hash resolves.
    block_number must exceed the real grant blocks (49M range) so getLogs sees them."""
    LIVE_TOKEN = "0xb2000000000000000000002d0ba3164cc74f58b7"
    ADMIN_LIVE = "0x38467be00970af18076fd08f6b4cf38ba91572b1"
    MINT_BURN_LIVE = "0xd1ca4dacdf3231011d175351f1f02d15c7c5664c"
    f = FakeRpc(8453).set_block_number(50_200_000)   # current mainnet, above all grant blocks
    f.grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_LIVE, 49145218,
                 tx="0x21cf9d7b81f36a196db463e63cf34c3478f2a325caa9d64a46780cd42dbfdf77")
    f.grant_role(C.B20_ROLE_MINT, MINT_BURN_LIVE, 49145440,
                 tx="0x9f3b2ad542b020e505fba5332e545653d96e9f6120aab474f3b6364c33fab230")
    f.grant_role(C.B20_ROLE_BURN, MINT_BURN_LIVE, 49145602,
                 tx="0x87e7f2b7a3590c0fdfc7c4a96481000342a446549d2b159caae40d28e878b1e2")
    roles = R.read_roles(f, LIVE_TOKEN, 8453)
    ev = roles["role_evidence"]
    assert ev[C.B20_ROLE_DEFAULT_ADMIN.lower()][0].role_name == "DEFAULT_ADMIN"
    assert ev[C.B20_ROLE_MINT.lower()][0].role_name == "MINT"
    assert ev[C.B20_ROLE_BURN.lower()][0].role_name == "BURN"


# ── Group 3: hasRole cross-check ─────────────────────────────────────────────

def test_read_roles_hasrole_confirmed_true():
    """hasRole returning True → has_role.confirmed = True, discrepancy = False."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, 5)
    f.set_has_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, True)
    roles = R.read_roles(f, ASSET, 84532, as_of_block=100)
    rhe = roles["role_evidence"][C.B20_ROLE_DEFAULT_ADMIN.lower()][0]
    assert rhe.has_role is not None
    assert rhe.has_role.confirmed is True
    assert rhe.discrepancy is False


def test_read_roles_hasrole_false_sets_discrepancy():
    """hasRole returning False while replay says held → discrepancy = True (loud!)."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, 5)
    f.set_has_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, False)
    roles = R.read_roles(f, ASSET, 84532, as_of_block=100)
    rhe = roles["role_evidence"][C.B20_ROLE_DEFAULT_ADMIN.lower()][0]
    assert rhe.has_role.confirmed is False
    assert rhe.discrepancy is True


def test_read_roles_hasrole_absent_stays_none():
    """No hasRole response → has_role = None (never fabricated)."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, 5)
    # No set_has_role → eth_call returns None
    roles = R.read_roles(f, ASSET, 84532, as_of_block=100)
    rhe = roles["role_evidence"][C.B20_ROLE_DEFAULT_ADMIN.lower()][0]
    assert rhe.has_role is None


def test_read_roles_hasrole_anchors_at_as_of_block():
    """has_role.block_number equals the as_of_block passed in."""
    f = FakeRpc(84532).grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, 5)
    f.set_has_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, True)
    roles = R.read_roles(f, ASSET, 84532, as_of_block=42)
    rhe = roles["role_evidence"][C.B20_ROLE_DEFAULT_ADMIN.lower()][0]
    assert rhe.has_role.block_number == 42


# ── Group 4: announcement EventEvidence ─────────────────────────────────────

def test_read_origin_returns_announcement_evidence_key():
    f = FakeRpc(84532).set_announcements(1)
    f.set_txcount(ADMIN_H, "0x10")
    origin = R.read_origin(f, ASSET, [ADMIN_H], 84532)
    assert "announcement_evidence" in origin


def test_read_origin_announcement_evidence_contains_event_evidence():
    f = FakeRpc(84532)
    f.announcement_logs = [{
        "topics": [C.B20_EVENT_ANNOUNCEMENT],
        "blockNumber": "0x64",       # 100
        "logIndex": "0x1",
        "transactionHash": "0xdeadbeef" + "00" * 28,
    }]
    f.set_txcount(ADMIN_H, "0x10")
    origin = R.read_origin(f, ASSET, [ADMIN_H], 84532)
    evs = origin["announcement_evidence"]
    assert len(evs) == 1
    ev = evs[0]
    assert isinstance(ev, EventEvidence)
    assert ev.tx_hash == "0xdeadbeef" + "00" * 28
    assert ev.block_number == 100
    assert ev.log_index == 1


def test_read_origin_multiple_announcements_all_get_evidence():
    f = FakeRpc(84532).set_announcements(3)
    f.set_txcount(ADMIN_H, "0x10")
    origin = R.read_origin(f, ASSET, [ADMIN_H], 84532)
    assert len(origin["announcement_evidence"]) == 3


def test_read_origin_no_announcements_returns_empty_list():
    f = FakeRpc(84532)
    f.set_txcount(ADMIN_H, "0x10")
    origin = R.read_origin(f, ASSET, [ADMIN_H], 84532)
    assert origin["announcement_evidence"] == []


def test_read_origin_failed_logs_returns_empty_evidence():
    """Failed announcement read → empty evidence list, not fabricated."""
    f = FakeRpc(84532).set_logs_fail()
    f.set_txcount(ADMIN_H, "0x10")
    origin = R.read_origin(f, ASSET, [ADMIN_H], 84532)
    assert origin["announcement_evidence"] == []


# ── Group 5: read_token wires up ScanInputs evidence fields ─────────────────

def _good_asset_rpc() -> FakeRpc:
    """Minimal FakeRpc that passes read_token and allows evidence collection."""
    f = FakeRpc(84532)
    f.set_is_b20(ASSET, True)
    f.set_is_b20_initialized(ASSET, True)
    f.set_activated("ASSET", True)
    f.grant_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, 1, log_index=0, tx=TX1)
    f.set_code(ADMIN_H, "0x6080604052")
    f.grant_role(C.B20_ROLE_SEIZE, SEIZE_H, 5)
    f.revoke_role(C.B20_ROLE_SEIZE, SEIZE_H, 6)
    f.set_selector(C.B20_SELECTOR_SUPPLY_CAP, "0x" + R.enc_uint(10 ** 24))
    f.set_selector(C.B20_SELECTOR_MULTIPLIER, "0x" + R.enc_uint(10 ** 18))
    f.set_call(R.calldata(C.B20_SELECTOR_POLICY_ID, R.word(C.B20_POLICY_TRANSFER_SENDER)),
               "0x" + R.enc_uint(0))
    f.set_call(R.calldata(C.B20_SELECTOR_POLICY_ID, R.word(C.B20_POLICY_TRANSFER_RECEIVER)),
               "0x" + R.enc_uint(0))
    f.set_call(R.calldata(C.B20_SELECTOR_IS_PAUSED, R.enc_uint(C.B20_PAUSABLE_TRANSFER)),
               "0x" + R.enc_uint(0))
    f.set_selector(C.B20_SELECTOR_DECIMALS, "0x" + R.enc_uint(18))
    f.set_txcount(ADMIN_H, "0x10")
    f.set_announcements(1)
    return f


def test_read_token_populates_as_of_block():
    f = _good_asset_rpc()
    f.block_number = 9999
    inp = R.read_token(ASSET, 84532, rpc=f)
    assert inp.as_of_block == 9999


def test_read_token_populates_role_evidence():
    inp = R.read_token(ASSET, 84532, rpc=_good_asset_rpc())
    assert isinstance(inp.role_evidence, dict)
    # Admin holder has a grant → role_evidence includes an entry for DEFAULT_ADMIN
    admin_ev = inp.role_evidence.get(C.B20_ROLE_DEFAULT_ADMIN.lower(), [])
    assert len(admin_ev) == 1
    assert isinstance(admin_ev[0], RoleHolderEvidence)


def test_read_token_populates_announcement_evidence():
    inp = R.read_token(ASSET, 84532, rpc=_good_asset_rpc())
    assert isinstance(inp.announcement_evidence, list)
    assert len(inp.announcement_evidence) == 1
    assert isinstance(inp.announcement_evidence[0], EventEvidence)


def test_read_token_state_evidence_supply_cap():
    inp = R.read_token(ASSET, 84532, rpc=_good_asset_rpc())
    assert "supply_cap" in inp.state_evidence
    ev = inp.state_evidence["supply_cap"]
    assert isinstance(ev, StateEvidence)
    assert ev.block_number is not None
    assert ev.raw_value is not None
    # raw_value is the ABI-encoded uint256: anyone can verify at ev.block_number
    assert ev.raw_value.startswith("0x")


def test_read_token_state_evidence_decimals():
    inp = R.read_token(ASSET, 84532, rpc=_good_asset_rpc())
    assert "decimals" in inp.state_evidence
    ev = inp.state_evidence["decimals"]
    assert isinstance(ev, StateEvidence)
    assert ev.block_number is not None


def test_evidence_never_changes_verdict():
    """Evidence fields are additive only; adding them must not alter trust_score or grade."""
    f = _good_asset_rpc()
    f.set_has_role(C.B20_ROLE_DEFAULT_ADMIN, ADMIN_H, True)
    inp_with_ev = R.read_token(ASSET, 84532, rpc=f)

    # Strip evidence; keep every scoring input identical.
    inp_no_ev = ScanInputs(
        token=inp_with_ev.token, chain_id=inp_with_ev.chain_id,
        variant=inp_with_ev.variant, decimals=inp_with_ev.decimals,
        currency_code=inp_with_ev.currency_code,
        admin_holders=inp_with_ev.admin_holders,
        admin_is_multisig=inp_with_ev.admin_is_multisig,
        admin_roles_revoked=inp_with_ev.admin_roles_revoked,
        mint_role_holders=inp_with_ev.mint_role_holders,
        burn_role_holders=inp_with_ev.burn_role_holders,
        pause_role_holders=inp_with_ev.pause_role_holders,
        pause_holder_is_multisig=inp_with_ev.pause_holder_is_multisig,
        supply_cap=inp_with_ev.supply_cap, multiplier_active=inp_with_ev.multiplier_active,
        burn_enabled=inp_with_ev.burn_enabled,
        policy_registry_active=inp_with_ev.policy_registry_active,
        can_freeze=inp_with_ev.can_freeze, can_seize=inp_with_ev.can_seize,
        can_burn_blocked=inp_with_ev.can_burn_blocked, can_pause=inp_with_ev.can_pause,
        is_paused=inp_with_ev.is_paused, asymmetric_policy=inp_with_ev.asymmetric_policy,
        deployed_via_factory=inp_with_ev.deployed_via_factory,
        factory_is_official=inp_with_ev.factory_is_official,
        issuer_wallet_age_days=inp_with_ev.issuer_wallet_age_days,
        issuer_has_history=inp_with_ev.issuer_has_history,
        verified_entity=inp_with_ev.verified_entity, public_docs=inp_with_ev.public_docs,
        announcement_events=inp_with_ev.announcement_events,
        read_diagnostics=inp_with_ev.read_diagnostics,
    )
    _AT = "2026-01-01T00:00:00Z"
    r1 = assess(inp_with_ev, scanned_at=_AT)
    r2 = assess(inp_no_ev, scanned_at=_AT)
    assert r1.trust_score == r2.trust_score
    assert r1.grade == r2.grade
