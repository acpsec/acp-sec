"""B20 Preflight verdict engine — unit guards over the shared FakeRpc (no network).

RED CHECKPOINT (task 01): these import `acpsec_api.b20.preflight`, which does NOT
exist yet, so the module fails to collect — that IS the red. They define the
contract the implementation must satisfy:

- activation gate FIRST: pre-Cobalt short-circuits to `unavailable`, no policy reads;
- clear transfer -> `allow`; blocked sender/receiver -> `deny` NAMING the scope + policy_id;
- evaluation order mirrors MockB20Asset.transfer: pause > sender policy > receiver
  policy > balance (so the §6 oracle can agree);
- a failed read -> `unavailable` with a diagnostic, NEVER a false `allow`;
- response shape {verdict, reasons, as_of_block, evidence_tier} + tier mapping.

See docs/b20-preflight-design-v1.md.
"""

from tests.b20.conftest import FakeRpc

from acpsec_api.b20 import constants as C
from acpsec_api.b20 import reader as R
from acpsec_api.b20 import preflight as P   # RED: module not implemented yet

# --- addresses ------------------------------------------------------------
TOKEN = "0x" + "b2" + "00" * 9 + "00" + "aa" * 9   # ASSET (byte[10]==0x00)
FROM = "0x" + "f1" * 20
TO = "0x" + "70" * 20

# --- selectors the implementation must use (contract) ---------------------
SEL_SUPPORTS_INTERFACE = "0x01ffc9a7"       # ERC-165 supportsInterface(bytes4)
IFACE_ERC8056 = "a60bf13d"                  # bytes4 arg (LEFT-aligned, not enc_uint)
SEL_IS_AUTHORIZED = "0x55a1179e"            # PolicyRegistry.isAuthorized(uint64,address)
SEL_BALANCE_OF = "0x70a08231"               # balanceOf(address)


# --- calldata builders (keys into FakeRpc.responses; `to` is ignored) -----
def _b4(hex4: str) -> str:
    return hex4.ljust(64, "0")   # 4 bytes, left-aligned in a 32-byte word


def cd_supports(iface: str = IFACE_ERC8056) -> str:
    return SEL_SUPPORTS_INTERFACE + _b4(iface)


def cd_is_paused(feature: int = C.B20_PAUSABLE_TRANSFER) -> str:
    return R.calldata(C.B20_SELECTOR_IS_PAUSED, R.enc_uint(feature))


def cd_policy_id(scope: str) -> str:
    return R.calldata(C.B20_SELECTOR_POLICY_ID, R.word(scope))


def cd_authorized(pid: int, acct: str) -> str:
    return SEL_IS_AUTHORIZED + R.enc_uint(pid) + R.enc_address(acct)


def cd_balance(acct: str) -> str:
    return SEL_BALANCE_OF + R.enc_address(acct)


def _bw(b: bool) -> str:
    return "0x" + R.enc_uint(1 if b else 0)


def _uw(n: int) -> str:
    return "0x" + R.enc_uint(n)


# --- fixture builder: a fully-programmed Cobalt-active token --------------
def _rpc(
    *, cobalt=True, paused=False, sender_pid=0, receiver_pid=0,
    sender_auth=True, receiver_auth=True, from_bal=1000,
) -> FakeRpc:
    f = FakeRpc(8453)
    f.set_call(cd_supports(), _bw(cobalt))
    f.set_call(cd_is_paused(), _bw(paused))
    f.set_call(cd_policy_id(C.B20_POLICY_TRANSFER_SENDER), _uw(sender_pid))
    f.set_call(cd_policy_id(C.B20_POLICY_TRANSFER_RECEIVER), _uw(receiver_pid))
    if sender_pid != 0:
        f.set_call(cd_authorized(sender_pid, FROM), _bw(sender_auth))
    if receiver_pid != 0:
        f.set_call(cd_authorized(receiver_pid, TO), _bw(receiver_auth))
    f.set_call(cd_balance(FROM), _uw(from_bal))
    return f


def _run(rpc, amount=100):
    return P.preflight(TOKEN, 8453, FROM, TO, amount, rpc=rpc)


# ── 1. Activation gate FIRST ─────────────────────────────────────────────
def test_pre_cobalt_chain_short_circuits_unavailable():
    f = _rpc(cobalt=False)
    v = _run(f).to_dict()
    assert v["verdict"] == "unavailable"
    assert any(r["code"] == "not_cobalt" for r in v["reasons"])
    assert v["evidence_tier"] == "unknown"
    # short-circuit: no policy reads attempted after the gate fails
    assert cd_policy_id(C.B20_POLICY_TRANSFER_SENDER) not in f.calls


def test_gate_read_failure_is_unavailable_not_allow():
    f = _rpc()
    f.set_call(cd_supports(), None)   # activation probe read fails
    v = _run(f).to_dict()
    assert v["verdict"] == "unavailable"
    assert any(r["code"] == "read_failed" for r in v["reasons"])


# ── Activation-probe failure taxonomy (issue #41) ────────────────────────
# A DEFINITIVE contract revert (chain answering "this contract has no ERC-165")
# is not_cobalt; a TRANSPORT failure (timeout/429/unreachable — no contract
# answer) stays read_failed. Both remain `unavailable` (no false allow).
_REVERT_ERR = "rpc error: {'code': 3, 'message': 'execution reverted', 'data': '0x01ffc9a7'}"


def _gate_fails(last_error, any_response):
    """A fully-programmed token whose activation probe returns no value, with the
    RpcClient diagnostic surface set to the given failure shape."""
    f = _rpc()
    f.set_call(cd_supports(), None)
    f.last_error = last_error
    f.any_response = any_response
    return f


def test_gate_definitive_revert_is_not_cobalt_with_evidence():
    # Real precompile: execution reverted, selector echoed (0x01ffc9a7) — the chain
    # DID answer "no ERC-165". This must be not_cobalt, not read_failed. #41.
    f = _gate_fails(_REVERT_ERR, any_response=True)
    v = _run(f).to_dict()
    assert v["verdict"] == "unavailable"
    codes = [r["code"] for r in v["reasons"]]
    assert "not_cobalt" in codes and "read_failed" not in codes
    detail = next(r["detail"] for r in v["reasons"] if r["code"] == "not_cobalt")
    assert "revert" in detail.lower() and "erc-165" in detail.lower()
    # short-circuit: no policy reads once the gate resolves not_cobalt
    assert cd_policy_id(C.B20_POLICY_TRANSFER_SENDER) not in f.calls


def test_gate_timeout_is_read_failed():
    # Timeout: node never answered (any_response False) → transport, not a contract revert.
    f = _gate_fails("TimeoutError: timed out", any_response=False)
    v = _run(f).to_dict()
    codes = [r["code"] for r in v["reasons"]]
    assert v["verdict"] == "unavailable"
    assert "read_failed" in codes and "not_cobalt" not in codes


def test_gate_rate_limit_is_read_failed():
    # 429 is REACHABLE (any_response True) but NOT a contract answer → read_failed,
    # never mistaken for not_cobalt.
    f = _gate_fails("http error: 429 Too Many Requests", any_response=True)
    v = _run(f).to_dict()
    codes = [r["code"] for r in v["reasons"]]
    assert v["verdict"] == "unavailable"
    assert "read_failed" in codes and "not_cobalt" not in codes


def test_gate_failure_never_allows_regardless_of_shape():
    # no-false-allow: neither a revert nor a transport failure may ever yield `allow`.
    for f in (
        _gate_fails(_REVERT_ERR, any_response=True),
        _gate_fails("TimeoutError: timed out", any_response=False),
        _gate_fails("http error: 429 Too Many Requests", any_response=True),
    ):
        assert _run(f).to_dict()["verdict"] == "unavailable"


# ── 2. Clear transfer allows ─────────────────────────────────────────────
def test_clear_transfer_allows():
    v = _run(_rpc()).to_dict()   # pids 0 (always-allow), not paused, balance ok
    assert v["verdict"] == "allow"
    assert v["reasons"] == []
    assert v["deny_class"] is None
    assert v["evidence_tier"] == "verified"
    assert v["as_of_block"] == 100   # FakeRpc.block_number default


# ── 3. Deny NAMES the blocking scope + policy_id, + deny_class discriminator ──
def test_blocked_sender_denies_naming_scope():
    v = _run(_rpc(sender_pid=2, sender_auth=False)).to_dict()
    assert v["verdict"] == "deny"
    assert v["deny_class"] == "policy"      # structural power ("contact the issuer")
    r = next(r for r in v["reasons"] if r["code"] == "policy_forbids")
    assert r["scope"] == "TRANSFER_SENDER_POLICY"
    assert r["policy_id"] == 2
    assert v["evidence_tier"] == "verified"


def test_blocked_receiver_denies_naming_scope():
    v = _run(_rpc(receiver_pid=3, receiver_auth=False)).to_dict()
    assert v["verdict"] == "deny"
    assert v["deny_class"] == "policy"
    r = next(r for r in v["reasons"] if r["code"] == "policy_forbids")
    assert r["scope"] == "TRANSFER_RECEIVER_POLICY"
    assert r["policy_id"] == 3


# ── 4. Ordering parity with MockB20Asset.transfer revert order ───────────
def test_pause_precedes_policy():
    # paused AND sender blocked -> pause wins (revert order: pause first).
    v = _run(_rpc(paused=True, sender_pid=2, sender_auth=False)).to_dict()
    assert v["verdict"] == "deny"
    assert v["reasons"][0]["code"] == "paused"


def test_sender_policy_precedes_receiver():
    v = _run(_rpc(sender_pid=2, sender_auth=False, receiver_pid=3, receiver_auth=False)).to_dict()
    assert v["reasons"][0]["scope"] == "TRANSFER_SENDER_POLICY"


def test_balance_checked_after_policy():
    # sender blocked AND insufficient balance -> policy wins (balance is step 5).
    v = _run(_rpc(sender_pid=2, sender_auth=False, from_bal=0), amount=100).to_dict()
    assert v["reasons"][0]["code"] == "policy_forbids"


def test_insufficient_balance_denies():
    v = _run(_rpc(from_bal=50), amount=100).to_dict()
    assert v["verdict"] == "deny"
    assert v["deny_class"] == "balance"     # transient condition ("top up")
    assert any(r["code"] == "insufficient_balance" for r in v["reasons"])


def test_paused_denies():
    v = _run(_rpc(paused=True)).to_dict()
    assert v["verdict"] == "deny"
    assert v["deny_class"] == "state"       # transient condition (issuer paused transfers)
    assert any(r["code"] == "paused" for r in v["reasons"])


# ── 5. A failed read -> unavailable, NEVER a false allow ─────────────────
def test_isauthorized_read_failure_is_unavailable_not_allow():
    f = _rpc(sender_pid=2)
    f.set_call(cd_authorized(2, FROM), None)   # evaluator read fails
    v = _run(f).to_dict()
    assert v["verdict"] == "unavailable"          # NOT "allow"
    assert any(r["code"] == "read_failed" for r in v["reasons"])
    assert v["evidence_tier"] == "unknown"


def test_gate_passes_but_policy_read_reverts_falls_through_to_unavailable():
    # Refinement (3): supportsInterface(0xa60bf13d) is an ERC-8056-core proxy, NOT
    # proof the policy surface is live. If the gate PASSES but a policy read then
    # reverts/fails, that must be unavailable(read_failed) — never allow, never
    # not_cobalt.
    f = _rpc()
    f.set_call(cd_policy_id(C.B20_POLICY_TRANSFER_SENDER), None)  # policyId reverts
    v = _run(f).to_dict()
    assert v["verdict"] == "unavailable"
    codes = {r["code"] for r in v["reasons"]}
    assert "read_failed" in codes
    assert "not_cobalt" not in codes              # gate passed; this is a real read failure


def test_balance_read_failure_is_unavailable_not_allow():
    f = _rpc()
    f.set_call(cd_balance(FROM), None)
    v = _run(f).to_dict()
    assert v["verdict"] == "unavailable"
    assert any(r["code"] == "read_failed" for r in v["reasons"])


# ── 6. Response shape ────────────────────────────────────────────────────
def test_response_shape_keys():
    v = _run(_rpc()).to_dict()
    assert set(v.keys()) == {"verdict", "reasons", "as_of_block", "evidence_tier", "deny_class"}
    for r in v["reasons"]:
        assert set(r.keys()) >= {"code", "detail"}
