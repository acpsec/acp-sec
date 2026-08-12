"""Self-checking oracle: preflight verdict vs an eth_call simulation of the REAL
transfer, against base-std mock contracts on anvil (task 01, §5 / design §6).

Invariant under test: for the same (token, from, to, amount) and chain state,
    preflight(...).verdict  ==  simulate_transfer(...)
i.e. `allow` iff `eth_call transfer(to, amount){from}` succeeds, `deny` iff it
reverts (PolicyForbids / ContractPaused / InsufficientBalance). If they disagree,
one of preflight or the mock is lying.

CHECKPOINT STATE: `importorskip` skips this module today (preflight not built),
and the anvil harness fixture is stood up during IMPLEMENTATION (design decision
#2 — the recipe is validated: MockPolicyRegistry + MockB20Asset deploy standalone
on anvil, MockB20Asset.supportsInterface(0xa60bf13d)==true, a blocked transfer
reverts PolicyForbids 0xa43fec12). Marked `@pytest.mark.oracle`; CI fast lane runs
`-m "not oracle"`.
"""

import pytest

# RED/skip guard: the engine under test does not exist yet at this checkpoint.
pytest.importorskip(
    "acpsec_api.b20.preflight",
    reason="preflight engine not implemented yet (design + RED checkpoint)",
)

pytestmark = pytest.mark.oracle

# Cobalt-active token mock and blocked party (design §6 recipe).
TOKEN = "0xB2000000000000000000000000000000DeAdBeeF"
BLOCKED = "0x" + "b1" * 20
OK_FROM = "0x" + "0f" * 20
TO = "0x" + "70" * 20
BLOCKLIST_ID = 2   # first custom BLOCKLIST policy in MockPolicyRegistry


@pytest.fixture(scope="module")
def anvil_mocks():
    """Boot anvil, anvil_setCode MockPolicyRegistry (at 0x8453..0002) + MockB20Asset,
    init token storage, createPolicy(BLOCKLIST)->2, updateBlocklist(2,true,[BLOCKED]),
    token.updatePolicy(TRANSFER_SENDER_POLICY, 2), mint balances. Yields an
    RpcClient pointed at the anvil URL.

    Stood up in IMPLEMENTATION per design §6 — see the validated forge/anvil recipe
    (mocks deploy standalone; MockB20Factory is skipped as it needs forge cheatcodes).
    """
    pytest.skip("anvil + base-std-mock harness is built in the implementation phase (design §6)")


# --- the oracle: predicted verdict must equal the simulated transfer ------
def _simulate_transfer(rpc, token, from_addr, to_addr, amount):
    """Raw eth_call of transfer(to, amount) WITH `from` set (RpcClient.eth_call has
    no `from`, so the harness issues the raw JSON-RPC). Returns True on success,
    False on revert — the ground truth the preflight verdict is checked against."""
    raise NotImplementedError  # harness-only; implemented alongside anvil_mocks


@pytest.mark.parametrize(
    "from_addr, to_addr, amount, expected",
    [
        (OK_FROM, TO, 1, "allow"),        # clear
        (BLOCKED, TO, 1, "deny"),         # sender on the blocklist
    ],
)
def test_preflight_agrees_with_transfer_simulation(anvil_mocks, from_addr, to_addr, amount, expected):
    from acpsec_api.b20 import preflight as P

    rpc = anvil_mocks
    verdict = P.preflight(TOKEN, 8453, from_addr, to_addr, amount, rpc=rpc).verdict
    simulated_ok = _simulate_transfer(rpc, TOKEN, from_addr, to_addr, amount)

    # 1) preflight matches the fixture's intent, and
    assert verdict == expected
    # 2) preflight matches ground truth: allow iff the real transfer would succeed.
    assert (verdict == "allow") == simulated_ok
