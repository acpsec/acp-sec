"""Self-checking oracle: preflight verdict vs an eth_call simulation of the REAL
transfer, against base-std mock contracts on anvil (task 01, §5 / design §6).

Invariant: for the same (token, from, to, amount) and chain state,
    preflight(...).verdict  ==  simulate_transfer(...)
`allow` iff `eth_call transfer(to, amount){from}` succeeds; `deny` iff it reverts
(PolicyForbids / ContractPaused / InsufficientBalance). If they disagree, one of
preflight or the mock is lying.

Opt-in (like the `network` marker): set B20_ORACLE=1 AND have forge/anvil on PATH
AND a built base-std checkout (BASE_STD_DIR, default /tmp/cobalt-data/base-std with
`forge build` run). Otherwise skipped. CI fast lane never sets B20_ORACLE.
Run: `B20_ORACLE=1 .venv/bin/pytest tests/b20/test_preflight_oracle.py -m oracle`.
"""

import json
import os
import shutil
import socket
import subprocess
import time

import pytest

pytest.importorskip("acpsec_api.b20.preflight", reason="preflight engine not implemented")

from acpsec_api.b20 import preflight as P          # noqa: E402
from acpsec_api.b20.rpc import RpcClient            # noqa: E402

pytestmark = pytest.mark.oracle

# --- deterministic anvil account 0 (the policy admin / tx signer) ----------
ADMIN = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

REGISTRY = "0x8453000000000000000000000000000000000002"   # PolicyRegistry precompile
TOKEN = "0xb2000000000000000000000000000000deadbeef"       # MockB20Asset (Cobalt-active)
BLOCKED = "0x" + "b1" * 20
OK_FROM = "0x" + "0f" * 20
TO = "0x" + "70" * 20
SENDER_SCOPE = "0xb81736c875ab819dd97f59f2a6542cfb731ad52b4ae15a6f24df2fb02b0327f5"

# base.b20 ERC-7201 namespace + field offsets (MockB20Storage.sol): slot = base + offset.
_STORAGE_BASE = 0xC78B71FEE795DDD74AFF64EA9B2474194C938C3196430E10BB5F01ED48434000
SLOT_TRANSFER_POLICY_IDS = hex(_STORAGE_BASE + 9)   # {sender,receiver,executor} packed uint64
BASE_BALANCES = hex(_STORAGE_BASE + 4)              # mapping(address=>uint256) base slot


def _base_std_dir() -> str:
    return os.environ.get("BASE_STD_DIR", "/tmp/cobalt-data/base-std")


def _deployed_bytecode(contract: str) -> str:
    p = os.path.join(_base_std_dir(), "out", f"{contract}.sol", f"{contract}.json")
    obj = json.load(open(p))["deployedBytecode"]["object"]
    return obj if obj.startswith("0x") else "0x" + obj


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def anvil_mocks():
    """Boot anvil, deploy+configure the base-std mocks per design §6 (validated
    spike), and yield an RpcClient pointed at anvil. See module docstring for opt-in."""
    if not os.environ.get("B20_ORACLE"):
        pytest.skip("set B20_ORACLE=1 to run the anvil oracle")
    if not (shutil.which("anvil") and shutil.which("cast")):
        pytest.skip("forge/anvil not on PATH")
    try:
        reg_code = _deployed_bytecode("MockPolicyRegistry")
        tok_code = _deployed_bytecode("MockB20Asset")
    except (OSError, KeyError):
        pytest.skip(f"base-std artifacts not built under {_base_std_dir()} (run `forge build`)")

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    def cast(*args, expect_ok=True):
        r = subprocess.run(["cast", *args, "--rpc-url", url],
                           capture_output=True, text=True)
        if expect_ok and r.returncode != 0:
            raise RuntimeError(f"cast {args[0]} failed: {r.stderr.strip()}")
        return r

    try:
        # wait for the node to accept connections
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

        # deploy mocks at their canonical addresses
        cast("rpc", "anvil_setCode", REGISTRY, reg_code)
        cast("rpc", "anvil_setCode", TOKEN, tok_code)
        # poke token storage: transferPolicyIds.sender = 2, balances[OK_FROM] = 1000
        word2 = "0x" + "0" * 63 + "2"
        cast("rpc", "anvil_setStorageAt", TOKEN, SLOT_TRANSFER_POLICY_IDS, word2)
        # `cast index` is a pure keccak computation — no --rpc-url (would error).
        bal_slot = subprocess.run(
            ["cast", "index", "address", OK_FROM, BASE_BALANCES],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        cast("rpc", "anvil_setStorageAt", TOKEN, bal_slot, "0x" + hex(1000)[2:].rjust(64, "0"))
        # registry: create BLOCKLIST policy (id 2) and block BLOCKED
        cast("send", "--private-key", PK, REGISTRY, "createPolicy(address,uint8)", ADMIN, "0")
        cast("send", "--private-key", PK, REGISTRY,
             "updateBlocklist(uint64,bool,address[])", "2", "true", f"[{BLOCKED}]")

        os.environ["B20_RPC_URL_8453"] = url
        yield RpcClient(8453)
    finally:
        os.environ.pop("B20_RPC_URL_8453", None)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _simulate_transfer(url, from_addr, amount) -> bool:
    """Ground truth: eth_call transfer(TO, amount) WITH `from`. True iff it does not
    revert. (RpcClient.eth_call has no `from`, so shell out to `cast call --from`.)"""
    r = subprocess.run(
        ["cast", "call", "--rpc-url", url, "--from", from_addr, TOKEN,
         "transfer(address,uint256)(bool)", TO, str(amount)],
        capture_output=True, text=True,
    )
    return r.returncode == 0 and r.stdout.strip().startswith("true")


@pytest.mark.parametrize(
    "from_addr, expected",
    [(OK_FROM, "allow"), (BLOCKED, "deny")],
)
def test_preflight_agrees_with_transfer_simulation(anvil_mocks, from_addr, expected):
    rpc = anvil_mocks
    verdict = P.preflight(TOKEN, 8453, from_addr, TO, 1, rpc=rpc).verdict
    simulated_ok = _simulate_transfer(rpc.url, from_addr, 1)

    assert verdict == expected                       # matches the fixture's intent, and
    assert (verdict == "allow") == simulated_ok      # matches ground truth (no lying)


def test_blocked_sender_names_the_scope(anvil_mocks):
    v = P.preflight(TOKEN, 8453, BLOCKED, TO, 1, rpc=anvil_mocks).to_dict()
    assert v["verdict"] == "deny" and v["deny_class"] == "policy"
    r = next(r for r in v["reasons"] if r["code"] == "policy_forbids")
    assert r["scope"] == "TRANSFER_SENDER_POLICY" and r["policy_id"] == 2
