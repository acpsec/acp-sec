"""Token creation-block lookup via eth_getCode binary search (Option 1).

Public Base RPC caps eth_getLogs at 2000 blocks, so a B20Created log lookup over
full history is infeasible (~21K calls). B20 tokens have bytecode, so we instead
binary-search for the first block at which the token has code (~log2(height)
eth_getCode calls), then bound the role/announcement scans to [creation, latest].
"""

from tests.b20.conftest import FakeRpc

from acpsec_api.b20 import reader as R

ASSET = "0x" + "b2" + "00" * 9 + "00" + "aa" * 9


def test_binary_search_finds_first_code_block():
    # code absent before block 100, present from 100 on; latest=1000.
    f = FakeRpc(84532).set_block_number(1000).set_creation_code(ASSET, 100, "0xef")
    assert R.get_creation_block(f, ASSET, 84532) == 100
    assert len(f.getcode_calls) <= 25  # bounded: ~log2(1000)+1, never the 21K scan


def test_genesis_deployment_returns_zero():
    # token has code at every block (deployed at/by block 0).
    f = FakeRpc(84532).set_block_number(1000).set_creation_code(ASSET, 0, "0xef")
    assert R.get_creation_block(f, ASSET, 84532) == 0


def test_no_code_anywhere_returns_none():
    # token never deployed: no code even at latest -> not a creation, give up.
    f = FakeRpc(84532).set_block_number(1000)  # ASSET absent from code maps
    assert R.get_creation_block(f, ASSET, 84532) is None


def test_rpc_failure_midway_returns_none():
    # by-block eth_getCode starts failing -> None (caller degrades to a window).
    f = (FakeRpc(84532).set_block_number(1000)
         .set_creation_code(ASSET, 100, "0xef").set_getcode_fail())
    assert R.get_creation_block(f, ASSET, 84532) is None


def test_block_number_failure_returns_none():
    f = FakeRpc(84532).set_creation_code(ASSET, 100, "0xef")
    f.block_number = None  # eth_block_number -> None
    assert R.get_creation_block(f, ASSET, 84532) is None
