"""EIP-7702 delegated EOAs must classify as single keys, not contracts/multisig.

Post-Cobalt (native AA), an EOA can carry a 7702 delegation designator: eth_getCode
returns ``0xef0100 || <20-byte delegate>`` (23 bytes) instead of ``0x``. The old
``_is_contract`` treated ANY non-empty code as a contract, so a delegated deployer
EOA read as ``admin_is_multisig=True`` — suppressing the single-EOA-admin High and
its critical, and hiding a bare mint key from #69.

Live ground truth (2026-09-25): our deployer 0x197C7433d7b500691AD2eCEf4dffc1B01C123dfA
returns 0xef010063c0c19a282a1b52b07dd5a65b58948a07dae32b on Base Sepolia (delegated),
0x on mainnet (bare). A delegation is key-controlled and revocable — still ONE key.
"""

from acpsec_api.b20 import reader as R
from acpsec_api.b20.dimensions import run_issuer_authority
from acpsec_api.b20.engine import CRITICAL_SINGLE_EOA_ADMIN, detect_critical
from acpsec_api.b20.models import ScanInputs
from tests.b20.conftest import FakeRpc

DELEGATED = "0xef0100" + "63c0c19a282a1b52b07dd5a65b58948a07dae32b"  # real Sepolia designator
EOA = "0x197c7433d7b500691ad2ecef4dffc1b01c123dfa"
CONTRACT = "0x1111111111111111111111111111111111111111"
BARE = "0x2222222222222222222222222222222222222222"


def _rpc(**code):
    f = FakeRpc(84532)
    for addr, c in code.items():
        f.code[addr.lower()] = c
    return f


# --- _delegation_target (pure) --------------------------------------------
def test_delegation_target_extracts_delegate():
    assert R._delegation_target(DELEGATED) == "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b"


def test_delegation_target_none_for_plain_contract_or_eoa():
    assert R._delegation_target("0x") is None
    assert R._delegation_target("0x6080604052348015") is None      # normal bytecode
    assert R._delegation_target(None) is None


# --- _is_contract ----------------------------------------------------------
def test_is_contract_false_for_delegated_eoa():
    assert R._is_contract(_rpc(**{EOA: DELEGATED}), EOA) is False


def test_is_contract_true_for_real_contract():
    assert R._is_contract(_rpc(**{CONTRACT: "0x60806040f3"}), CONTRACT) is True


def test_is_contract_false_for_bare_eoa_none_for_unreadable():
    assert R._is_contract(_rpc(**{BARE: "0x"}), BARE) is False
    assert R._is_contract(_rpc(), "0x9999999999999999999999999999999999999999") is None


# --- _classify_multisig ----------------------------------------------------
def test_classify_multisig_false_for_single_delegated_eoa():
    # The core regression: a delegated admin EOA must NOT read as multisig.
    assert R._classify_multisig(_rpc(**{EOA: DELEGATED}), [EOA]) is False


def test_classify_multisig_true_for_real_contract():
    assert R._classify_multisig(_rpc(**{CONTRACT: "0x60806040f3"}), [CONTRACT]) is True


# --- _classify_mint_eoa (#69) ---------------------------------------------
def test_classify_mint_eoa_includes_delegated_as_bare_key():
    # A delegated mint holder is still a single key -> must be flagged a bare EOA.
    assert R._classify_mint_eoa(_rpc(**{EOA: DELEGATED}), [EOA]) == [EOA]


# --- _classify_delegated_eoa (honest surfacing) ---------------------------
def test_classify_delegated_eoa_detects_designator():
    assert R._classify_delegated_eoa(_rpc(**{EOA: DELEGATED}), [EOA]) is True
    assert R._classify_delegated_eoa(_rpc(**{BARE: "0x"}), [BARE]) is False
    assert R._classify_delegated_eoa(_rpc(), None) is None


# --- dimension + engine integration ---------------------------------------
def _inp(**over):
    base = dict(
        token="0xb20000000000000000000000000000000000dead", chain_id=84532,
        variant="ASSET", admin_holders=[EOA], admin_is_multisig=False,
        admin_is_delegated_eoa=True,
    )
    base.update(over)
    return ScanInputs(**base)


def test_delegated_single_admin_still_fires_single_eoa_critical():
    assert CRITICAL_SINGLE_EOA_ADMIN in detect_critical(_inp())


def test_issuer_authority_surfaces_delegation_note():
    dim = run_issuer_authority(_inp())
    details = [f.detail for f in dim.findings]
    assert any("non-multisig EOA" in d for d in details), details
    assert any("delegation" in d.lower() for d in details), details


def test_no_delegation_note_when_admin_is_plain_eoa():
    dim = run_issuer_authority(_inp(admin_is_delegated_eoa=False))
    assert not any("delegation" in f.detail.lower() for f in dim.findings)
