"""Regression guard (task 2.3): the acp-sec source_verified -> CRITICAL pathway
must never exist for B20 tokens (they have no Solidity source).
"""

from dataclasses import fields

from acpsec_api.b20.engine import detect_critical
from acpsec_api.b20.models import ScanInputs


def test_b20_token_without_source_is_not_auto_critical():
    # A well-configured B20 token (which inherently has no verified source) must
    # not be flagged critical for anything source-related.
    inp = ScanInputs(
        token="0xB200", chain_id=8453,
        supply_cap=1_000_000 * 10**18,
        factory_is_official=True,
        admin_holders=["0xaaa"], admin_is_multisig=True,
    )
    assert detect_critical(inp) == []


def test_scan_inputs_has_no_source_verified_field():
    # Guard against re-introducing acp-sec's source-verification concept.
    names = {f.name for f in fields(ScanInputs)}
    assert "source_verified" not in names
    assert not any("source" in n for n in names)
