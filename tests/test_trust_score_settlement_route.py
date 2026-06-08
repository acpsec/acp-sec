"""Tests for acpsec/trust_score/data/settlement_route.py — TDD.

Guardrail A: the 95/5 and 90/5/5 fee split is enforced by the official ACP Core
Job contract, not by the agent. If the agent settles via the official ACP Core,
the split is conformant by construction and must not be flagged. Only a
custom/forked settlement contract is analysed; an undeterminable path is Unrated.
"""

from acpsec.trust_score.data.basescan import ContractData
from acpsec.trust_score.data.settlement_route import (
    ROUTE_CUSTOM,
    ROUTE_OFFICIAL_CORE,
    SettlementRouteResolver,
    assess_fee_split,
    is_conformant_split,
)

ACP_CORE = "0x238E541BfefD82238730D00a2208E5497F1832E0"


def _contract(address="0xABCDef0000000000000000000000000000000000",
              source="pragma solidity ^0.8.0;"):
    return ContractData(
        address=address,
        source_verified=True,
        contract_name="X",
        abi=[],
        source_code=source,
        compiler_version="v0.8.20",
    )


# ---------------------------------------------------------------------------
# Conformant split shapes
# ---------------------------------------------------------------------------

class TestIsConformantSplit:
    def test_95_5_is_conformant(self):
        assert is_conformant_split((95, 5)) is True

    def test_90_5_5_is_conformant(self):
        assert is_conformant_split((90, 5, 5)) is True

    def test_80_20_is_not_conformant(self):
        assert is_conformant_split((80, 20)) is False

    def test_single_value_is_not_conformant(self):
        assert is_conformant_split((100,)) is False


# ---------------------------------------------------------------------------
# Pure assessment from (route, split)
# ---------------------------------------------------------------------------

class TestAssessFeeSplit:
    def test_official_core_is_conformant(self):
        assert assess_fee_split(ROUTE_OFFICIAL_CORE, None) is False

    def test_custom_conformant_95_5_false(self):
        assert assess_fee_split(ROUTE_CUSTOM, (95, 5)) is False

    def test_custom_conformant_90_5_5_false(self):
        assert assess_fee_split(ROUTE_CUSTOM, (90, 5, 5)) is False

    def test_custom_80_20_is_nonconformant(self):
        assert assess_fee_split(ROUTE_CUSTOM, (80, 20)) is True

    def test_custom_unknown_split_is_unrated(self):
        assert assess_fee_split(ROUTE_CUSTOM, None) is None

    def test_indeterminate_route_is_unrated(self):
        assert assess_fee_split(None, None) is None


# ---------------------------------------------------------------------------
# Default resolver — official-core detection
# ---------------------------------------------------------------------------

class TestResolveDefault:
    def test_contract_is_official_core(self):
        r = SettlementRouteResolver(official_core=ACP_CORE)
        route, split = r.resolve(_contract(address=ACP_CORE))
        assert route == ROUTE_OFFICIAL_CORE
        assert split is None

    def test_address_match_is_case_insensitive(self):
        r = SettlementRouteResolver(official_core=ACP_CORE.lower())
        route, _ = r.resolve(_contract(address=ACP_CORE.upper()))
        assert route == ROUTE_OFFICIAL_CORE

    def test_routes_through_official_core_in_source(self):
        r = SettlementRouteResolver(official_core=ACP_CORE)
        src = f"contract Agent {{ address core = {ACP_CORE}; }}"
        route, _ = r.resolve(_contract(source=src))
        assert route == ROUTE_OFFICIAL_CORE

    def test_no_core_no_reader_is_indeterminate(self):
        r = SettlementRouteResolver(official_core=ACP_CORE)
        route, split = r.resolve(_contract())
        assert route is None
        assert split is None

    def test_custom_split_reader_returns_custom_route(self):
        r = SettlementRouteResolver(
            official_core=ACP_CORE,
            _split_reader=lambda cd: (80, 20),
        )
        route, split = r.resolve(_contract())
        assert route == ROUTE_CUSTOM
        assert split == (80, 20)

    def test_split_reader_returning_none_is_indeterminate(self):
        r = SettlementRouteResolver(
            official_core=ACP_CORE,
            _split_reader=lambda cd: None,
        )
        assert r.resolve(_contract()) == (None, None)

    def test_split_reader_raising_is_indeterminate(self):
        def boom(cd):
            raise RuntimeError("decode failed")
        r = SettlementRouteResolver(official_core=ACP_CORE, _split_reader=boom)
        assert r.resolve(_contract()) == (None, None)


# ---------------------------------------------------------------------------
# Required end-to-end cases (a) / (b) / (c)
# ---------------------------------------------------------------------------

class TestRequiredCases:
    def test_a_agent_via_official_core_not_flagged(self):
        r = SettlementRouteResolver(official_core=ACP_CORE)
        route, split = r.resolve(_contract(address=ACP_CORE))
        assert assess_fee_split(route, split) is False

    def test_b_forked_job_80_20_high_flag(self):
        r = SettlementRouteResolver(
            official_core=ACP_CORE,
            _split_reader=lambda cd: (80, 20),
        )
        route, split = r.resolve(_contract())
        assert assess_fee_split(route, split) is True

    def test_c_indeterminate_settlement_path_unrated(self):
        r = SettlementRouteResolver(official_core=ACP_CORE)
        route, split = r.resolve(_contract())
        assert assess_fee_split(route, split) is None
