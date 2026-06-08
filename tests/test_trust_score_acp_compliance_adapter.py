"""Tests for acpsec/trust_score/data/acp_compliance_adapter.py — ACP v3 (TDD).

ABI analysis maps to the canonical v3 lifecycle (open, budget_set, funded,
submitted, completed) and the reject/expire branches. The fee-split flag is NOT
re-derived from the agent ABI: it is resolved by the settlement route (official
ACP Core -> conformant by construction; custom fork -> analysed; otherwise
Unrated). See data/settlement_route.py (Guardrail A).
"""

from acpsec.trust_score.data.acp_compliance_adapter import (
    ACPComplianceAdapter,
    analyze_abi,
)
from acpsec.trust_score.data.basescan import ContractData
from acpsec.trust_score.data.settlement_route import SettlementRouteResolver
from acpsec.trust_score.dimensions.acp_compliance import ACPComplianceInput

ACP_CORE = "0x238E541BfefD82238730D00a2208E5497F1832E0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _abi(*fn_names: str) -> list[dict]:
    return [{"type": "function", "name": n, "inputs": [], "outputs": []} for n in fn_names]


def _abi_event(*event_names: str) -> list[dict]:
    return [{"type": "event", "name": n, "inputs": []} for n in event_names]


def _contract(abi: list | None = None, address: str = "0xABCD") -> ContractData:
    return ContractData(
        address=address,
        source_verified=True,
        contract_name="TestEscrow",
        abi=abi or [],
        source_code="pragma solidity ^0.8.0;",
        compiler_version="v0.8.20",
    )


def _adapter(**kwargs):
    def _noop_rpc(method: str, params: list):
        return "0x"
    return ACPComplianceAdapter(_rpc=_noop_rpc, **kwargs)


# ---------------------------------------------------------------------------
# fetch() return type
# ---------------------------------------------------------------------------

class TestFetchReturnType:
    def test_returns_acp_compliance_input(self):
        assert isinstance(_adapter().fetch(_contract()), ACPComplianceInput)


# ---------------------------------------------------------------------------
# missing_lifecycle_phases — v3 chain (open, budget_set, funded, submitted, completed)
# ---------------------------------------------------------------------------

class TestLifecyclePhases:
    def test_empty_abi_all_five_phases_missing(self):
        assert _adapter().fetch(_contract([])).missing_lifecycle_phases == 5

    def test_abi_with_open_function_four_phases_missing(self):
        assert _adapter().fetch(_contract(_abi("openJob"))).missing_lifecycle_phases == 4

    def test_abi_with_all_five_v3_phases_zero_missing(self):
        abi = _abi("openJob", "setBudget", "fundJob", "submitJob", "completeJob")
        assert _adapter().fetch(_contract(abi)).missing_lifecycle_phases == 0

    def test_events_with_v3_phase_keywords_count(self):
        events = _abi_event(
            "JobOpened", "BudgetSet", "JobFunded", "JobSubmitted", "JobCompleted"
        )
        assert _adapter().fetch(_contract(events)).missing_lifecycle_phases == 0

    def test_partial_lifecycle_phases(self):
        # funded + submitted present → 3 missing (open, budget_set, completed)
        abi = _abi("fundJob", "submitJob")
        assert _adapter().fetch(_contract(abi)).missing_lifecycle_phases == 3


# ---------------------------------------------------------------------------
# no_reject_refund_path — reject branch returns escrow to Client
# ---------------------------------------------------------------------------

class TestRejectRefundPath:
    def test_reject_fn_clears_flag(self):
        assert _adapter().fetch(_contract(_abi("rejectJob"))).no_reject_refund_path is False

    def test_refund_fn_clears_flag(self):
        assert _adapter().fetch(_contract(_abi("refundClient"))).no_reject_refund_path is False

    def test_cancel_fn_clears_flag(self):
        assert _adapter().fetch(_contract(_abi("cancelJob"))).no_reject_refund_path is False

    def test_no_reject_path_true(self):
        assert _adapter().fetch(_contract(_abi("deposit", "withdraw"))).no_reject_refund_path is True

    def test_empty_abi_no_reject_path_true(self):
        assert _adapter().fetch(_contract([])).no_reject_refund_path is True


# ---------------------------------------------------------------------------
# no_expiry_timeout — permissionless timeout releases escrow
# ---------------------------------------------------------------------------

class TestExpiryTimeout:
    def test_expire_fn_clears_flag(self):
        assert _adapter().fetch(_contract(_abi("expireJob"))).no_expiry_timeout is False

    def test_timeout_fn_clears_flag(self):
        assert _adapter().fetch(_contract(_abi("claimTimeout"))).no_expiry_timeout is False

    def test_deadline_fn_clears_flag(self):
        assert _adapter().fetch(_contract(_abi("jobDeadline"))).no_expiry_timeout is False

    def test_no_expiry_true(self):
        assert _adapter().fetch(_contract(_abi("deposit"))).no_expiry_timeout is True

    def test_empty_abi_no_expiry_true(self):
        assert _adapter().fetch(_contract([])).no_expiry_timeout is True


# ---------------------------------------------------------------------------
# settlement_not_atomic
# ---------------------------------------------------------------------------

class TestSettlementAtomicity:
    def test_settle_without_atomic_true(self):
        assert _adapter().fetch(_contract(_abi("settle"))).settlement_not_atomic is True

    def test_complete_without_atomic_true(self):
        assert _adapter().fetch(_contract(_abi("complete"))).settlement_not_atomic is True

    def test_atomic_settle_false(self):
        assert _adapter().fetch(_contract(_abi("atomicSettle"))).settlement_not_atomic is False

    def test_no_settle_function_false(self):
        assert _adapter().fetch(_contract(_abi("deposit"))).settlement_not_atomic is False

    def test_empty_abi_false(self):
        assert _adapter().fetch(_contract([])).settlement_not_atomic is False


# ---------------------------------------------------------------------------
# nonconformant_job_struct
# ---------------------------------------------------------------------------

class TestJobStruct:
    def test_create_job_fn_false(self):
        assert _adapter().fetch(_contract(_abi("createJob"))).nonconformant_job_struct is False

    def test_job_event_false(self):
        assert _adapter().fetch(_contract(_abi_event("JobCreated"))).nonconformant_job_struct is False

    def test_no_job_true(self):
        assert _adapter().fetch(_contract(_abi("deposit", "settle"))).nonconformant_job_struct is True

    def test_empty_abi_true(self):
        assert _adapter().fetch(_contract([])).nonconformant_job_struct is True


# ---------------------------------------------------------------------------
# Conservative CRITICAL flags
# ---------------------------------------------------------------------------

class TestConservativeCriticals:
    def test_escrow_drainable_always_false(self):
        assert _adapter().fetch(_contract(_abi("drainEscrow"))).escrow_drainable is False

    def test_can_self_settle_always_false(self):
        assert _adapter().fetch(_contract(_abi("selfSettle"))).can_self_settle is False


# ---------------------------------------------------------------------------
# fee_split_nonconformant — resolved by settlement route (Guardrail A)
# ---------------------------------------------------------------------------

class TestFeeSplitRouting:
    def test_official_core_address_not_flagged(self):
        # (a) agent settles via the official ACP Core → conformant by construction
        result = _adapter(chain=8453).fetch(_contract(address=ACP_CORE))
        assert result.fee_split_nonconformant is False

    def test_forked_80_20_split_flagged(self):
        # (b) forked Job contract with an 80/20 split → non-conformant
        resolver = SettlementRouteResolver(
            official_core=ACP_CORE,
            _split_reader=lambda cd: (80, 20),
        )
        result = _adapter(_settlement_resolver=resolver).fetch(_contract())
        assert result.fee_split_nonconformant is True

    def test_indeterminate_route_is_unrated(self):
        # (c) custom contract, settlement path undeterminable → Unrated (None)
        result = _adapter(chain=8453).fetch(_contract())
        assert result.fee_split_nonconformant is None


# ---------------------------------------------------------------------------
# Pure analyze_abi()
# ---------------------------------------------------------------------------

class TestAnalyzeAbi:
    def test_returns_dict(self):
        assert isinstance(analyze_abi([]), dict)

    def test_empty_abi_defaults(self):
        flags = analyze_abi([])
        assert flags["missing_lifecycle_phases"] == 5
        assert flags["no_reject_refund_path"] is True
        assert flags["no_expiry_timeout"] is True
        assert flags["settlement_not_atomic"] is False
        assert flags["nonconformant_job_struct"] is True

    def test_full_v3_lifecycle(self):
        abi = _abi("openJob", "setBudget", "fundJob", "submitJob", "completeJob")
        assert analyze_abi(abi)["missing_lifecycle_phases"] == 0

    def test_reject_clears_flag(self):
        assert analyze_abi(_abi("rejectJob"))["no_reject_refund_path"] is False

    def test_expire_clears_flag(self):
        assert analyze_abi(_abi("expireJob"))["no_expiry_timeout"] is False

    def test_analyze_abi_has_no_fee_split_key(self):
        # fee split is a routing question, not an ABI keyword match
        assert "fee_split_nonconformant" not in analyze_abi([])
