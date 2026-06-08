"""ACP Compliance adapter (Dimension 5) — ABI analysis for ACP v3 conformance.

Maps a contract's ABI onto the canonical v3 lifecycle (see acp_lifecycle.py):
open -> budget_set -> funded -> submitted -> completed, with reject/expire
branches. The fee-split flag is NOT re-derived from the agent ABI — it is a
settlement-routing question delegated to SettlementRouteResolver (Guardrail A):
official ACP Core is conformant by construction; a custom fork is analysed;
an undeterminable path is Unrated.

Injectable `_rpc` signature: (method: str, params: list) -> Any.
Critical flags (escrow_drainable, can_self_settle) require deep semantic
analysis not reliably detectable from ABI alone → default False (conservative).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

from ..chains import DEFAULT_CHAIN_ID, reference_contracts
from ..dimensions.acp_compliance import ACPComplianceInput
from .basescan import ContractData
from .settlement_route import SettlementRouteResolver, assess_fee_split

DEFAULT_RPC_URL = "https://mainnet.base.org"

# ACP v3 lifecycle phase → keyword stems (lower-case substring checks)
_LIFECYCLE_PHASE_KEYWORDS = {
    "open":       ("open", "creat"),
    "budget_set": ("budget",),
    "funded":     ("fund",),
    "submitted":  ("submit",),
    "completed":  ("complet",),
}

# Reject branch — escrow returns to Client on a rejected job
_REJECT_KEYWORDS = ("reject", "refund", "cancel")

# Expiry / permissionless timeout
_EXPIRY_KEYWORDS = ("expire", "expiry", "timeout", "deadline")

# Settlement keywords (triggers atomicity check)
_SETTLE_KEYWORDS = ("settle", "complete", "finalize")

# Atomic keyword — if present alongside a settle keyword, settlement IS atomic
_ATOMIC_KEYWORD = "atomic"

# ACP job interface keywords
_JOB_KEYWORDS = ("job",)


def analyze_abi(abi: list[dict]) -> dict:
    """Pure ABI analysis — returns a flag dict, no network calls.

    Keys returned:
        missing_lifecycle_phases: int  (0-5)
        no_reject_refund_path: bool
        no_expiry_timeout: bool
        settlement_not_atomic: bool
        nonconformant_job_struct: bool
    """
    names_lower = [
        e.get("name", "").lower()
        for e in abi
        if e.get("type") in ("function", "event")
    ]

    found_phases = sum(
        1
        for keywords in _LIFECYCLE_PHASE_KEYWORDS.values()
        if any(kw in name for name in names_lower for kw in keywords)
    )
    missing_lifecycle_phases = len(_LIFECYCLE_PHASE_KEYWORDS) - found_phases

    no_reject_refund_path = not any(
        kw in name for name in names_lower for kw in _REJECT_KEYWORDS
    )

    no_expiry_timeout = not any(
        kw in name for name in names_lower for kw in _EXPIRY_KEYWORDS
    )

    has_settle_fn = any(
        kw in name for name in names_lower for kw in _SETTLE_KEYWORDS
    )
    has_atomic = any(_ATOMIC_KEYWORD in name for name in names_lower)
    settlement_not_atomic = has_settle_fn and not has_atomic

    nonconformant_job_struct = not any(
        kw in name for name in names_lower for kw in _JOB_KEYWORDS
    )

    return {
        "missing_lifecycle_phases": missing_lifecycle_phases,
        "no_reject_refund_path": no_reject_refund_path,
        "no_expiry_timeout": no_expiry_timeout,
        "settlement_not_atomic": settlement_not_atomic,
        "nonconformant_job_struct": nonconformant_job_struct,
    }


def _default_rpc(rpc_url: str) -> Callable[[str, list], Any]:
    def call(method: str, params: list) -> Any:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            rpc_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            payload = json.loads(resp.read().decode())
        if "error" in payload:
            raise RuntimeError(f"rpc error: {payload['error']}")
        return payload.get("result")
    return call


class ACPComplianceAdapter:
    """Fetches ACP v3 compliance signals for a contract.

    Args:
        rpc_url: JSON-RPC endpoint (used only when _rpc is not provided).
        chain: chain id / name resolving the official ACP Core reference.
        _rpc: injectable ``(method, params) -> Any`` for testing.
        _settlement_resolver: injectable SettlementRouteResolver for testing.
    """

    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        chain: int | str = DEFAULT_CHAIN_ID,
        _rpc: Callable[[str, list], Any] | None = None,
        _settlement_resolver: SettlementRouteResolver | None = None,
    ) -> None:
        self._rpc = _rpc or _default_rpc(rpc_url)
        if _settlement_resolver is not None:
            self._settlement_resolver = _settlement_resolver
        else:
            refs = reference_contracts(chain)
            self._settlement_resolver = SettlementRouteResolver(
                official_core=refs.acp_core
            )

    def fetch(self, contract_data: ContractData) -> ACPComplianceInput:
        """Return an ACPComplianceInput populated from ABI + settlement route.

        Critical flags (escrow_drainable, can_self_settle) are always False
        because reliable detection requires semantic / symbolic analysis
        beyond what ABI inspection can provide. The fee-split flag is tri-state
        and resolved by the settlement route (None = Unrated).
        """
        flags = analyze_abi(contract_data.abi)
        route, split = self._settlement_resolver.resolve(contract_data)
        return ACPComplianceInput(
            escrow_drainable=False,         # conservative — requires semantic analysis
            can_self_settle=False,          # conservative — requires semantic analysis
            missing_lifecycle_phases=flags["missing_lifecycle_phases"],
            no_reject_refund_path=flags["no_reject_refund_path"],
            fee_split_nonconformant=assess_fee_split(route, split),
            no_expiry_timeout=flags["no_expiry_timeout"],
            settlement_not_atomic=flags["settlement_not_atomic"],
            nonconformant_job_struct=flags["nonconformant_job_struct"],
        )
