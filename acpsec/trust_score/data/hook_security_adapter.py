"""Hook Security adapter (Dimension 4) — Slither findings + on-chain owner check.

Combines static analysis from Slither with an RPC owner check to populate
HookSecurityInput for UniV4-style hooks or any callback-based contract.

Injectable callables:
- `_rpc(method, params) -> Any`          — JSON-RPC
- `_slither_run(target) -> list[SlitherFinding]` — Slither findings

When Slither is not available (SlitherNotAvailable), the adapter gracefully
falls back to RPC-derived signals only.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

from ..dimensions.hook_security import HookSecurityInput

DEFAULT_RPC_URL = "https://mainnet.base.org"

# owner() — keccak256("owner()")[0:4]
_OWNER_SELECTOR = "0x8da5cb5b"

# Slither check → HookSecurityInput field(s) to set True
_SLITHER_MAP: dict[str, dict[str, bool]] = {
    "access-control":          {"unauthorized_caller": True},
    "unprotected-upgrade":     {"unauthorized_caller": True, "hook_upgradeable_by_eoa": True},
    "reentrancy-eth":          {"hook_reentrancy": True},
    "reentrancy-no-eth":       {"hook_reentrancy": True},
    "controlled-delegatecall": {"permissions_over_scoped": True, "can_block_settlement": True},
    "arbitrary-send-eth":      {"dynamic_fee_manipulation": True, "permissions_over_scoped": True},
}

# --- Escrow-diversion corroboration (CRITICAL gate) -------------------------
# A single raw Slither signal must NOT trip the CRITICAL hook_diverts_escrow
# flag: CRITICAL_CAP locks the whole composite to F, so false positives are
# very costly. We require corroboration that the dangerous primitive is both
# reachable from a hook callback AND on a fund-moving path. Bias: under-flag
# CRITICAL rather than risk a false F.

_DANGEROUS_PRIMITIVES = {"arbitrary-send-eth", "controlled-delegatecall"}

# Hook callback function names (ACP v3 + Uniswap v4).
_CALLBACK_KEYWORDS = (
    "beforeaction", "afteraction",
    "beforeswap", "afterswap",
    "beforeaddliquidity", "afteraddliquidity",
    "beforeremoveliquidity", "afterremoveliquidity",
    "callback",
)

# Fund-moving / escrow / principal primitives.
_FUND_MOVE_KEYWORDS = (
    "transfer", "call{value", "call.value", ".value(",
    "safetransfer", "escrow", "principal", "withdraw", "balance",
)

# Signals that a controlled-delegatecall is to a known/immutable library
# (benign over-scoping rather than an exploitable diversion).
_BENIGN_LIBRARY_KEYWORDS = ("library", "immutable", "constant")


def _classify_diversion(finding) -> str:
    """Classify one dangerous finding as 'divert' / 'benign' / 'indeterminate'."""
    desc = (finding.description or "").lower()
    if finding.check == "controlled-delegatecall" and any(
        kw in desc for kw in _BENIGN_LIBRARY_KEYWORDS
    ):
        return "benign"
    in_callback = any(kw in desc for kw in _CALLBACK_KEYWORDS)
    moves_funds = any(kw in desc for kw in _FUND_MOVE_KEYWORDS)
    if in_callback and moves_funds:
        return "divert"
    return "indeterminate"


def assess_escrow_diversion(findings: list) -> bool | None:
    """Tri-state CRITICAL assessment from a completed Slither run.

    True  — a dangerous primitive is corroborated as a callback fund-diversion
    False — no diversion primitive, or all are clearly benign (downgraded to
            the over-scoped High penalty via _SLITHER_MAP)
    None  — Unrated: a dangerous primitive exists but reachability/intent
            cannot be determined statically
    """
    dangerous = [f for f in findings if f.check in _DANGEROUS_PRIMITIVES]
    if not dangerous:
        return False
    saw_indeterminate = False
    for f in dangerous:
        verdict = _classify_diversion(f)
        if verdict == "divert":
            return True
        if verdict == "indeterminate":
            saw_indeterminate = True
    return None if saw_indeterminate else False


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


def _default_slither_run() -> Callable[[str], list]:
    from .slither_runner import SlitherRunner
    runner = SlitherRunner()
    return lambda target: runner.run(target)


class HookSecurityAdapter:
    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        _rpc: Callable[[str, list], Any] | None = None,
        _slither_run: Callable[[str], list] | None = None,
    ) -> None:
        self._rpc = _rpc or _default_rpc(rpc_url)
        self._slither_run = _slither_run or _default_slither_run()

    def fetch(self, address: str) -> HookSecurityInput:
        from .slither_runner import SlitherNotAvailable

        owner_is_eoa = self._owner_is_eoa(address)

        flags: dict[str, bool] = {
            "unauthorized_caller": False,
            "permissions_over_scoped": False,
            "hook_reentrancy": False,
            "can_block_settlement": False,
            "dynamic_fee_manipulation": False,
            "hook_upgradeable_by_eoa": owner_is_eoa,
        }

        # hook_diverts_escrow stays Unrated (None) unless a completed Slither
        # run lets us corroborate or rule out a callback fund-diversion path.
        diverts_escrow: bool | None = None
        try:
            findings = self._slither_run(address)
            for finding in findings:
                for key, val in _SLITHER_MAP.get(finding.check, {}).items():
                    if val:
                        flags[key] = True
            diverts_escrow = assess_escrow_diversion(findings)
        except SlitherNotAvailable:
            pass

        return HookSecurityInput(hook_diverts_escrow=diverts_escrow, **flags)

    def _owner_is_eoa(self, address: str) -> bool:
        """Return True if the contract owner is an EOA (no deployed code)."""
        try:
            raw = self._rpc("eth_call", [{"to": address, "data": _OWNER_SELECTOR}, "latest"])
            if not raw or raw == "0x":
                return False
            owner_addr = "0x" + raw[-40:]
            if int(owner_addr, 16) == 0:
                return False
            code = self._rpc("eth_getCode", [owner_addr, "latest"])
            return not bool(code and code != "0x")
        except Exception:
            return False
