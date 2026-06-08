"""Dimension 4 — HOOK Security (weight 0.15).

Framed around the ACP v3 beforeAction / afterAction hook model: a hook runs as
a callback before and after an agent action and must not be able to seize
control of escrowed funds, censor settlement, or be hijacked. The Uniswap v4
hook checks (reentrancy, dynamic fee, over-scoped permissions) carry over since
ACP hooks share the same callback-and-pool threat surface.

hook_diverts_escrow is the CRITICAL check (tri-state): True only when a hook
callback can divert escrow / principal funds; None when reachability cannot be
determined statically (Unrated); False when ruled out.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import DimScore, Finding
from ..weights import WEIGHTS

_DIM = "hook_security"


@dataclass
class HookSecurityInput:
    unauthorized_caller: bool = False
    permissions_over_scoped: bool = False
    hook_reentrancy: bool = False
    can_block_settlement: bool = False
    dynamic_fee_manipulation: bool = False
    hook_upgradeable_by_eoa: bool = False
    # Tri-state (bool | None): None = Unrated (reachability undetermined).
    hook_diverts_escrow: bool | None = None


def run(inp: HookSecurityInput) -> DimScore:
    findings: list[Finding] = []
    unrated_checks: list[str] = []
    penalty = 0

    # CRITICAL — hook can divert escrow / principal during a callback (tri-state)
    if inp.hook_diverts_escrow is None:
        unrated_checks.append("hook_diverts_escrow")
    elif inp.hook_diverts_escrow:
        findings.append(Finding(
            dim=_DIM, severity="CRITICAL",
            detail="hook can divert escrow / principal funds during a "
                   "beforeAction/afterAction callback",
        ))

    # CRITICAL
    if inp.unauthorized_caller:
        findings.append(Finding(
            dim=_DIM, severity="CRITICAL",
            detail="unauthorized caller can invoke beforeAction/afterAction callbacks",
        ))

    # High
    if inp.permissions_over_scoped:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="hook permissions over-scoped (callback can move funds)",
        ))
        penalty += 25

    if inp.hook_reentrancy:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="hook reentrancy during callback into pool/settlement",
        ))
        penalty += 20

    # Medium
    if inp.can_block_settlement:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="hook callback can block or censor settlement",
        ))
        penalty += 15

    if inp.dynamic_fee_manipulation:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="dynamic fee manipulation in hook callback",
        ))
        penalty += 15

    if inp.hook_upgradeable_by_eoa:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="hook upgradeable by EOA",
        ))
        penalty += 15

    return DimScore(
        name=_DIM,
        score=max(0.0, 100.0 - penalty),
        weight=WEIGHTS[_DIM],
        findings=findings,
        unrated_checks=unrated_checks,
    )
