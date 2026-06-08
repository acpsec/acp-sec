"""Dimension 2 — Authority Scope & Key Management (weight 0.20).

Mitigations for withdrawal_gated_eoa:
  owner_multisig=True      → penalty reduced from -20 to -5
  owner_mpc_threshold=True → penalty reduced to 0 (no finding emitted)
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import DimScore, Finding
from ..weights import WEIGHTS

_DIM = "authority_scope"


@dataclass
class AuthorityScopeInput:
    can_move_arbitrary_funds: bool = False
    withdrawal_gated_eoa: bool = False
    owner_multisig: bool = False
    owner_mpc_threshold: bool = False
    no_spending_budget: bool = False
    infinite_token_approvals: bool = False
    no_timelock: bool = False
    no_emergency_stop: bool = False
    no_key_rotation: bool = False
    # Tri-state (bool | None): None = Unrated (data not reachable), zero penalty.
    signer_unrestricted: bool | None = None
    agent_card_no_spend_limit: bool | None = None


def run(inp: AuthorityScopeInput) -> DimScore:
    findings: list[Finding] = []
    unrated_checks: list[str] = []
    penalty = 0

    # CRITICAL
    if inp.can_move_arbitrary_funds:
        findings.append(Finding(
            dim=_DIM, severity="CRITICAL",
            detail="agent can move arbitrary user funds without per-tx consent",
        ))

    # High — withdrawal gated by EOA, with mitigations
    if inp.withdrawal_gated_eoa:
        if inp.owner_mpc_threshold:
            pass  # fully mitigated — no penalty, no finding
        elif inp.owner_multisig:
            findings.append(Finding(
                dim=_DIM, severity="High",
                detail="withdrawal gated by multisig owner (partially mitigated from EOA)",
            ))
            penalty += 5
        else:
            findings.append(Finding(
                dim=_DIM, severity="High",
                detail="withdrawal gated by single EOA owner",
            ))
            penalty += 20

    # High — signer key in Unrestricted mode (tri-state; None = Unrated)
    if inp.signer_unrestricted is None:
        unrated_checks.append("signer_unrestricted")
    elif inp.signer_unrestricted:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="signer key operates in Unrestricted mode (no on-chain scope to ACP)",
        ))
        penalty += 25

    # Medium — Agent Card declares no spend limit (tri-state; None = Unrated)
    if inp.agent_card_no_spend_limit is None:
        unrated_checks.append("agent_card_no_spend_limit")
    elif inp.agent_card_no_spend_limit:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="Agent Card declares no per-transaction or per-period spend limit",
        ))
        penalty += 15

    # High — no spending budget
    if inp.no_spending_budget:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="no on-chain spending budget or per-period cap",
        ))
        penalty += 25

    # Medium
    if inp.infinite_token_approvals:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="infinite token approvals requested",
        ))
        penalty += 15

    if inp.no_timelock:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="no timelock on privileged operations",
        ))
        penalty += 10

    if inp.no_emergency_stop:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="no pause / emergency-stop mechanism",
        ))
        penalty += 10

    # Low
    if inp.no_key_rotation:
        findings.append(Finding(
            dim=_DIM, severity="Low",
            detail="no key rotation path documented",
        ))
        penalty += 5

    return DimScore(
        name=_DIM,
        score=max(0.0, 100.0 - penalty),
        weight=WEIGHTS[_DIM],
        findings=findings,
        unrated_checks=unrated_checks,
    )
