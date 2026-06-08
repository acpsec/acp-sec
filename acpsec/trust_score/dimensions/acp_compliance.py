"""Dimension 5 — ACP v3 Compliance (weight 0.15).

Scored against the canonical ACP v3 job lifecycle (see acp_lifecycle.py):
open -> budget_set -> funded -> submitted -> completed, with rejected / expired
branches. CRITICAL checks guard escrow integrity: funds must only release to the
Provider on the completed path, and a Provider must not be able to self-settle
by skipping the Evaluator-gated submitted->completed transition.

fee_split_nonconformant is tri-state (bool | None): None when the settlement
path cannot be determined (Unrated). When the agent settles via the official ACP
Core, the 95/5 (no Evaluator) or 90/5/5 (with Evaluator) split is enforced by
the protocol and is conformant by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import DimScore, Finding
from ..weights import WEIGHTS

_DIM = "acp_compliance"


@dataclass
class ACPComplianceInput:
    escrow_drainable: bool = False
    can_self_settle: bool = False
    missing_lifecycle_phases: int = 0
    no_reject_refund_path: bool = False
    fee_split_nonconformant: bool | None = None
    no_expiry_timeout: bool = False
    settlement_not_atomic: bool = False
    nonconformant_job_struct: bool = False


def run(inp: ACPComplianceInput) -> DimScore:
    findings: list[Finding] = []
    unrated_checks: list[str] = []
    penalty = 0

    # CRITICAL
    if inp.escrow_drainable:
        findings.append(Finding(
            dim=_DIM, severity="CRITICAL",
            detail="escrow funds drainable outside the completed settlement path",
        ))

    if inp.can_self_settle:
        findings.append(Finding(
            dim=_DIM, severity="CRITICAL",
            detail="agent can self-settle, bypassing the Evaluator-gated submitted phase",
        ))

    # High — one finding per missing v3 lifecycle phase
    for i in range(inp.missing_lifecycle_phases):
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail=f"missing ACP v3 lifecycle phase ({i + 1} of {inp.missing_lifecycle_phases})",
        ))
        penalty += 15

    # High — no reject/refund path (escrow cannot return to Client)
    if inp.no_reject_refund_path:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="no reject path returning escrow to the Client on a rejected job",
        ))
        penalty += 20

    # High — fee split non-conformant (tri-state; None = Unrated)
    if inp.fee_split_nonconformant is None:
        unrated_checks.append("fee_split_nonconformant")
    elif inp.fee_split_nonconformant:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="settlement fee split is not the conformant 95/5 or 90/5/5",
        ))
        penalty += 20

    # Medium — no expiry / timeout
    if inp.no_expiry_timeout:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="no expiry / timeout to release escrow on a stalled job",
        ))
        penalty += 15

    # Medium — settlement atomicity
    if inp.settlement_not_atomic:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="settlement not atomic",
        ))
        penalty += 15

    # Medium — job struct / events
    if inp.nonconformant_job_struct:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="non-conformant job struct or missing events",
        ))
        penalty += 10

    return DimScore(
        name=_DIM,
        score=max(0.0, 100.0 - penalty),
        weight=WEIGHTS[_DIM],
        findings=findings,
        unrated_checks=unrated_checks,
    )
