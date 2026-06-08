"""Dimension 1 — Contract Security (weight 0.25).

Scores an on-chain contract from 100 downward using static-analysis results.
CRITICAL conditions emit a Finding(severity="CRITICAL") but carry no dimension-
level score penalty — the engine's CRITICAL_CAP handles the composite consequence.
High/Medium conditions subtract explicit point penalties and floor at 0.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import DimScore, Finding
from ..weights import WEIGHTS

_DIM = "contract_security"


@dataclass
class ContractSecurityInput:
    source_verified: bool
    has_arbitrary_delegatecall: bool = False
    has_unbounded_mint: bool = False
    has_reentrancy: bool = False
    missing_access_control: bool = False
    upgradeable_proxy_eoa_admin: bool = False
    has_selfdestruct: bool = False
    uses_tx_origin_auth: bool = False
    unchecked_low_level_calls: bool = False
    floating_pragma: bool = False


def run(inp: ContractSecurityInput) -> DimScore:
    findings: list[Finding] = []
    penalty = 0

    # CRITICAL — no dimension penalty; engine applies CRITICAL_CAP at composite level
    if not inp.source_verified:
        findings.append(Finding(dim=_DIM, severity="CRITICAL", detail="source code unverified"))
    if inp.has_arbitrary_delegatecall:
        findings.append(Finding(dim=_DIM, severity="CRITICAL", detail="arbitrary external call / delegatecall to caller-supplied address"))
    if inp.has_unbounded_mint:
        findings.append(Finding(dim=_DIM, severity="CRITICAL", detail="unbounded or hidden mint authority"))

    # High
    if inp.has_reentrancy:
        findings.append(Finding(dim=_DIM, severity="High", detail="reentrancy: external call before state update, no nonReentrant guard"))
        penalty += 30
    if inp.missing_access_control:
        findings.append(Finding(dim=_DIM, severity="High", detail="missing access control on privileged function"))
        penalty += 25
    if inp.upgradeable_proxy_eoa_admin:
        findings.append(Finding(dim=_DIM, severity="High", detail="upgradeable proxy with single EOA admin"))
        penalty += 20

    # Medium
    if inp.has_selfdestruct:
        findings.append(Finding(dim=_DIM, severity="Medium", detail="selfdestruct present"))
        penalty += 15
    if inp.uses_tx_origin_auth:
        findings.append(Finding(dim=_DIM, severity="Medium", detail="tx.origin used for authentication"))
        penalty += 15
    if inp.unchecked_low_level_calls:
        findings.append(Finding(dim=_DIM, severity="Medium", detail="unchecked low-level call return value"))
        penalty += 10
    if inp.floating_pragma:
        findings.append(Finding(dim=_DIM, severity="Medium", detail="floating or pre-0.8 pragma without SafeMath"))
        penalty += 10

    return DimScore(
        name=_DIM,
        score=max(0.0, 100.0 - penalty),
        weight=WEIGHTS[_DIM],
        findings=findings,
    )
