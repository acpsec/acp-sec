"""Dimension 3 — Identity & Attribution (weight 0.15)."""

from __future__ import annotations

from dataclasses import dataclass

from ..models import DimScore, Finding
from ..weights import WEIGHTS

_DIM = "identity"


@dataclass
class IdentityInput:
    owner_mismatch: bool = False
    no_erc8004: bool = False
    handle_unverified: bool = False
    endpoint_tls_mismatch: bool = False
    reputation_registry_inconsistent: bool = False
    sybil_signals: bool = False


def run(inp: IdentityInput) -> DimScore:
    findings: list[Finding] = []
    penalty = 0

    # CRITICAL
    if inp.owner_mismatch:
        findings.append(Finding(
            dim=_DIM, severity="CRITICAL",
            detail="agent card owner mismatch vs on-chain identity",
        ))

    # High
    if inp.no_erc8004:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="no ERC-8004 identity registered",
        ))
        penalty += 30

    if inp.handle_unverified:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="claimed handle unverified",
        ))
        penalty += 20

    # Medium
    if inp.endpoint_tls_mismatch:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="endpoint TLS mismatch",
        ))
        penalty += 10

    if inp.reputation_registry_inconsistent:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="reputation registry inconsistent",
        ))
        penalty += 10

    if inp.sybil_signals:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="Sybil signals detected (fresh wallet)",
        ))
        penalty += 10

    return DimScore(
        name=_DIM,
        score=max(0.0, 100.0 - penalty),
        weight=WEIGHTS[_DIM],
        findings=findings,
    )
