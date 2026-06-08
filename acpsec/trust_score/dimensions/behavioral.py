"""Dimension 6 — Behavioral & Wash-Resistance (weight 0.10).

HHI penalty formula (when HHI > 0.5):
    penalty = min(25, round((HHI - 0.5) * 50))
    → 0 at HHI=0.5, 25 at HHI=1.0 (linear scale)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import DimScore, Finding
from ..weights import WEIGHTS

_DIM = "behavioral"


def compute_hhi(counterparty_jobs: list[int]) -> float:
    """Herfindahl-Hirschman Index over per-counterparty job counts.

    Returns 0.0 when the list is empty or all counts are zero.
    """
    total = sum(counterparty_jobs)
    if total == 0:
        return 0.0
    return sum((n / total) ** 2 for n in counterparty_jobs)


@dataclass
class BehavioralInput:
    fund_loss_incident: bool = False
    dispute_rate: float = 0.0
    failed_delivery_rate: float = 0.0
    counterparty_jobs: list[int] = field(default_factory=list)
    volume_spike: bool = False


def run(inp: BehavioralInput) -> DimScore:
    findings: list[Finding] = []
    penalty = 0

    # High — historical fund-loss / exploit
    if inp.fund_loss_incident:
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail="historical fund-loss or exploit incident recorded",
        ))
        penalty += 40

    # High — dispute rate: min(40, rate * 200)
    if inp.dispute_rate > 0:
        dispute_penalty = min(40, inp.dispute_rate * 200)
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail=f"elevated dispute rate ({inp.dispute_rate:.1%})",
        ))
        penalty += dispute_penalty

    # High — failed-delivery rate: min(30, rate * 150)
    if inp.failed_delivery_rate > 0:
        delivery_penalty = min(30, inp.failed_delivery_rate * 150)
        findings.append(Finding(
            dim=_DIM, severity="High",
            detail=f"elevated failed-delivery rate ({inp.failed_delivery_rate:.1%})",
        ))
        penalty += delivery_penalty

    # Medium — HHI counterparty diversity
    hhi = compute_hhi(inp.counterparty_jobs)
    if hhi > 0.5:
        hhi_penalty = min(25, round((hhi - 0.5) * 50))
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail=f"low counterparty diversity (HHI={hhi:.2f} > 0.5)",
        ))
        penalty += hhi_penalty

    # Medium — volume spike
    if inp.volume_spike:
        findings.append(Finding(
            dim=_DIM, severity="Medium",
            detail="volume spike from few wallets detected",
        ))
        penalty += 15

    return DimScore(
        name=_DIM,
        score=max(0.0, 100.0 - penalty),
        weight=WEIGHTS[_DIM],
        findings=findings,
    )
