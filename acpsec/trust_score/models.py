"""Trust Score data models."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, Field

_VALID_SEVERITIES = {"CRITICAL", "High", "Medium", "Low"}


class ScanMode(str, Enum):
    """How the scan is run, which governs reachability of private data.

    external:   public/on-chain data only (default). Private data points are
                left Unrated rather than penalized.
    self_audit: operator-run scan that may supply private data (Agent Card
                spend limits, off-chain config) to score otherwise-Unrated checks.
    """

    EXTERNAL = "external"
    SELF_AUDIT = "self_audit"


DEFAULT_SCAN_MODE = ScanMode.EXTERNAL


class Finding(BaseModel):
    dim: str
    severity: str
    detail: str

    model_config = {"frozen": True}

    def model_post_init(self, __context: Any) -> None:
        if self.severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {self.severity!r}"
            )


class DimScore(BaseModel):
    name: str
    score: Annotated[float, Field(ge=0.0, le=100.0)]
    weight: float
    rated: bool = True
    findings: list[Finding] = Field(default_factory=list)
    unrated_checks: list[str] = Field(default_factory=list)


class SubScore(BaseModel):
    """Per-dimension score plus the sub-checks that ended up Unrated."""

    score: int
    unrated_checks: list[str] = Field(default_factory=list)


class TrustScoreResult(BaseModel):
    agent: str
    erc8004_id: str
    score: int
    grade: str
    multiplier: float
    critical: bool
    subscores: dict[str, SubScore]
    top_findings: list[Finding] = Field(default_factory=list)
    scanned_at: str
    scanner_version: str
    rated: bool = True
