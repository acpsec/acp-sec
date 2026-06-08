"""Trust Score composite scoring engine."""

from __future__ import annotations

from datetime import datetime, timezone

from .models import DimScore, Finding, SubScore, TrustScoreResult
from .weights import CRITICAL_CAP, GRADE_BANDS, UNRATED_MULTIPLIER

_SEVERITY_ORDER = {"CRITICAL": 0, "High": 1, "Medium": 2, "Low": 3}

SCANNER_VERSION = "acpsec-v0.5.0"


class TrustScoreEngine:
    def composite(self, dim_scores: list[DimScore]) -> int:
        raw = sum(d.score * d.weight for d in dim_scores if d.rated)
        return int(round(raw))

    def has_critical(self, dim_scores: list[DimScore]) -> bool:
        return any(
            f.severity == "CRITICAL"
            for d in dim_scores
            for f in d.findings
        )

    def is_unrated(self, dim_scores: list[DimScore]) -> bool:
        return any(not d.rated for d in dim_scores)

    def grade_and_multiplier(self, score: int) -> tuple[str, float]:
        for min_score, grade, multiplier in GRADE_BANDS:
            if score >= min_score:
                return grade, multiplier
        return "F", 0.10

    def assess(
        self,
        agent: str,
        dim_scores: list[DimScore],
        erc8004_id: str = "",
        scanner_version: str = SCANNER_VERSION,
        scanned_at: str | None = None,
    ) -> TrustScoreResult:
        critical = self.has_critical(dim_scores)
        unrated = self.is_unrated(dim_scores)

        score = CRITICAL_CAP if critical else self.composite(dim_scores)

        if unrated:
            grade, multiplier = self.grade_and_multiplier(score)
            multiplier = UNRATED_MULTIPLIER
        else:
            grade, multiplier = self.grade_and_multiplier(score)

        subscores = {
            d.name: SubScore(score=int(d.score), unrated_checks=list(d.unrated_checks))
            for d in dim_scores
        }

        all_findings: list[Finding] = [f for d in dim_scores for f in d.findings]
        all_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

        return TrustScoreResult(
            agent=agent,
            erc8004_id=erc8004_id,
            score=score,
            grade=grade,
            multiplier=multiplier,
            critical=critical,
            subscores=subscores,
            top_findings=all_findings,
            scanned_at=scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            scanner_version=scanner_version,
            rated=not unrated,
        )
