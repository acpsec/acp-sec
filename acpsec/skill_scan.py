"""Scoring, verdict, and orchestration for scan-skill (Phases 5–6).

Findings from the three layers (manifest / instruction / code) are mapped to a
verdict and a numeric score.  Both are *fully derivable* from the listed
findings — no fabricated or padded numbers.

Thresholds live here as config constants, not scattered magic numbers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .checks.skill_code import scan_code
from .config_loader import load_skill_manifest
from .injection.skill_patterns import scan_instructions
from .models import CheckResult, Severity, SkillScanResult
from .skill_manifest import scan_manifest

VERDICT_PASS = "PASS"
VERDICT_WARN = "WARN"
VERDICT_FAIL = "FAIL"

# Exit codes documented on the CLI: 0 PASS, 1 WARN, 2 FAIL.
EXIT_CODES = {VERDICT_PASS: 0, VERDICT_WARN: 1, VERDICT_FAIL: 2}

SKILL_MAX_SCORE = 100.0

# Per-finding deductions from the 100-pt starting score.  Verdict is derived
# from severities independently (below), so these only shape the numeric score.
SEVERITY_DEDUCTIONS: dict[Severity, float] = {
    Severity.CRITICAL: 50.0,
    Severity.HIGH: 30.0,
    Severity.MEDIUM: 12.0,
    Severity.LOW: 4.0,
    Severity.INFO: 0.0,
}

_FAIL_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}
_WARN_SEVERITIES = {Severity.MEDIUM}


def derive_verdict(findings: list[CheckResult]) -> str:
    """PASS (nothing ≥ MEDIUM) / WARN (mediums only) / FAIL (any high/critical)."""
    severities = {f.severity for f in findings}
    if severities & _FAIL_SEVERITIES:
        return VERDICT_FAIL
    if severities & _WARN_SEVERITIES:
        return VERDICT_WARN
    return VERDICT_PASS


def derive_score(findings: list[CheckResult]) -> float:
    """Start at SKILL_MAX_SCORE and deduct per finding; never below zero."""
    deduction = sum(SEVERITY_DEDUCTIONS[f.severity] for f in findings)
    return max(0.0, SKILL_MAX_SCORE - deduction)


def scan_skill(path: str | Path) -> SkillScanResult:
    """Statically scan a skill folder and return a :class:`SkillScanResult`.

    Never executes any file found in the skill folder.
    """
    manifest = load_skill_manifest(path)

    findings: dict[str, list[CheckResult]] = {
        "manifest": scan_manifest(manifest),
        "instruction": scan_instructions(manifest),
        "code": scan_code(manifest),
    }
    flat = [f for layer in findings.values() for f in layer]

    return SkillScanResult(
        skill_name=manifest.name,
        skill_path=manifest.path,
        timestamp=datetime.now(timezone.utc).isoformat(),
        verdict=derive_verdict(flat),
        score=round(derive_score(flat), 2),
        max_score=SKILL_MAX_SCORE,
        findings=findings,
        metadata={"skill_md_path": manifest.skill_md_path},
    )
