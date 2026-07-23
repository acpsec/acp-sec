"""Scoring + verdict tests for scan-skill (Phase 5)."""

from __future__ import annotations

from acpsec.models import CheckResult, CheckStatus, Severity
from acpsec.skill_scan import (
    SEVERITY_DEDUCTIONS,
    SKILL_MAX_SCORE,
    VERDICT_FAIL,
    VERDICT_PASS,
    VERDICT_WARN,
    derive_score,
    derive_verdict,
)


def _finding(severity: Severity) -> CheckResult:
    return CheckResult(
        check_id="SKILL-TEST",
        name="synthetic",
        dimension="code",
        status=CheckStatus.FAIL,
        score=0.0,
        max_score=0.0,
        severity=severity,
        evidence=["SKILL.md:1: synthetic"],
    )


def test_no_findings_is_pass_and_full_score():
    assert derive_verdict([]) == VERDICT_PASS
    assert derive_score([]) == SKILL_MAX_SCORE


def test_low_and_info_only_is_pass():
    findings = [_finding(Severity.LOW), _finding(Severity.INFO)]
    assert derive_verdict(findings) == VERDICT_PASS


def test_medium_only_is_warn():
    assert derive_verdict([_finding(Severity.MEDIUM)]) == VERDICT_WARN


def test_any_high_is_fail():
    assert derive_verdict([_finding(Severity.MEDIUM), _finding(Severity.HIGH)]) == VERDICT_FAIL


def test_any_critical_is_fail():
    assert derive_verdict([_finding(Severity.CRITICAL)]) == VERDICT_FAIL


def test_score_is_fully_derivable_from_findings():
    findings = [_finding(Severity.HIGH), _finding(Severity.MEDIUM)]
    expected = SKILL_MAX_SCORE - SEVERITY_DEDUCTIONS[Severity.HIGH] - SEVERITY_DEDUCTIONS[Severity.MEDIUM]
    assert derive_score(findings) == max(0.0, expected)


def test_score_never_negative():
    findings = [_finding(Severity.CRITICAL)] * 10
    assert derive_score(findings) == 0.0
