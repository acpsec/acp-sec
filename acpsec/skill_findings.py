"""Shared helper for building scan-skill findings as CheckResult primitives.

A *finding* is a problem the scanner surfaced — it reuses the leaf
:class:`CheckResult` model.  ``score``/``max_score`` are 0 because findings are
not a scored budget (skill scoring is deduction-based; see ``skill_scan``).
Status is derived from severity so the reporter can colour findings without a
separate field.
"""

from __future__ import annotations

from .models import CheckResult, CheckStatus, Severity

_FAIL_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}


def make_finding(
    check_id: str,
    name: str,
    layer: str,
    severity: Severity,
    file: str,
    line: int,
    excerpt: str,
    recommendation: str | None = None,
) -> CheckResult:
    """Build a finding CheckResult carrying ``file:line`` evidence."""
    status = CheckStatus.FAIL if severity in _FAIL_SEVERITIES else CheckStatus.WARN
    loc = f"{file}:{line}"
    excerpt = (excerpt or "").strip()
    evidence = f"{loc}: {excerpt}" if excerpt else loc
    return CheckResult(
        check_id=check_id,
        name=name,
        dimension=layer,
        status=status,
        score=0.0,
        max_score=0.0,
        severity=severity,
        evidence=[evidence],
        recommendations=[recommendation] if recommendation else [],
        details={"file": file, "line": line, "excerpt": excerpt, "layer": layer},
    )
