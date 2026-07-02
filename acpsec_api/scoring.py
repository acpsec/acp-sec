"""Score normalization, banding, and CRITICAL penalties.

Standalone port of the scoring helpers in ``dashboard/serve.py`` — copied
(not imported) so ``acpsec_api`` never depends on ``dashboard/``. When the
``acpsec`` package is installed it is the source of truth for banding and
penalties; the fallback tables/logic are only used when it is absent.

Keep in sync with the Flask reference until cutover retires serve.py.
"""

from __future__ import annotations

from typing import Any

from acpsec_api.availability import ACPSEC_AVAILABLE

if ACPSEC_AVAILABLE:
    from acpsec.scorer import ScoringEngine


# Score band table — only used when acpsec is unavailable.
FALLBACK_BANDS = [
    (90, "SECURE",      "Production-ready with active monitoring"),
    (70, "HARDENED",    "Minor gaps present, low overall risk"),
    (50, "VULNERABLE",  "Known exploitable weaknesses — remediate before production"),
    (30, "CRITICAL",    "Multiple high-severity issues — do not deploy"),
    (0,  "COMPROMISED", "Fundamental security failures — immediate halt required"),
]


def calc_band(score_pct: float) -> tuple[str, str]:
    """Return (band, verdict) for a given 0-100 score percentage."""
    if ACPSEC_AVAILABLE:
        return ScoringEngine().band(score_pct)
    for threshold, band, verdict in FALLBACK_BANDS:
        if score_pct >= threshold:
            return band, verdict
    return FALLBACK_BANDS[-1][1], FALLBACK_BANDS[-1][2]


def apply_critical_penalties(score: float, controls: list[dict]) -> float:
    """Deduct a penalty for each unmitigated CRITICAL-severity failure.

    Works with or without the acpsec package installed.
    """
    if ACPSEC_AVAILABLE:
        # Build lightweight CheckResult-compatible objects from the control dicts
        from acpsec.models import CheckResult, CheckStatus, Severity  # noqa: PLC0415

        check_results: list[CheckResult] = []
        for c in controls:
            try:
                sev = Severity(c.get("severity", "MEDIUM").upper())
                status_raw = c.get("status", "fail").lower()
                status = (
                    CheckStatus(status_raw)
                    if status_raw in CheckStatus._value2member_map_
                    else CheckStatus.FAIL
                )
                check_results.append(
                    CheckResult(
                        check_id=c.get("ctrl", "UNKNOWN"),
                        name=c.get("name", ""),
                        dimension=c.get("dimension", ""),
                        status=status,
                        score=float(c.get("score", 0)),
                        max_score=float(c.get("max", 0)),
                        severity=sev,
                    )
                )
            except Exception:
                continue
        return ScoringEngine().apply_penalties(score, check_results)
    else:
        # Fallback: manual penalty calculation
        penalty_per = 5  # mirrors acpsec.scorer.CRITICAL_PENALTY
        critical_failures = [
            c
            for c in controls
            if c.get("severity", "").upper() == "CRITICAL"
            and c.get("status", "fail").lower() == "fail"
        ]
        return max(0.0, score - len(critical_failures) * penalty_per)


def normalise_acpsec(data: dict) -> dict:
    """Convert an acpsec AssessmentResult JSON into the dashboard wire format."""
    controls: list[dict] = []
    for dim in data.get("dimensions", []):
        for check in dim.get("checks", []):
            evidence = check.get("evidence", [])
            controls.append({
                "ctrl":            check["check_id"],
                "name":            check.get("name", check["check_id"]),
                "score":           check.get("score", 0),
                "max":             check.get("max_score", 0),
                "finding":         evidence[0] if evidence else "No evidence recorded.",
                "severity":        check.get("severity", "MEDIUM"),
                "dimension":       dim.get("dimension_id", ""),
                "dimension_name":  dim.get("name", ""),
                "recommendations": check.get("recommendations", []),
                "status":          check.get("status", "fail"),
            })

    return {
        "agent_name":    data.get("agent_name", "Unknown Agent"),
        "agent_version": data.get("agent_version", ""),
        "band":          data.get("band", ""),
        "verdict":       data.get("verdict", ""),
        "final_score":   data.get("final_score", 0),
        "timestamp":     data.get("timestamp", ""),
        "controls":      controls,
        "source":        "acpsec",
    }


def normalise_asf(data: dict) -> dict:
    """Pass-through for the dashboard's native ASF format."""
    return {
        "agent_name":    data.get("agent_name", "Agent"),
        "agent_version": data.get("agent_version", ""),
        "band":          data.get("band", ""),
        "verdict":       data.get("verdict", ""),
        "final_score":   data.get("final_score", 0),
        "timestamp":     data.get("timestamp", ""),
        "controls":      data.get("controls", []),
        "source":        "asf",
    }


def auto_normalise(data: dict) -> dict:
    """Detect format and normalise to the dashboard wire format."""
    if "dimensions" in data:
        return normalise_acpsec(data)
    if "controls" in data:
        return normalise_asf(data)
    raise ValueError(
        "Unrecognised JSON format. "
        "Expected 'dimensions' (acpsec output) or 'controls' (dashboard native) key."
    )


def compute_manual_score(payload: dict) -> dict[str, Any]:
    """Compute the normalised score object for a manual control entry.

    Mirrors the body of POST /api/score/manual in serve.py.
    """
    controls: list[dict] = payload.get("controls", [])
    total_score = sum(float(c.get("score", 0)) for c in controls)
    total_max = sum(float(c.get("max", 0)) for c in controls)

    penalised_score = apply_critical_penalties(total_score, controls)
    score_pct = round(penalised_score / total_max * 100, 1) if total_max > 0 else 0.0
    band, verdict = calc_band(score_pct)

    return {
        "agent_name":    payload.get("agent_name", "Manual Entry"),
        "agent_version": payload.get("agent_version", ""),
        "band":          band,
        "verdict":       verdict,
        "final_score":   round(penalised_score, 2),
        "timestamp":     payload.get("timestamp", ""),
        "controls":      controls,
        "source":        "manual",
        "acpsec_scoring": ACPSEC_AVAILABLE,
    }
