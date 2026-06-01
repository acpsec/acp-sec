"""
Tests for the COMMERCE dimension (v0.4.0).

Covers each of the 5 checks, the opt-in gate, scoring math, and the
fund-transfer score-cap rule that lives in the ScoringEngine.
"""

from __future__ import annotations

import pytest

from acpsec.checks.commerce import run_commerce_checks
from acpsec.models import (
    AgentConfig,
    CheckResult,
    CheckStatus,
    CommerceConfig,
    DimensionResult,
    Severity,
)
from acpsec.scorer import (
    FUND_TRANSFER_CAP_PCT,
    OPTIONAL_DIMENSION_WEIGHTS,
    ScoringEngine,
)


def _compliant_commerce() -> CommerceConfig:
    return CommerceConfig(
        enabled=True,
        escrow=True,
        escrow_provider="acp-core",
        evaluator=True,
        evaluator_url="https://evaluator.example.io",
        job_types=["service", "subscription"],
        fund_transfer=False,
        fund_transfer_protections=[],
        lifecycle_documented=True,
    )


def _compliant_agent() -> AgentConfig:
    return AgentConfig(name="CMR-compliant", commerce=_compliant_commerce())


def _fund_transfer_agent() -> AgentConfig:
    cfg = _compliant_agent()
    cfg.commerce.fund_transfer = True
    cfg.commerce.fund_transfer_protections = ["daily-cap", "hitl-above-threshold"]
    cfg.commerce.job_types = ["service", "fund-transfer"]
    return cfg


def _empty_commerce_agent() -> AgentConfig:
    return AgentConfig(name="empty", commerce=CommerceConfig(enabled=True))


# ---------------------------------------------------------------------------
# Opt-in gate + weight
# ---------------------------------------------------------------------------

class TestCommerceGate:
    def test_raises_when_disabled(self):
        agent = AgentConfig(name="x", commerce=CommerceConfig(enabled=False))
        with pytest.raises(RuntimeError, match="commerce.enabled=false"):
            run_commerce_checks(agent)

    def test_dimension_weight(self):
        assert OPTIONAL_DIMENSION_WEIGHTS["COMMERCE"] == 10


# ---------------------------------------------------------------------------
# Compliant — all 5 checks pass
# ---------------------------------------------------------------------------

class TestCompliant:
    def test_all_five_pass(self):
        r = run_commerce_checks(_compliant_agent())
        assert r.dimension_id == "COMMERCE"
        assert r.max_score == 10
        assert r.score == 10, [(c.check_id, c.status, c.score) for c in r.checks]
        assert all(c.status == CheckStatus.PASS for c in r.checks)
        assert [c.check_id for c in r.checks] == \
            ["CMR-01", "CMR-02", "CMR-03", "CMR-04", "CMR-05"]


# ---------------------------------------------------------------------------
# Per-check failure paths
# ---------------------------------------------------------------------------

class TestPerCheck:
    def test_cmr01_critical_severity(self):
        c = next(c for c in run_commerce_checks(_compliant_agent()).checks
                 if c.check_id == "CMR-01")
        assert c.severity == Severity.CRITICAL
        assert c.max_score == 3

    def test_cmr01_fails_without_escrow(self):
        c = next(c for c in run_commerce_checks(_empty_commerce_agent()).checks
                 if c.check_id == "CMR-01")
        assert c.status == CheckStatus.FAIL

    def test_cmr02_fails_without_evaluator(self):
        c = next(c for c in run_commerce_checks(_empty_commerce_agent()).checks
                 if c.check_id == "CMR-02")
        assert c.status == CheckStatus.FAIL

    def test_cmr03_rejects_unknown_job_types(self):
        agent = AgentConfig(name="x", commerce=CommerceConfig(
            enabled=True, job_types=["wishful-thinking"],
        ))
        c = next(c for c in run_commerce_checks(agent).checks if c.check_id == "CMR-03")
        assert c.status == CheckStatus.FAIL

    def test_cmr03_passes_with_one_recognised_type(self):
        agent = AgentConfig(name="x", commerce=CommerceConfig(
            enabled=True, job_types=["service"],
        ))
        c = next(c for c in run_commerce_checks(agent).checks if c.check_id == "CMR-03")
        assert c.status == CheckStatus.PASS

    def test_cmr04_vacuous_pass_when_not_fund_transfer(self):
        # An agent that doesn't claim fund_transfer passes CMR-04 vacuously.
        c = next(c for c in run_commerce_checks(_compliant_agent()).checks
                 if c.check_id == "CMR-04")
        assert c.status == CheckStatus.PASS

    def test_cmr04_fails_when_fund_transfer_without_protections(self):
        agent = _fund_transfer_agent()
        agent.commerce.fund_transfer_protections = []
        c = next(c for c in run_commerce_checks(agent).checks if c.check_id == "CMR-04")
        assert c.status == CheckStatus.FAIL

    def test_cmr04_passes_with_declared_protections(self):
        c = next(c for c in run_commerce_checks(_fund_transfer_agent()).checks
                 if c.check_id == "CMR-04")
        assert c.status == CheckStatus.PASS

    def test_cmr05_low_severity(self):
        c = next(c for c in run_commerce_checks(_compliant_agent()).checks
                 if c.check_id == "CMR-05")
        assert c.severity == Severity.LOW
        assert c.max_score == 1

    def test_cmr05_prompt_signal_accepted(self):
        agent = AgentConfig(
            name="prompt-only",
            system_prompt="Our job lifecycle: offer → escrow → release.",
            commerce=CommerceConfig(enabled=True),
        )
        c = next(c for c in run_commerce_checks(agent).checks if c.check_id == "CMR-05")
        assert c.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# Fund-transfer cap rule (lives in ScoringEngine)
# ---------------------------------------------------------------------------

def _critical_failure_check() -> CheckResult:
    return CheckResult(
        check_id="X-FAIL", name="forced critical", dimension="X",
        status=CheckStatus.FAIL, score=0.0, max_score=5.0,
        severity=Severity.CRITICAL,
    )


def _passing_check(max_score: float = 5.0) -> CheckResult:
    return CheckResult(
        check_id="X-PASS", name="forced pass", dimension="X",
        status=CheckStatus.PASS, score=max_score, max_score=max_score,
        severity=Severity.HIGH,
    )


class TestFundTransferCap:
    def test_cap_constant(self):
        assert FUND_TRANSFER_CAP_PCT == 30.0

    def test_no_cap_without_fund_transfer(self):
        engine = ScoringEngine()
        agent = _compliant_agent()        # fund_transfer = False
        result = engine.apply_penalties(
            score=80.0, checks=[_critical_failure_check()],
            agent_config=agent, max_score=100,
        )
        # Just the CRITICAL_PENALTY (-5) applies. Cap NOT triggered.
        assert result == 75.0

    def test_no_cap_without_critical_fails(self):
        engine = ScoringEngine()
        agent = _fund_transfer_agent()
        # All checks pass — cap should NOT engage even with fund_transfer=true.
        result = engine.apply_penalties(
            score=80.0, checks=[_passing_check()],
            agent_config=agent, max_score=100,
        )
        assert result == 80.0

    def test_cap_engages_at_30_when_fund_transfer_and_critical(self):
        engine = ScoringEngine()
        agent = _fund_transfer_agent()
        result = engine.apply_penalties(
            score=80.0, checks=[_critical_failure_check()],
            agent_config=agent, max_score=100,
        )
        # 80 - 5 (CRITICAL) = 75, then capped at 30% of 100 = 30.0
        assert result == 30.0

    def test_cap_scales_with_max_score(self):
        # For a /110 budget (e.g. with X402 enabled), the cap is 30% of 110 = 33.
        engine = ScoringEngine()
        agent = _fund_transfer_agent()
        result = engine.apply_penalties(
            score=80.0, checks=[_critical_failure_check()],
            agent_config=agent, max_score=110,
        )
        assert result == 33.0

    def test_warning_appears_in_assessment_metadata(self):
        engine = ScoringEngine()
        agent = _fund_transfer_agent()
        # Build a synthetic dimension with one critical fail.
        dim = DimensionResult(
            dimension_id="X", name="X",
            score=0.0, max_score=5.0,
            checks=[_critical_failure_check()],
        )
        assessment = engine.build_assessment(
            "X-agent", "1.0", [dim], agent_config=agent,
        )
        warnings_ = assessment.metadata.get("penalty_warnings", [])
        assert any("Fund-transfer" in w for w in warnings_), warnings_
