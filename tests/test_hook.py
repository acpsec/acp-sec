"""
Tests for the HOOK dimension (v0.5.0).

Covers each of the 6 checks, the opt-in gate, scoring math, and the
hook-fund-transfer score-cap rule that lives in the ScoringEngine.
"""

from __future__ import annotations

import pytest

from acpsec.checks.hook import run_hook_checks
from acpsec.models import (
    AgentConfig,
    CheckResult,
    CheckStatus,
    DimensionResult,
    HookConfig,
    Severity,
)
from acpsec.scorer import (
    HOOK_FUND_TRANSFER_CAP_PCT,
    HOOK_MIN_SCORE,
    OPTIONAL_DIMENSION_WEIGHTS,
    ScoringEngine,
)


def _compliant_hook() -> HookConfig:
    return HookConfig(
        enabled=True,
        hook_contracts_disclosed=True,
        hook_addresses=["0xABC123"],
        commitment_immutable=True,
        fee_on_transfer_detection=True,
        signature_replay_protection=True,
        chain_id_in_signature=True,
        reentrancy_guard=True,
        expiry_recovery=True,
    )


def _compliant_hook_agent() -> AgentConfig:
    return AgentConfig(name="HOOK-compliant", hook=_compliant_hook())


def _empty_hook_agent() -> AgentConfig:
    return AgentConfig(name="empty-hook", hook=HookConfig(enabled=True))


def _fund_transfer_hook_agent() -> AgentConfig:
    from acpsec.models import CommerceConfig
    agent = _compliant_hook_agent()
    agent.commerce = CommerceConfig(
        enabled=True,
        fund_transfer=True,
        fund_transfer_protections=["daily-cap", "hitl-above-threshold"],
    )
    return agent


# ---------------------------------------------------------------------------
# Opt-in gate + weight
# ---------------------------------------------------------------------------

class TestHookGate:
    def test_hook_disabled_raises(self):
        agent = AgentConfig(name="x", hook=HookConfig(enabled=False))
        with pytest.raises(RuntimeError, match="hook.enabled=false"):
            run_hook_checks(agent)

    def test_hook_weight(self):
        assert OPTIONAL_DIMENSION_WEIGHTS["HOOK"] == 10


# ---------------------------------------------------------------------------
# Compliant — all 6 checks pass
# ---------------------------------------------------------------------------

class TestHookAllPass:
    def test_hook_all_pass(self):
        r = run_hook_checks(_compliant_hook_agent())
        assert r.dimension_id == "HOOK"
        assert r.max_score == 10
        assert r.score == 10, [(c.check_id, c.status, c.score) for c in r.checks]
        assert all(c.status == CheckStatus.PASS for c in r.checks)

    def test_hook_dimension_result_structure(self):
        r = run_hook_checks(_compliant_hook_agent())
        assert r.dimension_id == "HOOK"
        assert r.max_score == 10
        assert len(r.checks) == 6
        check_ids = [c.check_id for c in r.checks]
        assert check_ids == ["HOOK-01", "HOOK-02", "HOOK-03", "HOOK-04", "HOOK-05", "HOOK-06"]


# ---------------------------------------------------------------------------
# Empty config — all 6 checks fail
# ---------------------------------------------------------------------------

class TestHookAllFail:
    def test_hook_all_fail(self):
        r = run_hook_checks(_empty_hook_agent())
        assert r.score == 0, [(c.check_id, c.status, c.score) for c in r.checks]
        assert all(c.status == CheckStatus.FAIL for c in r.checks)


# ---------------------------------------------------------------------------
# Per-check pass paths
# ---------------------------------------------------------------------------

class TestPerCheck:
    def test_hook01_pass_via_config(self):
        agent = AgentConfig(
            name="hook01-config",
            hook=HookConfig(enabled=True, hook_contracts_disclosed=True),
        )
        c = next(c for c in run_hook_checks(agent).checks if c.check_id == "HOOK-01")
        assert c.status == CheckStatus.PASS

    def test_hook01_pass_via_addresses(self):
        agent = AgentConfig(
            name="hook01-addr",
            hook=HookConfig(enabled=True, hook_addresses=["0x123"]),
        )
        c = next(c for c in run_hook_checks(agent).checks if c.check_id == "HOOK-01")
        assert c.status == CheckStatus.PASS

    def test_hook01_pass_via_prompt(self):
        agent = AgentConfig(
            name="hook01-prompt",
            system_prompt="This agent implements the IACPHook interface.",
            hook=HookConfig(enabled=True),
        )
        c = next(c for c in run_hook_checks(agent).checks if c.check_id == "HOOK-01")
        assert c.status == CheckStatus.PASS

    def test_hook02_pass_via_prompt(self):
        agent = AgentConfig(
            name="hook02-prompt",
            system_prompt="Guard against AlreadyDeposited to prevent double-commit.",
            hook=HookConfig(enabled=True),
        )
        c = next(c for c in run_hook_checks(agent).checks if c.check_id == "HOOK-02")
        assert c.status == CheckStatus.PASS

    def test_hook03_pass_via_prompt(self):
        agent = AgentConfig(
            name="hook03-prompt",
            system_prompt="Always perform a balance check before and after transfer.",
            hook=HookConfig(enabled=True),
        )
        c = next(c for c in run_hook_checks(agent).checks if c.check_id == "HOOK-03")
        assert c.status == CheckStatus.PASS

    def test_hook04_pass_via_chain_id(self):
        agent = AgentConfig(
            name="hook04-chain-id",
            hook=HookConfig(enabled=True, chain_id_in_signature=True),
        )
        c = next(c for c in run_hook_checks(agent).checks if c.check_id == "HOOK-04")
        assert c.status == CheckStatus.PASS

    def test_hook05_pass_via_prompt(self):
        agent = AgentConfig(
            name="hook05-prompt",
            system_prompt="Use ReentrancyGuard on all state-changing callbacks.",
            hook=HookConfig(enabled=True),
        )
        c = next(c for c in run_hook_checks(agent).checks if c.check_id == "HOOK-05")
        assert c.status == CheckStatus.PASS

    def test_hook06_pass_via_prompt(self):
        agent = AgentConfig(
            name="hook06-prompt",
            system_prompt="Call recoverTokens when a job has expired.",
            hook=HookConfig(enabled=True),
        )
        c = next(c for c in run_hook_checks(agent).checks if c.check_id == "HOOK-06")
        assert c.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# Hook fund-transfer cap rule (rule 4 in ScoringEngine.apply_penalties)
# ---------------------------------------------------------------------------

def _passing_auth_dim(score: float = 15.0, max_score: float = 15.0) -> DimensionResult:
    return DimensionResult(
        dimension_id="AUTH",
        name="Authentication",
        score=score,
        max_score=max_score,
        checks=[],
    )


def _hook_dim(score: float) -> DimensionResult:
    return DimensionResult(
        dimension_id="HOOK",
        name="ERC-8183 Hook Contract Security",
        score=score,
        max_score=10.0,
        checks=[],
    )


class TestHookFundTransferCap:
    def test_hook_fund_transfer_cap_constant(self):
        assert HOOK_FUND_TRANSFER_CAP_PCT == 30.0

    def test_hook_min_score_constant(self):
        assert HOOK_MIN_SCORE == 6.0

    def test_hook_fund_transfer_cap_rule4(self):
        """fund-transfer agent with HOOK score < 6 must be capped at 30% of max_score."""
        engine = ScoringEngine()
        agent = _fund_transfer_hook_agent()
        # HOOK scores 4/10 (below HOOK_MIN_SCORE=6), AUTH is full (100%)
        dim_results = [_passing_auth_dim(), _hook_dim(score=4.0)]
        result = engine.apply_penalties(
            score=80.0,
            checks=[],
            agent_config=agent,
            max_score=100,
            dimension_results=dim_results,
        )
        # 80 - 0 penalties = 80, then capped at 30% of 100 = 30
        assert result == 30.0

    def test_hook_cap_not_triggered_when_hook_score_sufficient(self):
        """fund-transfer agent with HOOK score >= 6 must NOT trigger the hook cap."""
        engine = ScoringEngine()
        agent = _fund_transfer_hook_agent()
        dim_results = [_passing_auth_dim(), _hook_dim(score=6.0)]
        result = engine.apply_penalties(
            score=80.0,
            checks=[],
            agent_config=agent,
            max_score=100,
            dimension_results=dim_results,
        )
        assert result == 80.0

    def test_hook_cap_not_triggered_without_fund_transfer(self):
        """non-fund-transfer agent with low HOOK score must NOT be capped."""
        engine = ScoringEngine()
        agent = _compliant_hook_agent()  # commerce.fund_transfer=False by default
        dim_results = [_passing_auth_dim(), _hook_dim(score=2.0)]
        result = engine.apply_penalties(
            score=80.0,
            checks=[],
            agent_config=agent,
            max_score=100,
            dimension_results=dim_results,
        )
        assert result == 80.0
