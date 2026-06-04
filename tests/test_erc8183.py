"""
Tests for the ERC8183 dimension (v0.5.0).

Covers the opt-in gate, dimension weight, all five checks (ERC-01 through
ERC-05), partial-credit paths, prompt-signal detection, and the returned
DimensionResult structure.
"""

from __future__ import annotations

import pytest

from acpsec.checks.erc8183 import run_erc8183_checks
from acpsec.models import AgentConfig, CheckStatus, ERC8183Config
from acpsec.scorer import OPTIONAL_DIMENSION_WEIGHTS


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _compliant_erc8183() -> ERC8183Config:
    return ERC8183Config(
        enabled=True,
        job_lifecycle_documented=True,
        hook_architecture_documented=True,
        evaluator_disclosed=True,
        fee_split_documented=True,
        job_type_declared=True,
        supported_chains=["base", "ethereum"],
    )


def _compliant_agent() -> AgentConfig:
    return AgentConfig(name="ERC8183-compliant", erc8183=_compliant_erc8183())


def _empty_erc8183_agent() -> AgentConfig:
    """Agent with the dimension enabled but every flag at its default (False/empty)."""
    return AgentConfig(name="empty", erc8183=ERC8183Config(enabled=True))


# ---------------------------------------------------------------------------
# Opt-in gate + weight
# ---------------------------------------------------------------------------

class TestERC8183Gate:
    def test_erc8183_disabled_raises(self):
        agent = AgentConfig(name="x", erc8183=ERC8183Config(enabled=False))
        with pytest.raises(RuntimeError, match="erc8183.enabled=false"):
            run_erc8183_checks(agent)

    def test_erc8183_weight(self):
        assert OPTIONAL_DIMENSION_WEIGHTS["ERC8183"] == 10


# ---------------------------------------------------------------------------
# All-pass / all-fail smoke tests
# ---------------------------------------------------------------------------

class TestBoundaryScores:
    def test_erc8183_all_pass(self):
        r = run_erc8183_checks(_compliant_agent())
        assert r.dimension_id == "ERC8183"
        assert r.max_score == 10
        assert r.score == 10, [(c.check_id, c.status, c.score) for c in r.checks]
        assert all(c.status == CheckStatus.PASS for c in r.checks)

    def test_erc8183_all_fail(self):
        r = run_erc8183_checks(_empty_erc8183_agent())
        assert r.score == 0, [(c.check_id, c.status, c.score) for c in r.checks]
        assert all(c.status in (CheckStatus.FAIL, CheckStatus.WARN) for c in r.checks)


# ---------------------------------------------------------------------------
# ERC-01 — Job lifecycle statuses disclosed (3 pts, HIGH)
# ---------------------------------------------------------------------------

class TestERC01:
    def _check(self, agent: AgentConfig):
        return next(c for c in run_erc8183_checks(agent).checks if c.check_id == "ERC-01")

    def test_erc01_full_pass_via_config(self):
        """job_lifecycle_documented=True earns full 3 pts."""
        agent = AgentConfig(
            name="x",
            erc8183=ERC8183Config(enabled=True, job_lifecycle_documented=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS
        assert c.score == 3

    def test_erc01_partial_via_prompt(self):
        """System prompt containing 3 of 6 lifecycle statuses earns 1.5 pts (WARN)."""
        agent = AgentConfig(
            name="x",
            system_prompt="This agent supports open, funded, and submitted jobs.",
            erc8183=ERC8183Config(enabled=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.WARN
        assert c.score == 1.5

    def test_erc01_full_via_prompt(self):
        """Prompt containing all 6 statuses earns full 3 pts."""
        prompt = (
            "Job states: open, funded, submitted, completed, rejected, expired."
        )
        agent = AgentConfig(
            name="x",
            system_prompt=prompt,
            erc8183=ERC8183Config(enabled=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS
        assert c.score == 3

    def test_erc01_fails_with_no_signals(self):
        c = self._check(_empty_erc8183_agent())
        assert c.status == CheckStatus.FAIL
        assert c.score == 0
        assert c.max_score == 3


# ---------------------------------------------------------------------------
# ERC-02 — Hook architecture documented (2 pts, HIGH)
# ---------------------------------------------------------------------------

class TestERC02:
    def _check(self, agent: AgentConfig):
        return next(c for c in run_erc8183_checks(agent).checks if c.check_id == "ERC-02")

    def test_erc02_pass_via_prompt(self):
        """'beforeaction' in system_prompt satisfies ERC-02."""
        agent = AgentConfig(
            name="x",
            system_prompt="This service calls beforeAction on every transaction.",
            erc8183=ERC8183Config(enabled=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS
        assert c.score == 2

    def test_erc02_pass_via_config(self):
        agent = AgentConfig(
            name="x",
            erc8183=ERC8183Config(enabled=True, hook_architecture_documented=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS

    def test_erc02_fails_with_no_signals(self):
        c = self._check(_empty_erc8183_agent())
        assert c.status == CheckStatus.FAIL
        assert c.score == 0


# ---------------------------------------------------------------------------
# ERC-03 — Evaluator role and fee split disclosed (2 pts, MEDIUM)
# ---------------------------------------------------------------------------

class TestERC03:
    def _check(self, agent: AgentConfig):
        return next(c for c in run_erc8183_checks(agent).checks if c.check_id == "ERC-03")

    def test_erc03_partial_evaluator_only(self):
        """evaluator_disclosed=True but fee_split_documented=False → 1 pt partial."""
        agent = AgentConfig(
            name="x",
            erc8183=ERC8183Config(enabled=True, evaluator_disclosed=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.WARN
        assert c.score == 1

    def test_erc03_full_pass(self):
        """Both evaluator_disclosed=True AND fee_split_documented=True → 2 pts."""
        agent = AgentConfig(
            name="x",
            erc8183=ERC8183Config(
                enabled=True,
                evaluator_disclosed=True,
                fee_split_documented=True,
            ),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS
        assert c.score == 2

    def test_erc03_pass_via_prompt_fee_split(self):
        """'evaluator' and '90/5/5' in prompt scores full 2 pts."""
        agent = AgentConfig(
            name="x",
            system_prompt="Fees are split 90/5/5 between agent, evaluator, and protocol.",
            erc8183=ERC8183Config(enabled=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS
        assert c.score == 2

    def test_erc03_fails_with_no_signals(self):
        c = self._check(_empty_erc8183_agent())
        assert c.status == CheckStatus.FAIL
        assert c.score == 0


# ---------------------------------------------------------------------------
# ERC-04 — Job type categorization declared (2 pts, MEDIUM)
# ---------------------------------------------------------------------------

class TestERC04:
    def _check(self, agent: AgentConfig):
        return next(c for c in run_erc8183_checks(agent).checks if c.check_id == "ERC-04")

    def test_erc04_pass_via_prompt(self):
        """'fund-transfer' in system_prompt satisfies ERC-04."""
        agent = AgentConfig(
            name="x",
            system_prompt="This agent handles fund-transfer jobs only.",
            erc8183=ERC8183Config(enabled=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS
        assert c.score == 2

    def test_erc04_pass_via_config(self):
        agent = AgentConfig(
            name="x",
            erc8183=ERC8183Config(enabled=True, job_type_declared=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS

    def test_erc04_fails_with_no_signals(self):
        c = self._check(_empty_erc8183_agent())
        assert c.status == CheckStatus.FAIL
        assert c.score == 0


# ---------------------------------------------------------------------------
# ERC-05 — Multi-chain support documented (1 pt, LOW)
# ---------------------------------------------------------------------------

class TestERC05:
    def _check(self, agent: AgentConfig):
        return next(c for c in run_erc8183_checks(agent).checks if c.check_id == "ERC-05")

    def test_erc05_pass_via_chains(self):
        """supported_chains with valid ERC-8183 chains passes ERC-05."""
        agent = AgentConfig(
            name="x",
            erc8183=ERC8183Config(
                enabled=True,
                supported_chains=["base", "ethereum"],
            ),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS
        assert c.score == 1

    def test_erc05_pass_via_prompt(self):
        """'base' in system_prompt satisfies ERC-05."""
        agent = AgentConfig(
            name="x",
            system_prompt="This agent operates on the base network.",
            erc8183=ERC8183Config(enabled=True),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.PASS
        assert c.score == 1

    def test_erc05_fails_unrecognised_chain(self):
        """An unrecognised chain name does not satisfy ERC-05."""
        agent = AgentConfig(
            name="x",
            erc8183=ERC8183Config(enabled=True, supported_chains=["mychain"]),
        )
        c = self._check(agent)
        assert c.status == CheckStatus.FAIL
        assert c.score == 0

    def test_erc05_fails_with_no_signals(self):
        c = self._check(_empty_erc8183_agent())
        assert c.status == CheckStatus.FAIL
        assert c.score == 0


# ---------------------------------------------------------------------------
# DimensionResult structure
# ---------------------------------------------------------------------------

class TestDimensionResultStructure:
    def test_erc8183_dimension_result_structure(self):
        """Returned DimensionResult has correct dimension_id, max_score, and 5 checks."""
        r = run_erc8183_checks(_compliant_agent())
        assert r.dimension_id == "ERC8183"
        assert r.max_score == 10
        assert len(r.checks) == 5
        assert [c.check_id for c in r.checks] == [
            "ERC-01", "ERC-02", "ERC-03", "ERC-04", "ERC-05"
        ]
