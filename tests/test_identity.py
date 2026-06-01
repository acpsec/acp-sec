"""
Tests for the IDENTITY dimension (v0.4.0).

Covers each of the 5 checks (positive + negative paths), the opt-in
gate, scoring math, and the custodial penalty interaction with the
scoring engine.
"""

from __future__ import annotations

import pytest

from acpsec.checks.identity import run_identity_checks
from acpsec.models import (
    AgentConfig,
    CheckStatus,
    IdentityConfig,
    Severity,
)
from acpsec.scorer import (
    CUSTODIAL_WALLET_PENALTY,
    OPTIONAL_DIMENSION_WEIGHTS,
    ScoringEngine,
    total_max_score,
)


def _compliant_identity() -> IdentityConfig:
    return IdentityConfig(
        enabled=True,
        non_custodial=True,
        custodial_wallet=False,
        wallet_provider="privy",
        communication_email="security@example.com",
        communication_channels=["x:@apsecagent", "discord:acp-sec"],
        payment_wallet_address="0x" + "a" * 40,
        payment_card_x402=True,
        erc_8183=True,
        supported_chains=["base", "solana"],
    )


def _compliant_agent() -> AgentConfig:
    return AgentConfig(
        name="ID-compliant",
        identity=_compliant_identity(),
    )


def _empty_identity_agent() -> AgentConfig:
    return AgentConfig(
        name="ID-empty",
        identity=IdentityConfig(enabled=True),  # all fields default-False/empty
    )


def _custodial_agent() -> AgentConfig:
    cfg = _compliant_agent()
    cfg.identity.custodial_wallet = True
    cfg.identity.non_custodial = False
    return cfg


# ---------------------------------------------------------------------------
# Opt-in gate
# ---------------------------------------------------------------------------

class TestIdentityGate:
    def test_raises_when_disabled(self):
        agent = AgentConfig(name="x", identity=IdentityConfig(enabled=False))
        with pytest.raises(RuntimeError, match="identity.enabled=false"):
            run_identity_checks(agent)

    def test_dimension_weight(self):
        assert OPTIONAL_DIMENSION_WEIGHTS["IDENTITY"] == 10


# ---------------------------------------------------------------------------
# Compliant — all 5 checks pass, dim scores 10/10
# ---------------------------------------------------------------------------

class TestCompliant:
    def test_all_five_pass(self):
        r = run_identity_checks(_compliant_agent())
        assert r.dimension_id == "IDENTITY"
        assert r.max_score == 10
        assert r.score == 10, [(c.check_id, c.status, c.score) for c in r.checks]
        assert [c.check_id for c in r.checks] == \
            ["ID-01", "ID-02", "ID-03", "ID-04", "ID-05"]
        assert all(c.status == CheckStatus.PASS for c in r.checks)


# ---------------------------------------------------------------------------
# Per-check failure paths
# ---------------------------------------------------------------------------

class TestPerCheck:
    def test_id01_critical_severity(self):
        c = next(c for c in run_identity_checks(_compliant_agent()).checks
                 if c.check_id == "ID-01")
        assert c.severity == Severity.CRITICAL
        assert c.max_score == 3

    def test_id01_fails_when_custodial(self):
        c = next(c for c in run_identity_checks(_custodial_agent()).checks
                 if c.check_id == "ID-01")
        assert c.status == CheckStatus.FAIL

    def test_id01_prompt_signal_only(self):
        agent = AgentConfig(
            name="prompt-only",
            system_prompt="We use Privy for non-custodial wallets via OS Keychain.",
            identity=IdentityConfig(enabled=True),
        )
        c = next(c for c in run_identity_checks(agent).checks if c.check_id == "ID-01")
        assert c.status == CheckStatus.PASS, c.evidence

    def test_id02_fails_when_no_contact(self):
        c = next(c for c in run_identity_checks(_empty_identity_agent()).checks
                 if c.check_id == "ID-02")
        assert c.status == CheckStatus.FAIL

    def test_id02_email_alone_is_enough(self):
        agent = AgentConfig(
            name="email-only",
            identity=IdentityConfig(enabled=True, communication_email="x@y.io"),
        )
        c = next(c for c in run_identity_checks(agent).checks if c.check_id == "ID-02")
        assert c.status == CheckStatus.PASS

    def test_id03_requires_address_or_x402(self):
        # Empty → fail
        c = next(c for c in run_identity_checks(_empty_identity_agent()).checks
                 if c.check_id == "ID-03")
        assert c.status == CheckStatus.FAIL
        # x402 alone passes
        agent = AgentConfig(name="x", identity=IdentityConfig(
            enabled=True, payment_card_x402=True,
        ))
        c = next(c for c in run_identity_checks(agent).checks if c.check_id == "ID-03")
        assert c.status == CheckStatus.PASS

    def test_id03_rejects_malformed_address(self):
        agent = AgentConfig(name="x", identity=IdentityConfig(
            enabled=True, payment_wallet_address="0xshort",
        ))
        c = next(c for c in run_identity_checks(agent).checks if c.check_id == "ID-03")
        assert c.status == CheckStatus.FAIL

    def test_id04_prompt_signal_accepted(self):
        agent = AgentConfig(
            name="prompt-erc",
            system_prompt="We comply with ERC-8183 for cross-agent identity.",
            identity=IdentityConfig(enabled=True),
        )
        c = next(c for c in run_identity_checks(agent).checks if c.check_id == "ID-04")
        assert c.status == CheckStatus.PASS

    def test_id05_passes_with_one_chain(self):
        agent = AgentConfig(name="x", identity=IdentityConfig(
            enabled=True, supported_chains=["base"],
        ))
        c = next(c for c in run_identity_checks(agent).checks if c.check_id == "ID-05")
        assert c.status == CheckStatus.PASS
        assert c.severity == Severity.LOW


# ---------------------------------------------------------------------------
# Custodial-wallet penalty (-10) via ScoringEngine
# ---------------------------------------------------------------------------

class TestCustodialPenalty:
    def test_custodial_penalty_constant(self):
        assert CUSTODIAL_WALLET_PENALTY == 10

    def test_apply_penalties_deducts_10_when_custodial(self):
        # 100-pt baseline with no critical fails, custodial_wallet=true.
        engine = ScoringEngine()
        agent = _custodial_agent()
        result = engine.apply_penalties(
            score=50.0, checks=[], agent_config=agent, max_score=100,
        )
        # No CRITICAL fails in the empty `checks` list, so only the
        # custodial penalty applies: 50 - 10 = 40.
        assert result == 40.0

    def test_no_custodial_penalty_when_flag_off(self):
        engine = ScoringEngine()
        result = engine.apply_penalties(
            score=50.0, checks=[], agent_config=_compliant_agent(), max_score=100,
        )
        assert result == 50.0

    def test_penalty_floors_at_zero(self):
        engine = ScoringEngine()
        result = engine.apply_penalties(
            score=5.0, checks=[], agent_config=_custodial_agent(), max_score=100,
        )
        assert result == 0.0


# ---------------------------------------------------------------------------
# total_max_score arithmetic
# ---------------------------------------------------------------------------

class TestTotalMaxScore:
    def test_identity_alone(self):
        assert total_max_score(("IDENTITY",)) == 110

    def test_identity_plus_commerce(self):
        assert total_max_score(("IDENTITY", "COMMERCE")) == 120

    def test_all_optionals(self):
        # 100 + 10 (X402) + 12 (MCP) + 3 (PLUGIN) + 10 (IDENTITY) + 10 (COMMERCE)
        assert total_max_score(
            ("X402", "MCP", "PLUGIN", "IDENTITY", "COMMERCE"),
        ) == 145
