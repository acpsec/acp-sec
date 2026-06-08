"""Tests for acpsec/trust_score/acp_lifecycle.py — ACP v3 state machine (TDD).

These assert real state-transition semantics (who can call what, when escrow
releases and to whom, phase ordering), not ABI keyword matches.
"""

import pytest

from acpsec.trust_score.acp_lifecycle import (
    ESCROW_RECIPIENT,
    LIFECYCLE_PHASES,
    TERMINAL_PHASES,
    UnknownPhaseError,
    action_caller,
    escrow_recipient,
    is_terminal,
    next_phase,
    phase_index,
    precedes,
)


# ---------------------------------------------------------------------------
# Canonical phase chain
# ---------------------------------------------------------------------------

class TestPhases:
    def test_five_phases_in_order(self):
        assert LIFECYCLE_PHASES == (
            "open", "budget_set", "funded", "submitted", "completed",
        )

    def test_phase_index_is_monotonic(self):
        idxs = [phase_index(p) for p in LIFECYCLE_PHASES]
        assert idxs == sorted(idxs)

    def test_phase_index_unknown_raises(self):
        with pytest.raises(UnknownPhaseError):
            phase_index("disputed")


# ---------------------------------------------------------------------------
# Happy-path transitions
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_setbudget_opens_budget(self):
        assert next_phase("open", "setBudget") == "budget_set"

    def test_fund_after_budget(self):
        assert next_phase("budget_set", "fund") == "funded"

    def test_submit_after_funded(self):
        assert next_phase("funded", "submit") == "submitted"

    def test_complete_after_submitted(self):
        assert next_phase("submitted", "complete") == "completed"


# ---------------------------------------------------------------------------
# Ordering invariants — submitted must precede completed
# ---------------------------------------------------------------------------

class TestOrdering:
    def test_submitted_precedes_completed(self):
        assert precedes("submitted", "completed") is True

    def test_completed_does_not_precede_submitted(self):
        assert precedes("completed", "submitted") is False

    def test_cannot_complete_directly_from_funded(self):
        # complete is only reachable from submitted — no skipping the submit phase.
        assert next_phase("funded", "complete") is None

    def test_cannot_fund_before_budget_set(self):
        assert next_phase("open", "fund") is None


# ---------------------------------------------------------------------------
# Who may call each action (Evaluator gates completion)
# ---------------------------------------------------------------------------

class TestActionCallers:
    def test_complete_is_evaluator_gated(self):
        assert action_caller("complete") == "evaluator"

    def test_submit_is_provider(self):
        assert action_caller("submit") == "provider"

    def test_fund_is_client(self):
        assert action_caller("fund") == "client"

    def test_reject_is_evaluator(self):
        assert action_caller("reject") == "evaluator"

    def test_expire_is_permissionless(self):
        assert action_caller("expire") == "anyone"


# ---------------------------------------------------------------------------
# Reject branch — escrow returns to Client
# ---------------------------------------------------------------------------

class TestRejectBranch:
    def test_reject_from_funded(self):
        assert next_phase("funded", "reject") == "rejected"

    def test_reject_from_submitted(self):
        assert next_phase("submitted", "reject") == "rejected"

    def test_cannot_reject_from_open(self):
        assert next_phase("open", "reject") is None


# ---------------------------------------------------------------------------
# Expiry branch — permissionless timeout, escrow returns to Client
# ---------------------------------------------------------------------------

class TestExpiryBranch:
    def test_expire_from_funded(self):
        assert next_phase("funded", "expire") == "expired"

    def test_expire_from_submitted(self):
        assert next_phase("submitted", "expire") == "expired"

    def test_cannot_expire_from_completed(self):
        assert next_phase("completed", "expire") is None


# ---------------------------------------------------------------------------
# Escrow settlement semantics
# ---------------------------------------------------------------------------

class TestEscrowRecipient:
    def test_completed_releases_to_provider(self):
        assert escrow_recipient("completed") == "provider"

    def test_rejected_returns_to_client(self):
        assert escrow_recipient("rejected") == "client"

    def test_expired_returns_to_client(self):
        assert escrow_recipient("expired") == "client"

    def test_recipient_map_matches_helper(self):
        for terminal, who in ESCROW_RECIPIENT.items():
            assert escrow_recipient(terminal) == who

    def test_non_terminal_escrow_raises(self):
        with pytest.raises(UnknownPhaseError):
            escrow_recipient("funded")


# ---------------------------------------------------------------------------
# Terminal classification
# ---------------------------------------------------------------------------

class TestTerminal:
    def test_completed_is_terminal(self):
        assert is_terminal("completed") is True

    def test_rejected_is_terminal(self):
        assert is_terminal("rejected") is True

    def test_expired_is_terminal(self):
        assert is_terminal("expired") is True

    def test_funded_is_not_terminal(self):
        assert is_terminal("funded") is False

    def test_terminal_set_contents(self):
        assert TERMINAL_PHASES == frozenset({"completed", "rejected", "expired"})
