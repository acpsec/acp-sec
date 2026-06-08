"""Canonical ACP v3 job lifecycle state machine.

This is the conformance ground-truth for Dimension 5 — the reference the
adapter and scoring logic are checked against, rather than relying on ABI
keyword matches alone.

Happy path:   open -> budget_set -> funded -> submitted -> completed
Branches:     funded / submitted -> rejected   (escrow returns to Client)
              any non-terminal   -> expired     (permissionless timeout; -> Client)

Settlement:   completed -> Provider, rejected -> Client, expired -> Client.
Gating:       complete is Evaluator-gated and reachable only from submitted, so
              a Provider cannot self-settle by skipping the submitted phase.
"""

from __future__ import annotations

LIFECYCLE_PHASES: tuple[str, ...] = (
    "open", "budget_set", "funded", "submitted", "completed",
)

TERMINAL_PHASES = frozenset({"completed", "rejected", "expired"})

# (from_phase, action, to_phase)
TRANSITIONS: tuple[tuple[str, str, str], ...] = (
    ("open",       "setBudget", "budget_set"),
    ("budget_set", "fund",      "funded"),
    ("funded",     "submit",    "submitted"),
    ("submitted",  "complete",  "completed"),
    ("funded",     "reject",    "rejected"),
    ("submitted",  "reject",    "rejected"),
    ("open",       "expire",    "expired"),
    ("budget_set", "expire",    "expired"),
    ("funded",     "expire",    "expired"),
    ("submitted",  "expire",    "expired"),
)

# Where escrow settles on each terminal phase.
ESCROW_RECIPIENT: dict[str, str] = {
    "completed": "provider",
    "rejected":  "client",
    "expired":   "client",
}

# Authorized caller for each action.
ACTION_CALLER: dict[str, str] = {
    "setBudget": "client",
    "fund":      "client",
    "submit":    "provider",
    "complete":  "evaluator",
    "reject":    "evaluator",
    "expire":    "anyone",
}


class UnknownPhaseError(ValueError):
    """Raised when a phase is not a recognised ACP v3 lifecycle phase."""


def phase_index(phase: str) -> int:
    """Position of a happy-path phase in the linear chain."""
    try:
        return LIFECYCLE_PHASES.index(phase)
    except ValueError as exc:
        raise UnknownPhaseError(f"unknown lifecycle phase: {phase!r}") from exc


def next_phase(phase: str, action: str) -> str | None:
    """Resolve the phase reached by applying ``action`` in ``phase``.

    Returns None when the action is not valid from the given phase (e.g.
    completing before submitting).
    """
    for src, act, dst in TRANSITIONS:
        if src == phase and act == action:
            return dst
    return None


def precedes(a: str, b: str) -> bool:
    """True if happy-path phase ``a`` comes strictly before ``b``."""
    return phase_index(a) < phase_index(b)


def is_terminal(phase: str) -> bool:
    return phase in TERMINAL_PHASES


def escrow_recipient(terminal: str) -> str:
    """Who receives escrow when the job ends in ``terminal``."""
    try:
        return ESCROW_RECIPIENT[terminal]
    except KeyError as exc:
        raise UnknownPhaseError(
            f"{terminal!r} is not a terminal phase with escrow settlement"
        ) from exc


def action_caller(action: str) -> str:
    """Authorized caller role for ``action``."""
    try:
        return ACTION_CALLER[action]
    except KeyError as exc:
        raise UnknownPhaseError(f"unknown action: {action!r}") from exc
