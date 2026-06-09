"""ACP Provider for acp-sec.

Exposes the acp-sec Trust Score scanner as an ACP (Agent Commerce Protocol)
Provider / seller agent on Base Sepolia. A Client agent submits a "scan address
X" job; this Provider runs the Trust Score scan and delivers the result JSON,
settling through ACP escrow.

The on-chain job lifecycle is driven by the official Node SDK
(`@virtuals-protocol/acp-node`) in ``provider.mjs``. That thin Node loop shells
out to this Python package (``python -m acpsec.acp_provider <requirement>``) to
run the actual scan, reusing the existing ``acpsec trust-score`` engine.

This module holds the pure, unit-testable pieces of the Provider:

- :mod:`acpsec.acp_provider.job_logic` -- parse the scan target out of a job
  requirement, decide accept/reject, and format the Trust Score result into an
  ACP deliverable payload.
- :mod:`acpsec.acp_provider.executor` -- run a Trust Score scan by invoking the
  existing CLI as a subprocess and returning the parsed result.
"""

from __future__ import annotations

from .job_logic import (
    SERVICE_NAME,
    DEFAULT_CHAIN,
    AcceptanceDecision,
    build_deliverable,
    evaluate_request,
    parse_scan_target,
)
from .executor import ScanError, run_scan

__all__ = [
    "SERVICE_NAME",
    "DEFAULT_CHAIN",
    "AcceptanceDecision",
    "build_deliverable",
    "evaluate_request",
    "parse_scan_target",
    "ScanError",
    "run_scan",
]
