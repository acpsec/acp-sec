"""Pure, unit-testable job logic for the acp-sec ACP Provider.

These helpers contain no network or chain I/O so they can be exercised in
isolation:

- :func:`parse_scan_target` -- pull the target contract address out of whatever
  shape the buyer put in the job requirement (string, dict, nested).
- :func:`evaluate_request` -- decide whether to accept the job and why.
- :func:`build_deliverable` -- wrap a Trust Score result into the ACP
  ``DeliverablePayload`` shape the Node SDK delivers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

SERVICE_NAME = "acp-sec-trust-score"
DEFAULT_CHAIN = "base-sepolia"

# An EVM contract/account address: 0x followed by 40 hex chars. We do not enforce
# EIP-55 checksum casing -- buyers may send a lowercased address.
_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _iter_strings(obj: Any) -> Iterator[str]:
    """Yield every string found anywhere inside ``obj`` (str/dict/list/tuple)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        # Prefer explicit address-bearing keys first so they win when present.
        priority = ("address", "agent", "target", "contract")
        for key in priority:
            if key in obj:
                yield from _iter_strings(obj[key])
        for key, value in obj.items():
            if key in priority:
                continue
            yield from _iter_strings(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _iter_strings(value)


def parse_scan_target(requirement: Any) -> str | None:
    """Extract the target 0x contract address from a job requirement.

    Accepts the requirement as a string, a dict (e.g.
    ``{"address": "0x..."}`` or ``{"type": "scan", "value": "scan 0x..."}``),
    or nested structures. Returns the first address found, or ``None``.
    """
    for text in _iter_strings(requirement):
        match = _ADDRESS_RE.search(text)
        if match:
            return match.group(0)
    return None


@dataclass(frozen=True)
class AcceptanceDecision:
    """Outcome of evaluating an incoming job request."""

    accept: bool
    reason: str
    target: str | None = None


def evaluate_request(requirement: Any) -> AcceptanceDecision:
    """Decide whether to accept a scan job and produce a human-readable reason.

    We accept any request that contains a parseable 0x address; otherwise we
    reject and tell the buyer how to phrase the request.
    """
    target = parse_scan_target(requirement)
    if target is None:
        return AcceptanceDecision(
            accept=False,
            reason=(
                "No contract address found in the request. Send the target as a "
                '0x address, e.g. {"address": "0x7770..."} or '
                '"scan address 0x7770...".'
            ),
            target=None,
        )
    return AcceptanceDecision(
        accept=True,
        reason=(
            f"acp-sec will run a Trust Score scan on {target} (Base Sepolia) and "
            "deliver the result JSON."
        ),
        target=target,
    )


def build_deliverable(trust_json: dict[str, Any]) -> dict[str, Any]:
    """Wrap a Trust Score result into an ACP ``DeliverablePayload`` (object form).

    The Node SDK accepts a deliverable of ``string | Record<string, unknown>``.
    We send an object carrying a short human summary plus the full Trust Score
    result so the buyer/evaluator can verify it.
    """
    agent = trust_json.get("agent", "unknown")
    score = trust_json.get("score")
    grade = trust_json.get("grade")
    rated = trust_json.get("rated")
    rated_note = "" if rated else " (Unrated -- partial data)"
    summary = (
        f"acp-sec Trust Score for {agent}: {score}/100, grade {grade}{rated_note}."
    )
    return {
        "type": "object",
        "service": SERVICE_NAME,
        "summary": summary,
        "value": trust_json,
    }
