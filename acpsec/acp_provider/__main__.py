"""CLI bridge invoked by the Node Provider for both job phases.

The Node seller loop (``provider.mjs``) calls this two ways:

    # REQUEST phase -- accept/reject decision (no scan, no network):
    python -m acpsec.acp_provider "<requirement-or-address>" --mode evaluate

    # TRANSACTION phase -- run the Trust Score scan:
    python -m acpsec.acp_provider "<requirement-or-address>" --chain base-sepolia

Both modes route the requirement through :func:`evaluate_request`, the single
source of truth for parsing + accept/reject. ``--mode evaluate`` prints the
decision (``{accept, reason, target}``) and exits 0 for both accept and reject
(rejection is a valid decision, not an error). Scan mode reuses the very same
decision: it scans ``decision.target`` -- so the address accepted at REQUEST
time is, by construction, the address scanned at TRANSACTION time.

On scan failure it prints a JSON object with an ``error`` key and exits
non-zero so the Node side can react. All human-readable logging goes to stderr
to keep stdout pure JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from .executor import ScanError, run_scan
from .job_logic import DEFAULT_CHAIN, build_deliverable, evaluate_request


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acpsec.acp_provider")
    parser.add_argument(
        "requirement",
        help="Target 0x address, or a requirement string/JSON containing one.",
    )
    parser.add_argument(
        "--mode",
        choices=["scan", "evaluate"],
        default="scan",
        help="'evaluate' returns the accept/reject decision; 'scan' runs the scan.",
    )
    parser.add_argument("--chain", default=DEFAULT_CHAIN)
    parser.add_argument("--scan-mode", default="external")
    parser.add_argument("--no-slither", action="store_true")
    args = parser.parse_args(argv)

    # The Node side passes objects as a JSON string (JSON.stringify); restore the
    # structure so evaluate_request's priority-key parsing (address/agent/target/
    # contract win first) works instead of a flat first-match on serialized text.
    # A plain address or sentence isn't valid JSON -> fall back to the raw string.
    try:
        requirement = json.loads(args.requirement)
    except (json.JSONDecodeError, TypeError):
        requirement = args.requirement

    # Single source of truth: parse + accept/reject live only in evaluate_request.
    decision = evaluate_request(requirement)

    if args.mode == "evaluate":
        # Accept and reject are both successful evaluations (exit 0); the verdict
        # is carried in the `accept` field for the Node side to act on.
        json.dump(asdict(decision), sys.stdout)
        return 0

    # Scan mode -- gate on the same decision instead of re-checking inline.
    if not decision.accept:
        json.dump(
            {"error": "no_target_address", "detail": decision.reason},
            sys.stdout,
        )
        return 2

    target = decision.target  # the exact address evaluate_request accepted
    print(f"acp-sec: scanning {target} on {args.chain}...", file=sys.stderr)
    try:
        trust = run_scan(
            target,
            chain=args.chain,
            scan_mode=args.scan_mode,
            no_slither=args.no_slither,
        )
    except ScanError as exc:
        json.dump({"error": "scan_failed", "detail": str(exc)}, sys.stdout)
        return 1

    json.dump(build_deliverable(trust), sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
