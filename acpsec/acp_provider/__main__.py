"""CLI bridge invoked by the Node Provider to execute a scan job.

The Node seller loop (``provider.mjs``) calls this on the TRANSACTION phase:

    python -m acpsec.acp_provider "<requirement-or-address>" --chain base-sepolia

It parses the target address out of the requirement, runs the Trust Score scan,
and prints a single ACP deliverable JSON object on stdout. On failure it prints
a JSON object with an ``error`` key and exits non-zero so the Node side can
react. All human-readable logging goes to stderr to keep stdout pure JSON.
"""

from __future__ import annotations

import argparse
import json
import sys

from .executor import ScanError, run_scan
from .job_logic import DEFAULT_CHAIN, build_deliverable, parse_scan_target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acpsec.acp_provider")
    parser.add_argument(
        "requirement",
        help="Target 0x address, or a requirement string/JSON containing one.",
    )
    parser.add_argument("--chain", default=DEFAULT_CHAIN)
    parser.add_argument("--scan-mode", default="external")
    parser.add_argument("--no-slither", action="store_true")
    args = parser.parse_args(argv)

    target = parse_scan_target(args.requirement)
    if not target:
        json.dump(
            {"error": "no_target_address", "detail": "no 0x address in requirement"},
            sys.stdout,
        )
        return 2

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
