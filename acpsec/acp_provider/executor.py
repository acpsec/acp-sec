"""Run a Trust Score scan as a subprocess and return the parsed result.

The Provider reuses the existing ``acpsec trust-score`` CLI as its job
executor. We invoke it as ``python -m acpsec.cli trust-score ...`` (rather than
copying the multi-dimension orchestration) so the scan stays a single source of
truth. The Basescan API key is passed through the child environment, never on
the command line, so it does not leak into the process listing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


class ScanError(RuntimeError):
    """Raised when the Trust Score scan subprocess fails or yields no output."""


def run_scan(
    address: str,
    *,
    chain: str = "base-sepolia",
    scan_mode: str = "external",
    no_slither: bool = False,
    basescan_key: str | None = None,
    timeout: int = 600,
    python_executable: str | None = None,
) -> dict[str, Any]:
    """Run ``acpsec trust-score`` for ``address`` and return the result dict.

    Parameters mirror the CLI flags. ``basescan_key`` defaults to the
    ``BASESCAN_API_KEY`` environment variable. Raises :class:`ScanError` on any
    failure so the Provider can reject/notify the buyer cleanly.
    """
    key = basescan_key or os.environ.get("BASESCAN_API_KEY", "")
    if not key:
        raise ScanError(
            "BASESCAN_API_KEY is not set; it is required to run a live "
            "Trust Score scan."
        )

    python = python_executable or sys.executable
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "trust-score.json"
        cmd = [
            python,
            "-m",
            "acpsec.cli",
            "trust-score",
            "--agent",
            address,
            "--chain",
            chain,
            "--scan-mode",
            scan_mode,
            "--output",
            str(out_path),
        ]
        if no_slither:
            cmd.append("--no-slither")

        # Pass the key via the environment, not argv, to keep it out of `ps`.
        child_env = {**os.environ, "BASESCAN_API_KEY": key}
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=child_env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"scan timed out after {timeout}s") from exc

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise ScanError(
                f"trust-score exited with code {proc.returncode}: {detail}"
            )
        if not out_path.exists():
            raise ScanError("trust-score completed but produced no output JSON")

        try:
            return json.loads(out_path.read_text())
        except json.JSONDecodeError as exc:
            raise ScanError(f"could not parse trust-score output: {exc}") from exc
