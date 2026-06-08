"""Slither static-analysis runner.

Invokes Slither as a subprocess and normalises its JSON output into a flat
list of SlitherFinding objects.  Informational-impact detectors are dropped
— only High, Medium, and Low findings are returned.

Injectable `_subprocess_run` callable signature:
    (cmd: list[str]) -> tuple[returncode: int, stdout: str, stderr: str]
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Callable

_EXCLUDED_IMPACTS = {"Informational", "Optimization"}


class SlitherError(Exception):
    """Raised when Slither reports a compilation/analysis failure or its output
    cannot be parsed."""


class SlitherNotAvailable(Exception):
    """Raised when the Slither executable is not found on PATH."""


@dataclass
class SlitherFinding:
    check: str
    impact: str
    confidence: str
    description: str


def _default_subprocess_run(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


class SlitherRunner:
    def __init__(
        self,
        executable: str = "slither",
        _subprocess_run: Callable[[list[str]], tuple[int, str, str]] | None = None,
    ) -> None:
        self._executable = executable
        self._run = _subprocess_run or _default_subprocess_run

    def run(self, target: str, api_key: str | None = None) -> list[SlitherFinding]:
        cmd = [self._executable, target, "--json", "-"]
        if api_key:
            cmd += ["--etherscan-apikey", api_key]

        try:
            returncode, stdout, stderr = self._run(cmd)
        except FileNotFoundError as exc:
            raise SlitherNotAvailable(
                f"Slither executable not found: {self._executable!r}. "
                "Install with: pip install slither-analyzer"
            ) from exc

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise SlitherError(
                f"Failed to parse Slither JSON output (exit {returncode}): {exc}\n"
                f"stdout: {stdout[:200]!r}"
            ) from exc

        if not payload.get("success", True):
            raise SlitherError(
                f"Slither analysis failed: {payload.get('error', 'unknown error')}"
            )

        detectors = payload.get("results", {}).get("detectors", [])
        return [
            SlitherFinding(
                check=d["check"],
                impact=d["impact"],
                confidence=d.get("confidence", ""),
                description=d.get("description", ""),
            )
            for d in detectors
            if d.get("impact") not in _EXCLUDED_IMPACTS
        ]
