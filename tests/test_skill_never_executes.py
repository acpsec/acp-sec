"""The core safety invariant: scan-skill never executes bundled skill code."""

from __future__ import annotations

import shutil
from pathlib import Path

from click.testing import CliRunner

from acpsec.checks.skill_code import scan_code
from acpsec.cli import main
from acpsec.config_loader import load_skill_manifest
from acpsec.injection.skill_patterns import scan_instructions
from acpsec.skill_manifest import scan_manifest
from acpsec.skill_scan import scan_skill

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def _sentinels(folder: Path) -> list[Path]:
    return list(folder.rglob("SENTINEL_EXECUTED*"))


def test_scan_skill_never_executes_bundled_code(tmp_path):
    # Copy the fixture so any accidental execution writes into tmp, not the repo.
    dst = tmp_path / "never_executed"
    shutil.copytree(FIXTURES / "never_executed", dst)

    scan_skill(dst)

    assert _sentinels(dst) == [], "scan_skill executed bundled skill code"


def test_cli_scan_skill_never_executes_bundled_code(tmp_path):
    # The entry point users actually invoke — human and --json paths.
    dst = tmp_path / "never_executed"
    shutil.copytree(FIXTURES / "never_executed", dst)

    runner = CliRunner()
    runner.invoke(main, ["scan-skill", str(dst)])
    runner.invoke(main, ["scan-skill", str(dst), "--json"])

    assert _sentinels(dst) == [], "the scan-skill CLI executed bundled skill code"


def test_individual_layers_never_execute_bundled_code(tmp_path):
    dst = tmp_path / "never_executed"
    shutil.copytree(FIXTURES / "never_executed", dst)

    manifest = load_skill_manifest(dst)
    scan_manifest(manifest)
    scan_instructions(manifest)
    scan_code(manifest)  # uses ast.parse, which must not execute the module

    assert _sentinels(dst) == [], "a scan layer executed bundled skill code"
