"""End-to-end CLI tests for `acpsec scan-skill` over every fixture (Phase 6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from acpsec.cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "skills"

# (fixture, allowed verdicts, a finding id that must appear)
CASES = [
    ("benign_basic", {"PASS"}, None),
    ("benign_network", {"PASS", "WARN"}, "SKILL-CODE-NET"),
    ("benign_security_doc", {"PASS"}, None),
    ("inj_exfil", {"FAIL"}, "SKILL-INSTR-EXFIL"),
    ("inj_hidden", {"FAIL"}, "SKILL-INSTR-HIDDEN"),
    ("inj_override", {"FAIL"}, "SKILL-INSTR-OVERRIDE"),
    ("code_obfuscated", {"FAIL"}, "SKILL-CODE-OBFUS"),
    ("code_netexfil", {"FAIL"}, "SKILL-CODE-NET"),
    ("code_sensitive_path", {"WARN", "FAIL"}, "SKILL-CODE-SENSPATH"),
    ("hook_autorun", {"FAIL"}, "SKILL-AUTORUN"),
]

EXIT_FOR_VERDICT = {"PASS": 0, "WARN": 1, "FAIL": 2}


@pytest.mark.parametrize("fixture,allowed,required_id", CASES)
def test_scan_skill_verdict_and_findings(fixture, allowed, required_id):
    runner = CliRunner()
    result = runner.invoke(main, ["scan-skill", str(FIXTURES / fixture), "--json"])

    assert result.exit_code in {EXIT_FOR_VERDICT[v] for v in allowed}, result.output

    payload = json.loads(result.stdout)
    assert payload["verdict"] in allowed

    # Exit code must match the reported verdict exactly.
    assert result.exit_code == EXIT_FOR_VERDICT[payload["verdict"]]

    all_ids = [
        f["check_id"]
        for layer in payload["findings"].values()
        for f in layer
    ]
    if required_id is not None:
        assert any(cid.startswith(required_id) for cid in all_ids), all_ids


def test_pass_fixture_has_zero_exit():
    runner = CliRunner()
    result = runner.invoke(main, ["scan-skill", str(FIXTURES / "benign_basic")])
    assert result.exit_code == 0
