"""Reporter + JSON schema tests for scan-skill (Phase 6)."""

from __future__ import annotations

import json
from pathlib import Path

from acpsec.models import SkillScanResult
from acpsec.reporter import print_skill_scan, save_json
from acpsec.skill_scan import scan_skill

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def test_scan_skill_returns_result_with_layered_findings():
    result = scan_skill(FIXTURES / "inj_exfil")
    assert isinstance(result, SkillScanResult)
    assert result.verdict == "FAIL"
    assert set(result.findings.keys()) == {"manifest", "instruction", "code"}


def test_json_schema_is_stable(tmp_path: Path):
    result = scan_skill(FIXTURES / "code_netexfil")
    out = tmp_path / "scan.json"
    save_json(result, out)
    data = json.loads(out.read_text())
    for key in ("skill_name", "skill_path", "verdict", "score", "max_score", "findings"):
        assert key in data
    assert set(data["findings"].keys()) == {"manifest", "instruction", "code"}
    # Every serialized finding keeps its id, severity and evidence.
    all_findings = [f for layer in data["findings"].values() for f in layer]
    assert all_findings
    for f in all_findings:
        assert f["check_id"]
        assert f["severity"]
        assert f["evidence"]


def test_human_report_prints_verdict_and_evidence(capsys):
    result = scan_skill(FIXTURES / "inj_exfil")
    print_skill_scan(result)
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "SKILL.md:" in out
