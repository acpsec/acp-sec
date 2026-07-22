"""Manifest-layer tests for scan-skill (Phase 2)."""

from __future__ import annotations

from pathlib import Path

from acpsec.config_loader import load_skill_manifest
from acpsec.models import CheckStatus, SkillManifest
from acpsec.skill_manifest import scan_manifest

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def _finding_ids(findings) -> set[str]:
    return {f.check_id for f in findings}


def test_load_parses_frontmatter_and_body():
    manifest = load_skill_manifest(FIXTURES / "benign_basic")
    assert isinstance(manifest, SkillManifest)
    assert manifest.name == "word-count"
    assert "Count words" in manifest.description or "count" in manifest.description.lower()
    assert "Word Count" in manifest.body
    assert manifest.frontmatter_present is True
    assert manifest.frontmatter_error is None


def test_benign_basic_has_no_code_files():
    manifest = load_skill_manifest(FIXTURES / "benign_basic")
    assert [f for f in manifest.files if f.is_code] == []


def test_files_inventory_marks_code_and_reference_state():
    manifest = load_skill_manifest(FIXTURES / "code_obfuscated")
    by_name = {f.name: f for f in manifest.files}
    assert by_name["run.py"].is_code is True
    assert by_name["run.py"].referenced is True
    # run.sh is a code file that the SKILL.md body never mentions.
    assert by_name["run.sh"].is_code is True
    assert by_name["run.sh"].referenced is False


def test_unreferenced_executable_is_a_finding():
    manifest = load_skill_manifest(FIXTURES / "code_obfuscated")
    findings = scan_manifest(manifest)
    assert "SKILL-MANIFEST-02" in _finding_ids(findings)
    fin = next(f for f in findings if f.check_id == "SKILL-MANIFEST-02")
    assert any("run.sh" in e for e in fin.evidence)


def test_missing_frontmatter_is_a_finding_not_a_crash(tmp_path: Path):
    skill = tmp_path / "no_fm"
    skill.mkdir()
    (skill / "SKILL.md").write_text("# Just a heading\n\nNo frontmatter at all.\n")
    manifest = load_skill_manifest(skill)
    assert manifest.frontmatter_present is False
    findings = scan_manifest(manifest)
    assert "SKILL-MANIFEST-01" in _finding_ids(findings)
    fin = next(f for f in findings if f.check_id == "SKILL-MANIFEST-01")
    assert fin.status == CheckStatus.FAIL or fin.status == CheckStatus.WARN


def test_benign_basic_manifest_is_clean():
    manifest = load_skill_manifest(FIXTURES / "benign_basic")
    assert scan_manifest(manifest) == []
