"""Instruction-layer tests for scan-skill (Phase 3)."""

from __future__ import annotations

from pathlib import Path

from acpsec.config_loader import load_skill_manifest
from acpsec.injection.skill_patterns import scan_instructions

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def _scan(name: str):
    return scan_instructions(load_skill_manifest(FIXTURES / name))


def _ids(findings) -> set[str]:
    return {f.check_id for f in findings}


def test_exfiltration_directive_detected():
    findings = _scan("inj_exfil")
    assert "SKILL-INSTR-EXFIL" in _ids(findings)


def test_override_and_secrecy_directives_detected():
    ids = _ids(_scan("inj_override"))
    assert "SKILL-INSTR-OVERRIDE" in ids
    assert "SKILL-INSTR-SECRECY" in ids


def test_hidden_content_detected():
    # HTML comment + zero-width chars + base64 payload in the body.
    assert "SKILL-INSTR-HIDDEN" in _ids(_scan("inj_hidden"))


def test_every_finding_carries_file_and_line_evidence():
    for f in _scan("inj_exfil") + _scan("inj_override") + _scan("inj_hidden"):
        assert f.evidence, f"{f.check_id} has no evidence"
        assert any("SKILL.md:" in e for e in f.evidence), f.evidence


def test_benign_basic_has_no_instruction_findings():
    assert _scan("benign_basic") == []


def test_security_doc_is_quote_and_fence_aware():
    # Attack phrasings quoted inside fenced blocks / blockquotes / quotes are
    # documentation, not directives — they must NOT be flagged.
    assert _scan("benign_security_doc") == []
