"""Code-layer static-analysis tests for scan-skill (Phase 4)."""

from __future__ import annotations

from pathlib import Path

from acpsec.checks.skill_code import scan_code
from acpsec.config_loader import load_skill_manifest
from acpsec.models import Severity

FIXTURES = Path(__file__).parent / "fixtures" / "skills"


def _scan(name: str):
    return scan_code(load_skill_manifest(FIXTURES / name))


def _ids(findings) -> set[str]:
    return {f.check_id for f in findings}


def test_obfuscation_detected():
    findings = _scan("code_obfuscated")
    assert "SKILL-CODE-OBFUS" in _ids(findings)
    fin = next(f for f in findings if f.check_id == "SKILL-CODE-OBFUS")
    assert any("run.py:" in e for e in fin.evidence)


def test_env_exfil_combo_detected():
    ids = _ids(_scan("code_netexfil"))
    assert "SKILL-CODE-NET" in ids
    assert "SKILL-CODE-ENVEXFIL" in ids


def test_exfil_sink_is_high_severity():
    findings = _scan("code_netexfil")
    net = next(f for f in findings if f.check_id == "SKILL-CODE-NET")
    assert net.severity in (Severity.HIGH, Severity.CRITICAL)


def test_sensitive_path_without_network_detected():
    findings = _scan("code_sensitive_path")
    assert "SKILL-CODE-SENSPATH" in _ids(findings)
    # No network sink in this fixture.
    assert "SKILL-CODE-NET" not in _ids(findings)


def test_autorun_hook_detected():
    ids = _ids(_scan("hook_autorun"))
    assert any(i.startswith("SKILL-AUTORUN") for i in ids), ids


def test_declared_network_is_low_severity():
    findings = _scan("benign_network")
    assert "SKILL-CODE-NET" in _ids(findings)
    net = next(f for f in findings if f.check_id == "SKILL-CODE-NET")
    # api.github.com is declared in SKILL.md → not an exfil sink.
    assert net.severity in (Severity.LOW, Severity.INFO)


def test_benign_basic_has_no_code_findings():
    assert _scan("benign_basic") == []
