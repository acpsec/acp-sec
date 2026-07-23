"""scan-skill rules must be registered in the catalogue and stay in sync."""

from __future__ import annotations

from pathlib import Path

from acpsec.catalogue import get_skill_check_catalogue
from acpsec.config_loader import load_skill_manifest
from acpsec.checks.skill_code import scan_code
from acpsec.injection.skill_patterns import scan_instructions
from acpsec.skill_manifest import scan_manifest

FIXTURES = Path(__file__).parent / "fixtures" / "skills"

_REQUIRED_KEYS = {"id", "name", "dimension", "dimension_name", "severity", "description"}
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_catalogue_entries_follow_the_metadata_convention():
    catalogue = get_skill_check_catalogue()
    assert catalogue, "skill catalogue is empty"
    ids = [c["id"] for c in catalogue]
    assert len(ids) == len(set(ids)), "duplicate rule ids in skill catalogue"
    for entry in catalogue:
        assert _REQUIRED_KEYS <= set(entry), entry
        assert entry["id"].startswith("SKILL-"), entry["id"]
        assert entry["severity"] in _VALID_SEVERITIES, entry
        assert entry["description"].strip()


def test_every_emitted_rule_is_registered():
    catalogue_ids = {c["id"] for c in get_skill_check_catalogue()}
    emitted: set[str] = set()
    for d in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        m = load_skill_manifest(d)
        for f in scan_manifest(m) + scan_instructions(m) + scan_code(m):
            emitted.add(f.check_id)
    assert emitted, "no findings emitted across fixtures"
    missing = emitted - catalogue_ids
    assert not missing, f"emitted rules missing from catalogue: {sorted(missing)}"
