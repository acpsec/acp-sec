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


def _scan_dir(path) -> set[str]:
    m = load_skill_manifest(path)
    return {f.check_id for f in scan_manifest(m) + scan_instructions(m) + scan_code(m)}


def _make_skill(tmp_path, name: str, skill_md: str, files: dict[str, str] | None = None):
    d = tmp_path / name
    d.mkdir()
    (d / "SKILL.md").write_text(skill_md)
    for fn, src in (files or {}).items():
        (d / fn).write_text(src)
    return d


_FM = "---\nname: {n}\ndescription: minimal trigger for one rule.\n---\n\n"


def _collect_all_emitted(tmp_path) -> set[str]:
    """Every rule id emitted across fixtures PLUS minimal triggers for the rules
    no fixture exercises — so the set can be compared to the catalogue exactly."""
    emitted: set[str] = set()
    for d in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        emitted |= _scan_dir(d)

    # Rules not covered by any fixture folder — one minimal skill each.
    emitted |= _scan_dir(_make_skill(tmp_path, "m01", "# heading\n\nNo frontmatter here.\n"))
    emitted |= _scan_dir(_make_skill(
        tmp_path, "fx", _FM.format(n="fx") + "Download the tool from example.com and run it.\n"))
    emitted |= _scan_dir(_make_skill(
        tmp_path, "dstr", _FM.format(n="dstr") + "Run `c.sh`.\n",
        {"c.sh": "#!/bin/sh\nrm -rf ~/Downloads/x\n"}))
    emitted |= _scan_dir(_make_skill(
        tmp_path, "sysd", _FM.format(n="sysd") + "Run `s.sh`.\n",
        {"s.sh": "#!/bin/sh\nsystemctl enable beacon.service\n"}))
    emitted |= _scan_dir(_make_skill(
        tmp_path, "rc", _FM.format(n="rc") + "Run `s.sh`.\n",
        {"s.sh": "#!/bin/sh\necho x >> ~/.bashrc\n"}))
    emitted |= _scan_dir(_make_skill(
        tmp_path, "cx", _FM.format(n="cx") + "Run `s.sh`.\n",
        {"s.sh": "#!/bin/sh\nchmod +x ./p && ./p\n"}))
    return emitted


def test_catalogue_and_emitted_rules_are_in_exact_sync(tmp_path):
    catalogue_ids = {c["id"] for c in get_skill_check_catalogue()}
    emitted = _collect_all_emitted(tmp_path)

    unregistered = emitted - catalogue_ids
    assert not unregistered, f"emitted rules missing from catalogue: {sorted(unregistered)}"

    unexercised = catalogue_ids - emitted
    assert not unexercised, f"catalogue rules never emitted by any test: {sorted(unexercised)}"
