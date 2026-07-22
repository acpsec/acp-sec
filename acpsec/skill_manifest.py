"""Manifest-layer checks for scan-skill (Phase 2).

Findings:
  SKILL-MANIFEST-01  missing / malformed SKILL.md frontmatter
  SKILL-MANIFEST-02  executable file present but never referenced in the body
"""

from __future__ import annotations

from .models import CheckResult, Severity, SkillManifest
from .skill_findings import make_finding

LAYER = "manifest"


def scan_manifest(manifest: SkillManifest) -> list[CheckResult]:
    findings: list[CheckResult] = []

    if not manifest.frontmatter_present:
        findings.append(
            make_finding(
                "SKILL-MANIFEST-01",
                "Missing or malformed frontmatter",
                LAYER,
                Severity.MEDIUM,
                "SKILL.md",
                1,
                manifest.frontmatter_error or "no valid YAML frontmatter block",
                recommendation="Add a valid `---` YAML frontmatter block with name + description.",
            )
        )

    for f in manifest.files:
        if f.is_code and not f.referenced:
            findings.append(
                make_finding(
                    "SKILL-MANIFEST-02",
                    "Executable file not referenced in SKILL.md",
                    LAYER,
                    Severity.MEDIUM,
                    f.name,
                    1,
                    "executable file present but never mentioned in the skill body",
                    recommendation="Remove unused scripts, or document why the file ships with the skill.",
                )
            )

    return findings
