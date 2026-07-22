"""Instruction-layer static detection for scan-skill (Phase 3).

Scans the SKILL.md description + body for malicious *authoring* — the inverse
of ``injection/runner.py`` (which sends live payloads to an agent).  Categories
A–F from ``payloads.py`` seed the override/extraction rules; secrecy, scope
escalation, exfiltration and hidden-content rules are written directly from the
threat model.

Quote/fence awareness: fenced code blocks, blockquote lines, and
documentation-framed double-quoted spans are treated as *examples*, not
directives, and are neutralised before detection.  Inline `code` spans are kept
— legitimate directives routinely wrap paths in backticks.

Findings:
  SKILL-INSTR-OVERRIDE   authority-override / fake-system phrasing
  SKILL-INSTR-SECRECY    hide actions or content from the user
  SKILL-INSTR-EXFIL      read secrets/credentials and include them in output
  SKILL-INSTR-SCOPE      access files/paths beyond the skill's stated purpose
  SKILL-INSTR-FETCHEXEC  download remote content and execute it
  SKILL-INSTR-HIDDEN     hidden/encoded content (HTML comment, zero-width, base64)
"""

from __future__ import annotations

import re

from ..models import CheckResult, Severity, SkillManifest
from ..skill_findings import make_finding

LAYER = "instruction"

_ZERO_WIDTH = "​‌‍⁠﻿"
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH}]")
_HTML_COMMENT_RE = re.compile(r"<!--")
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_DQUOTE_RE = re.compile(r'"[^"]*"')

_DOC_CUES = (
    "example", "such as", "like ", "e.g", "might say", "might append",
    "might write", "for instance", "quoted", "payload", "phrase", "attacker",
)

_OVERRIDE_PATTERNS = [
    re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|earlier|above|preceding)\s+(instruction|prompt|direction)", re.I),
    re.compile(r"disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|earlier|above)", re.I),
    re.compile(r"new\s+system\s+(prompt|directive|instruction)", re.I),
    re.compile(r"overrides?\s+your\s+(existing\s+)?(guideline|instruction|rule)", re.I),
    re.compile(r"you\s+(are\s+now|now\s+operate)\b", re.I),
    re.compile(r"\bwithout\s+restrictions?\b", re.I),
    re.compile(r"system\s+override", re.I),
]

_SECRECY_PATTERNS = [
    re.compile(r"do\s+not\s+(tell|mention|inform|reveal|disclose|notify)", re.I),
    re.compile(r"don'?t\s+(tell|mention|let\s+the\s+user)", re.I),
    re.compile(r"keep\s+(this|it|these|that)\b.{0,40}\b(secret|hidden|confidential)", re.I),
    re.compile(r"without\s+(telling|informing|notifying)\s+the\s+user", re.I),
    re.compile(r"\bsilently\b", re.I),
    re.compile(r"hide\s+(this|these|it|the\s+fact)", re.I),
]

_FETCHEXEC_PATTERNS = [
    re.compile(r"(download|fetch|curl|wget)\b.{0,60}\b(run|execute|exec|eval)\b", re.I),
    re.compile(r"curl[^\n]*\|\s*(sh|bash|zsh)", re.I),
    re.compile(r"pipe\b.{0,20}\bto\s+(sh|bash)", re.I),
]

_SENSITIVE_TOKEN_RE = re.compile(
    r"(\.env\b|~/\.ssh|id_rsa|~/\.aws|\.aws/credentials|~/\.config/gcloud|"
    r"keychain|private\s+key|api[_\s-]?key|password|\bcredentials\b|\bsecret)",
    re.I,
)

_EXFIL_OUTPUT_RE = re.compile(
    r"(include\b.{0,40}\b(content|contents)|in\s+your\s+(response|answer|output|reply)|"
    r"append\b.{0,40}\b(response|answer|output|reply)|verbatim|"
    r"paste\b.{0,40}\b(response|output)|output\s+.{0,20}(content|file))",
    re.I,
)

_ACCESS_VERB_RE = re.compile(r"\b(read|open|access|cat|load|dump|exfiltrate)\b", re.I)


def scan_instructions(manifest: SkillManifest) -> list[CheckResult]:
    findings: list[CheckResult] = []

    scannable = _scannable_units(manifest)

    exfil_hit = False
    for line_no, text in scannable:
        for pat in _OVERRIDE_PATTERNS:
            if pat.search(text):
                findings.append(_f("SKILL-INSTR-OVERRIDE", "Authority-override phrasing",
                                   Severity.HIGH, line_no, text,
                                   "Skills must not instruct the agent to ignore or override its guidelines."))
                break
        for pat in _SECRECY_PATTERNS:
            if pat.search(text):
                findings.append(_f("SKILL-INSTR-SECRECY", "Secrecy directive",
                                   Severity.HIGH, line_no, text,
                                   "Skills must not instruct the agent to hide actions from the user."))
                break
        for pat in _FETCHEXEC_PATTERNS:
            if pat.search(text):
                findings.append(_f("SKILL-INSTR-FETCHEXEC", "Remote fetch-and-execute directive",
                                   Severity.HIGH, line_no, text,
                                   "Do not download and execute remote code from a skill instruction."))
                break

    # Exfiltration: a sensitive token anywhere + an output-inclusion directive.
    has_sensitive = any(_SENSITIVE_TOKEN_RE.search(t) for _, t in scannable)
    if has_sensitive:
        for line_no, text in scannable:
            if _EXFIL_OUTPUT_RE.search(text):
                findings.append(_f("SKILL-INSTR-EXFIL", "Credential-exfiltration directive",
                                   Severity.CRITICAL, line_no, text,
                                   "Skills must never read secrets and place them in agent output."))
                exfil_hit = True

    # Scope escalation: instructed access to sensitive paths without an exfil sink.
    if has_sensitive and not exfil_hit:
        for line_no, text in scannable:
            if _SENSITIVE_TOKEN_RE.search(text) and _ACCESS_VERB_RE.search(text):
                findings.append(_f("SKILL-INSTR-SCOPE", "Scope-escalation directive",
                                   Severity.HIGH, line_no, text,
                                   "Skill accesses paths beyond its stated purpose."))
                break

    # Hidden / encoded content — scanned on the RAW body (the hiding is the point).
    findings.extend(_scan_hidden(manifest))

    return findings


def _f(check_id, name, severity, line_no, text, rec) -> CheckResult:
    excerpt = text.strip()[:120]
    return make_finding(check_id, name, LAYER, severity, "SKILL.md", line_no, excerpt, rec)


def _scannable_units(manifest: SkillManifest) -> list[tuple[int, str]]:
    """Description + de-quoted body lines with absolute SKILL.md line numbers."""
    units: list[tuple[int, str]] = []

    if manifest.description:
        units.append((_description_line(manifest), manifest.description))

    in_fence = False
    for idx, raw in enumerate(manifest.body.splitlines()):
        abs_no = manifest.body_start_line + idx
        stripped = raw.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence or stripped.startswith(">"):
            continue
        text = raw
        # Neutralise documentation-framed double-quoted example spans.
        if any(cue in raw.lower() for cue in _DOC_CUES):
            text = _DQUOTE_RE.sub(" ", text)
        units.append((abs_no, text))

    return units


def _description_line(manifest: SkillManifest) -> int:
    for idx, raw in enumerate(manifest.raw.splitlines(), start=1):
        if raw.lstrip().startswith("description:"):
            return idx
    return 1


def _scan_hidden(manifest: SkillManifest) -> list[CheckResult]:
    findings: list[CheckResult] = []
    seen: set[tuple[str, int]] = set()

    def add(line_no: int, excerpt: str, why: str) -> None:
        key = ("SKILL-INSTR-HIDDEN", line_no)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            make_finding("SKILL-INSTR-HIDDEN", f"Hidden content ({why})", LAYER,
                         Severity.HIGH, "SKILL.md", line_no, excerpt,
                         "Remove hidden/encoded content — SKILL.md must be fully human-readable.")
        )

    for idx, raw in enumerate(manifest.body.splitlines()):
        abs_no = manifest.body_start_line + idx
        if _HTML_COMMENT_RE.search(raw):
            add(abs_no, raw.strip()[:120], "HTML comment")
        if _ZERO_WIDTH_RE.search(raw):
            add(abs_no, "zero-width characters embedded in text", "zero-width chars")
        if _BASE64_BLOB_RE.search(raw):
            add(abs_no, raw.strip()[:120], "base64 blob")

    return findings
