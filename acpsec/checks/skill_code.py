"""Code-layer static analysis for scan-skill (Phase 4).

Scans bundled ``*.sh / *.py / *.js / *.ts`` files with line/regex heuristics
plus a light Python ``ast`` pass.  **Never executes anything.**

Findings:
  SKILL-CODE-OBFUS      eval/exec of decoded or assembled strings; opaque blobs
  SKILL-CODE-NET        network egress (severity depends on destination)
  SKILL-CODE-SENSPATH   reads a sensitive path (ssh/aws/gcloud/.env/keychain/…)
  SKILL-CODE-ENVEXFIL   environment dump + network sink in the same file
  SKILL-CODE-DESTRUCT   rm -rf outside the skill dir, dd, mkfs
  SKILL-AUTORUN-CRON    crontab persistence
  SKILL-AUTORUN-LAUNCHCTL  launchctl / LaunchAgents persistence
  SKILL-AUTORUN-SYSTEMD    systemd unit persistence
  SKILL-AUTORUN-RCFILE     shell rc-file modification
  SKILL-AUTORUN-CHMODEXEC  chmod +x followed by execution

Precision posture (baseline; final thresholds live in ``skill_scan``):
  declared network        → LOW      (domain documented in SKILL.md)
  undeclared network      → MEDIUM   (WARN)
  known exfil sink        → HIGH     (discord/telegram/pastebin-alikes)
  sensitive path (read)   → HIGH
  env dump + net sink     → CRITICAL
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..models import CheckResult, Severity, SkillManifest
from ..skill_findings import make_finding

LAYER = "code"

_CODE_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs", ".cjs"}

_URL_RE = re.compile(r"https?://([^/\s\"')]+)", re.I)

_EXFIL_SINKS = (
    "discord.com/api/webhooks", "discordapp.com", "canary.discord.com",
    "api.telegram.org", "t.me/", "pastebin.com", "hastebin.com", "ghostbin",
    "webhook.site", "requestbin", "pipedream", "ngrok.io", "transfer.sh",
    "0x0.st", "termbin.com", "paste.ee",
)

_NET_PATTERNS = [
    re.compile(r"\brequests\.(get|post|put|patch|delete)\b", re.I),
    re.compile(r"\burllib\.request\.(urlopen|Request)\b", re.I),
    re.compile(r"\bhttpx\.(get|post|Client|stream)\b", re.I),
    re.compile(r"\bhttp\.client\.", re.I),
    re.compile(r"\bsocket\.socket\b", re.I),
    re.compile(r"\bwebsocket", re.I),
    re.compile(r"\bfetch\s*\(", re.I),
    re.compile(r"\baxios\b", re.I),
    re.compile(r"XMLHttpRequest", re.I),
    re.compile(r"\bcurl\b", re.I),
    re.compile(r"\bwget\b", re.I),
]

_SENSITIVE_PATH_RE = re.compile(
    r"(~/\.ssh|\.ssh/|id_rsa|id_ed25519|~/\.aws|\.aws/credentials|"
    r"~/\.config/gcloud|gcloud/credentials|\.env\b|keychain|"
    r"security\s+find-(generic|internet)-password|"
    r"Library/Application Support/Google/Chrome|\.mozilla/firefox|"
    r"\.ethereum/keystore|wallet\.dat|MetaMask|Keychains)",
    re.I,
)

_ENV_DUMP_RE = re.compile(r"(dict\s*\(\s*os\.environ|os\.environ\.copy|printenv|\benv\b\s*$|\$\(env\))", re.I)
_ENV_REF_RE = re.compile(r"os\.environ\b|process\.env\b|\benviron\b", re.I)

_OBFUS_EVAL_RE = re.compile(r"\b(eval|exec)\s*\(", re.I)
_OBFUS_DECODE_RE = re.compile(
    r"(b64decode|base64\.b64decode|base64\s+-d|base64\s+--decode|"
    r"bytes\.fromhex|fromhex|atob\s*\(|codecs\.decode|\.decode\(\s*['\"]?(base64|hex))",
    re.I,
)
_CHARCODE_RE = re.compile(r"(\"\"\.join\s*\(\s*chr|String\.fromCharCode|\bchr\s*\(\s*\d)", re.I)
_BLOB_RE = re.compile(r"['\"][A-Za-z0-9+/]{60,}={0,2}['\"]")

_AUTORUN_PATTERNS = {
    "SKILL-AUTORUN-CRON": re.compile(r"\bcrontab\b", re.I),
    "SKILL-AUTORUN-LAUNCHCTL": re.compile(r"(launchctl\b|LaunchAgents|LaunchDaemons)", re.I),
    "SKILL-AUTORUN-SYSTEMD": re.compile(r"(systemctl\s+(enable|start)|/etc/systemd/|\.service\b)", re.I),
    "SKILL-AUTORUN-RCFILE": re.compile(r">>\s*~?/?\.?(bashrc|zshrc|bash_profile|profile|zprofile)", re.I),
    "SKILL-AUTORUN-CHMODEXEC": re.compile(r"chmod\s+\+x", re.I),
}

_DESTRUCT_PATTERNS = [
    re.compile(r"rm\s+-[rf]{1,2}\s+(/|~|\$HOME|\*)", re.I),
    re.compile(r"\bdd\s+if=", re.I),
    re.compile(r"\bmkfs\b", re.I),
]


def scan_code(manifest: SkillManifest) -> list[CheckResult]:
    findings: list[CheckResult] = []
    declared = _declared_domains(manifest.raw)
    root = Path(manifest.path)

    for f in manifest.files:
        if not f.is_code:
            continue
        suffix = Path(f.name).suffix.lower()
        if suffix not in _CODE_SUFFIXES:
            continue
        try:
            source = (root / f.name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_scan_file(f.name, source, suffix, declared))

    return findings


def _scan_file(name: str, source: str, suffix: str, declared: set[str]) -> list[CheckResult]:
    findings: list[CheckResult] = []
    lines = source.splitlines()

    net_lines: list[int] = []
    file_domains: set[str] = set()
    has_env_dump = False
    obfus_lines: set[int] = set()
    sens_line: int | None = None

    for i, line in enumerate(lines, start=1):
        for dom in _URL_RE.findall(line):
            file_domains.add(dom.lower())

        if any(p.search(line) for p in _NET_PATTERNS):
            net_lines.append(i)

        if _ENV_DUMP_RE.search(line):
            has_env_dump = True

        if _SENSITIVE_PATH_RE.search(line) and sens_line is None:
            sens_line = i

        if _OBFUS_EVAL_RE.search(line) and (_OBFUS_DECODE_RE.search(line) or _CHARCODE_RE.search(line)):
            obfus_lines.add(i)
        elif _CHARCODE_RE.search(line):
            obfus_lines.add(i)
        elif _BLOB_RE.search(line):
            obfus_lines.add(i)
        elif suffix in {".sh", ".bash", ".zsh"} and _OBFUS_EVAL_RE.search(line) and _OBFUS_DECODE_RE.search(line):
            obfus_lines.add(i)

        for check_id, pat in _AUTORUN_PATTERNS.items():
            if pat.search(line):
                findings.append(make_finding(check_id, "Automatic persistence / autorun", LAYER,
                                             Severity.HIGH, name, i, line.strip()[:120],
                                             "Skills must not install background persistence."))
        for pat in _DESTRUCT_PATTERNS:
            if pat.search(line):
                findings.append(make_finding("SKILL-CODE-DESTRUCT", "Destructive command", LAYER,
                                             Severity.HIGH, name, i, line.strip()[:120],
                                             "Skill runs a destructive command outside its own directory."))
                break

    # Python ast pass — flags eval/exec whose argument is not a plain string.
    if suffix in {".py"}:
        obfus_lines |= _ast_obfus_lines(source)

    for ln in sorted(obfus_lines):
        excerpt = lines[ln - 1].strip()[:120] if ln - 1 < len(lines) else ""
        findings.append(make_finding("SKILL-CODE-OBFUS", "Obfuscated / packed code", LAYER,
                                     Severity.HIGH, name, ln, excerpt,
                                     "Remove eval/exec of decoded or assembled strings."))

    # Network egress — classify by the most severe destination in the file.
    if net_lines:
        severity, note = _classify_network(source, file_domains, declared)
        ln = net_lines[0]
        excerpt = lines[ln - 1].strip()[:120] if ln - 1 < len(lines) else ""
        findings.append(make_finding("SKILL-CODE-NET", f"Network egress ({note})", LAYER,
                                     severity, name, ln, excerpt,
                                     "Document every network destination in SKILL.md; never send secrets."))
        is_sink = severity in (Severity.HIGH, Severity.CRITICAL)
        if has_env_dump and is_sink:
            findings.append(make_finding("SKILL-CODE-ENVEXFIL", "Environment dump sent to network", LAYER,
                                         Severity.CRITICAL, name, ln, excerpt,
                                         "Never transmit the process environment off the machine."))

    if sens_line is not None:
        excerpt = lines[sens_line - 1].strip()[:120] if sens_line - 1 < len(lines) else ""
        findings.append(make_finding("SKILL-CODE-SENSPATH", "Reads a sensitive path", LAYER,
                                     Severity.HIGH, name, sens_line, excerpt,
                                     "Skill reads credentials/keys outside its own directory."))

    return findings


def _classify_network(source: str, domains: set[str], declared: set[str]) -> tuple[Severity, str]:
    low = source.lower()
    if any(sink in low for sink in _EXFIL_SINKS) or any(
        any(sink in d for sink in _EXFIL_SINKS) for d in domains
    ):
        return Severity.HIGH, "known exfil sink"
    if domains and domains <= declared:
        return Severity.LOW, "declared domain"
    if not domains:
        return Severity.MEDIUM, "destination not statically resolvable"
    return Severity.MEDIUM, "undeclared destination"


def _declared_domains(skill_md_text: str) -> set[str]:
    domains = {d.lower() for d in _URL_RE.findall(skill_md_text)}
    # Also treat bare "api.github.com"-style hostnames in prose as declared.
    for m in re.findall(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", skill_md_text, re.I):
        domains.add(m.lower())
    return domains


def _ast_obfus_lines(source: str) -> set[int]:
    lines: set[int] = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return lines
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            arg = node.args[0] if node.args else None
            if arg is not None and not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                lines.add(getattr(node, "lineno", 0))
    return lines
