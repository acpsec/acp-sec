"""Load and validate agent configuration from YAML."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from .models import (
    AgentConfig,
    CommerceConfig,
    IdentityConfig,
    MCPAccessConfig,
    MCPAuditConfig,
    MCPAuthConfig,
    MCPConfig,
    PluginConfig,
    SkillFile,
    SkillManifest,
    X402AssetConfig,
    X402Config,
    X402FinalityConfig,
)

# Extensions that make a bundled file "code" for scan-skill purposes.
_CODE_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs", ".cjs",
}


_ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")


def _expand_env_vars(value: str) -> str:
    """Expand ${VAR_NAME} references to environment variables."""
    def replacer(match: re.Match) -> str:
        var = match.group(1)
        resolved = os.environ.get(var)
        if resolved is None:
            raise ValueError(f"Environment variable '{var}' is not set.")
        return resolved

    return _ENV_VAR_RE.sub(replacer, value)


def _expand_recursive(obj: object) -> object:
    if isinstance(obj, str):
        return _expand_env_vars(obj)
    if isinstance(obj, dict):
        return {k: _expand_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_recursive(item) for item in obj]
    return obj


def load_config(path: str | Path) -> AgentConfig:
    """Load an agent YAML config and return an AgentConfig."""
    raw = Path(path).read_text()
    data: dict = yaml.safe_load(raw)
    data = _expand_recursive(data)

    # Flatten nested sections into AgentConfig fields
    provider = data.pop("provider", {})
    security = data.pop("security", {})
    metadata = data.pop("metadata", {})
    x402_raw     = data.pop("x402",     {}) or {}
    mcp_raw      = data.pop("mcp",      {}) or {}
    plugin_raw   = data.pop("plugin",   {}) or {}
    identity_raw = data.pop("identity", {}) or {}
    commerce_raw = data.pop("commerce", {}) or {}

    flat = {
        "name": data.get("name", "unknown"),
        "version": data.get("version", "1.0"),
        "provider_type": provider.get("type", data.get("provider_type", "anthropic")),
        "model": provider.get("model", data.get("model", "claude-sonnet-4-6")),
        "api_key": provider.get("api_key", data.get("api_key")),
        "endpoint": provider.get("endpoint", data.get("endpoint")),
        "system_prompt": data.get("system_prompt", ""),
        "tools": data.get("tools", []),
        "auth_type": security.get("auth_type", data.get("auth_type", "bearer")),
        "session_isolation": security.get("session_isolation", data.get("session_isolation", True)),
        "output_filtering": security.get("output_filtering", data.get("output_filtering", False)),
        "hitl_tiers": security.get("hitl_tiers", data.get("hitl_tiers", [])),
        "environment": metadata.get("environment", data.get("environment", "staging")),
        "owner": metadata.get("owner", data.get("owner", "")),
        "x402":     _build_x402_config(x402_raw),
        "mcp":      _build_mcp_config(mcp_raw),
        "plugin":   _build_plugin_config(plugin_raw),
        "identity": _build_identity_config(identity_raw),
        "commerce": _build_commerce_config(commerce_raw),
    }

    return AgentConfig(**flat)


def _split_frontmatter(text: str) -> tuple[dict | None, str | None, str, int]:
    """Split a SKILL.md into (frontmatter dict, error, body, body_start_line).

    A missing or malformed frontmatter block is reported via the returned
    error string rather than raising — it is a *finding*, not a crash.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, "no frontmatter block", text, 1

    # Find the closing fence.
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            fm_text = "\n".join(lines[1:i])
            body = "\n".join(lines[i + 1:])
            body_start = i + 2  # 1-based line of first body line
            try:
                data = yaml.safe_load(fm_text)
                if not isinstance(data, dict):
                    return None, "frontmatter is not a mapping", body, body_start
                return data, None, body, body_start
            except yaml.YAMLError as e:
                return None, f"malformed frontmatter: {e}", body, body_start

    return None, "unterminated frontmatter block", text, 1


def load_skill_manifest(path: str | Path) -> SkillManifest:
    """Parse a skill folder (or its SKILL.md) into a :class:`SkillManifest`.

    ``path`` may be the skill directory (containing ``SKILL.md``) or the
    ``SKILL.md`` file itself.  Never executes anything in the folder.
    """
    p = Path(path)
    if p.is_dir():
        skill_root = p
        skill_md = p / "SKILL.md"
    else:
        skill_md = p
        skill_root = p.parent

    raw = skill_md.read_text(encoding="utf-8", errors="replace") if skill_md.exists() else ""
    fm, fm_error, body, body_start = _split_frontmatter(raw)

    name = ""
    description = ""
    if fm is not None:
        name = str(fm.get("name", "") or "")
        description = str(fm.get("description", "") or "")
    if not name:
        name = skill_root.name

    files = _inventory_files(skill_root, skill_md, body)

    return SkillManifest(
        name=name,
        description=description,
        body=body,
        path=str(skill_root),
        skill_md_path=str(skill_md),
        files=files,
        frontmatter_present=fm is not None,
        frontmatter_error=fm_error,
        body_start_line=body_start,
        raw=raw,
    )


def _inventory_files(skill_root: Path, skill_md: Path, body: str) -> list[SkillFile]:
    """List every file under the skill root except SKILL.md itself."""
    files: list[SkillFile] = []
    for entry in sorted(skill_root.rglob("*")):
        if not entry.is_file() or entry == skill_md:
            continue
        rel = entry.relative_to(skill_root).as_posix()
        is_code = entry.suffix.lower() in _CODE_EXTENSIONS or _is_executable(entry)
        referenced = entry.name in body or rel in body
        try:
            size = entry.stat().st_size
        except OSError:
            size = 0
        files.append(
            SkillFile(name=rel, is_code=is_code, referenced=referenced, size=size)
        )
    return files


def _is_executable(entry: Path) -> bool:
    try:
        return bool(entry.stat().st_mode & 0o111)
    except OSError:
        return False


def _build_x402_config(raw: dict) -> X402Config:
    """Build an X402Config from the YAML `x402:` block (or defaults if empty)."""
    finality_raw = raw.get("finality", {}) or {}
    asset_raw = raw.get("asset", {}) or {}
    return X402Config(
        enabled=bool(raw.get("enabled", False)),
        scheme=raw.get("scheme", "exact"),
        networks=list(raw.get("networks", []) or []),
        facilitator_url=raw.get("facilitator_url", ""),
        per_request_max_usd=float(raw.get("per_request_max_usd", 0.0)),
        daily_cap_usd=float(raw.get("daily_cap_usd", 0.0)),
        nonce_strategy=raw.get("nonce_strategy", "facilitator"),
        finality=X402FinalityConfig(
            network=finality_raw.get("network", "base"),
            confirmation_blocks=int(finality_raw.get("confirmation_blocks", 12)),
            azul_aware=bool(finality_raw.get("azul_aware", False)),
            pre_azul=bool(finality_raw.get("pre_azul", False)),
        ),
        asset=X402AssetConfig(
            address=asset_raw.get("address", ""),
            symbol=asset_raw.get("symbol", "USDC"),
        ),
    )


def _build_mcp_config(raw: dict) -> MCPConfig:
    """Build an MCPConfig from the YAML `mcp:` block (or defaults if empty)."""
    auth_raw = raw.get("auth", {}) or {}
    access_raw = raw.get("access", {}) or {}
    audit_raw = raw.get("audit", {}) or {}
    return MCPConfig(
        enabled=bool(raw.get("enabled", False)),
        server_url=raw.get("server_url", ""),
        auth=MCPAuthConfig(
            required=bool(auth_raw.get("required", True)),
            mechanism=auth_raw.get("mechanism", "bearer"),
            tool_scoping=bool(auth_raw.get("tool_scoping", False)),
            oauth_version=str(auth_raw.get("oauth_version", "")),
            pkce=bool(auth_raw.get("pkce", False)),
            token_rotation=bool(auth_raw.get("token_rotation", False)),
        ),
        access=MCPAccessConfig(
            resource_isolation=bool(access_raw.get("resource_isolation", False)),
            sandbox_mode=bool(access_raw.get("sandbox_mode", False)),
        ),
        audit=MCPAuditConfig(
            enabled=bool(audit_raw.get("enabled", False)),
            log_tool_calls=bool(audit_raw.get("log_tool_calls", False)),
            log_results=bool(audit_raw.get("log_results", False)),
        ),
        prompt_injection_protection=bool(raw.get("prompt_injection_protection", False)),
    )


def _build_plugin_config(raw: dict) -> PluginConfig:
    """Build a PluginConfig from the YAML `plugin:` block (or defaults)."""
    return PluginConfig(
        enabled=bool(raw.get("enabled", False)),
        sandboxed=bool(raw.get("sandboxed", False)),
        permission_scoping=bool(raw.get("permission_scoping", False)),
        input_validation=bool(raw.get("input_validation", False)),
    )


def _build_identity_config(raw: dict) -> IdentityConfig:
    """Build an IdentityConfig from the YAML `identity:` block (or defaults).

    Recognises the v0.4.0 Virtuals-ACP / ERC-8183 identity surface.
    """
    return IdentityConfig(
        enabled=bool(raw.get("enabled", False)),
        non_custodial=bool(raw.get("non_custodial", False)),
        custodial_wallet=bool(raw.get("custodial_wallet", False)),
        wallet_provider=str(raw.get("wallet_provider", "")),
        communication_email=str(raw.get("communication_email", "")),
        communication_channels=list(raw.get("communication_channels", []) or []),
        payment_wallet_address=str(raw.get("payment_wallet_address", "")),
        payment_card_x402=bool(raw.get("payment_card_x402", False)),
        erc_8183=bool(raw.get("erc_8183", False)),
        supported_chains=list(raw.get("supported_chains", []) or []),
    )


def _build_commerce_config(raw: dict) -> CommerceConfig:
    """Build a CommerceConfig from the YAML `commerce:` block (or defaults).

    Recognises the v0.4.0 Virtuals-ACP commerce surface (escrow, evaluator,
    job types, fund-transfer protections, lifecycle docs).
    """
    return CommerceConfig(
        enabled=bool(raw.get("enabled", False)),
        escrow=bool(raw.get("escrow", False)),
        escrow_provider=str(raw.get("escrow_provider", "")),
        evaluator=bool(raw.get("evaluator", False)),
        evaluator_url=str(raw.get("evaluator_url", "")),
        job_types=list(raw.get("job_types", []) or []),
        fund_transfer=bool(raw.get("fund_transfer", False)),
        fund_transfer_protections=list(raw.get("fund_transfer_protections", []) or []),
        lifecycle_documented=bool(raw.get("lifecycle_documented", False)),
    )
