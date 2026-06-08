"""ACP-SEC CLI — acpsec check / inject / report."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from .agent_client import AgentClient
from .checks import (
    run_auth_checks,
    run_commerce_checks,
    run_context_checks,
    run_governance_checks,
    run_identity_checks,
    run_input_validation_checks,
    run_mcp_checks,
    run_output_safety_checks,
    run_plugin_checks,
    run_privilege_checks,
    run_x402_checks,
)
from .config_loader import load_config
from .injection import InjectionRunner
from .injection.payloads import CATEGORIES
from .models import AgentConfig, DimensionResult
from .reporter import print_assessment, print_injection_report, save_json
from .scorer import ScoringEngine

console = Console()

DIMENSION_RUNNERS = {
    "auth": ("AUTH", "Authentication & Identity", run_auth_checks),
    "ctx": ("CTX", "Context Integrity", run_context_checks),
    "inj": ("INJ", "Input Validation & Injection Resistance", run_input_validation_checks),
    "priv": ("PRIV", "Privilege & Tool Authorization", run_privilege_checks),
    "out": ("OUT", "Output Safety & Leakage Prevention", run_output_safety_checks),
    "gov": ("GOV", "Governance, Audit & Observability", run_governance_checks),
}

OPTIONAL_DIMENSION_RUNNERS = {
    "x402":     ("X402",     "x402 Protocol Posture",         run_x402_checks),
    "mcp":      ("MCP",      "MCP Server Security",           run_mcp_checks),
    "plugin":   ("PLUGIN",   "Skill-Plugin Security",         run_plugin_checks),
    "identity": ("IDENTITY", "Agent Identity & Wallet Model", run_identity_checks),
    "commerce": ("COMMERCE", "Agent Commerce Protocol",       run_commerce_checks),
}

MAX_SCORES = {"AUTH": 15, "CTX": 20, "INJ": 20, "PRIV": 20, "OUT": 15, "GOV": 10}


@click.group()
@click.version_option("0.4.0", prog_name="acpsec")
def main() -> None:
    """ACP-SEC: AI Agent Security Assessment Framework."""


# ---------------------------------------------------------------------------
# acpsec check
# ---------------------------------------------------------------------------
@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to agent YAML config file.",
)
@click.option(
    "--dim", "-d",
    multiple=True,
    type=click.Choice(list(DIMENSION_RUNNERS.keys()) + ["all"]),
    default=["all"],
    show_default=True,
    help="Dimension(s) to check. Use 'all' for full assessment.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Save results to JSON file.",
)
@click.option(
    "--no-live",
    is_flag=True,
    default=False,
    help="Skip checks that require live API calls (static analysis only).",
)
@click.option(
    "--x402",
    "x402_only",
    is_flag=True,
    default=False,
    help="Run ONLY the X402 dimension. Requires x402.enabled in the YAML.",
)
@click.option(
    "--azul",
    "azul_only",
    is_flag=True,
    default=False,
    help="Run ONLY the X402-AZUL-01 multiproof-finality check.",
)
@click.option(
    "--skip-x402",
    is_flag=True,
    default=False,
    help="Force-skip the X402 dimension even if x402.enabled is true.",
)
@click.option(
    "--mcp",
    "mcp_only",
    is_flag=True,
    default=False,
    help="Run ONLY the MCP dimension. Requires mcp.enabled in the YAML.",
)
@click.option(
    "--skip-mcp",
    is_flag=True,
    default=False,
    help="Force-skip the MCP dimension even if mcp.enabled is true.",
)
@click.option(
    "--plugin",
    "plugin_only",
    is_flag=True,
    default=False,
    help="Run ONLY the PLUGIN dimension. Requires plugin.enabled in the YAML.",
)
@click.option(
    "--skip-plugin",
    is_flag=True,
    default=False,
    help="Force-skip the PLUGIN dimension even if plugin.enabled is true.",
)
@click.option(
    "--identity",
    "identity_only",
    is_flag=True,
    default=False,
    help="Run ONLY the IDENTITY dimension (v0.4.0). Requires identity.enabled.",
)
@click.option(
    "--skip-identity",
    is_flag=True,
    default=False,
    help="Force-skip the IDENTITY dimension even if identity.enabled is true.",
)
@click.option(
    "--commerce",
    "commerce_only",
    is_flag=True,
    default=False,
    help="Run ONLY the COMMERCE dimension (v0.4.0). Requires commerce.enabled.",
)
@click.option(
    "--skip-commerce",
    is_flag=True,
    default=False,
    help="Force-skip the COMMERCE dimension even if commerce.enabled is true.",
)
def check(
    config: Path,
    dim: tuple[str, ...],
    output: Path | None,
    no_live: bool,
    x402_only: bool,
    azul_only: bool,
    skip_x402: bool,
    mcp_only: bool,
    skip_mcp: bool,
    plugin_only: bool,
    skip_plugin: bool,
    identity_only: bool,
    skip_identity: bool,
    commerce_only: bool,
    skip_commerce: bool,
) -> None:
    """Run security checks against an AI agent."""
    try:
        cfg = load_config(config)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        sys.exit(1)

    console.print(f"\n[bold]ACP-SEC[/bold] checking [cyan]{cfg.name}[/cyan]...")

    client = AgentClient(cfg)

    if not no_live:
        console.print("[dim]Verifying agent connectivity...[/dim]")
        if not client.health_check():
            console.print("[yellow]Warning: Agent health check failed. Proceeding with static checks.[/yellow]")

    # --x402 / --azul / --mcp / --plugin / --identity / --commerce are
    # mutually exclusive "run ONLY this" shortcuts.
    only_flags = [
        x402_only, azul_only, mcp_only, plugin_only,
        identity_only, commerce_only,
    ]
    if sum(only_flags) > 1:
        console.print(
            "[red]--x402, --azul, --mcp, --plugin, --identity, --commerce "
            "are mutually exclusive.[/red]"
        )
        sys.exit(2)

    if any(only_flags):
        # Skip the standard 6 dimensions entirely.
        selected_dims: set[str] = set()
    else:
        selected_dims = set(DIMENSION_RUNNERS.keys()) if "all" in dim else set(dim)

    dimension_results: list[DimensionResult] = []

    for key, (dim_id, dim_name, runner_fn) in DIMENSION_RUNNERS.items():
        if key not in selected_dims:
            continue
        console.print(f"  [dim]Checking {dim_id}...[/dim]", end="\r")
        try:
            result = runner_fn(cfg, client)
        except Exception as e:
            console.print(f"  [red]Error in {dim_id}: {e}[/red]")
            continue
        dimension_results.append(result)

    # X402 dimension — opt-in, runs only when cfg.x402.enabled (unless --skip-x402).
    if not skip_x402 and (cfg.x402.enabled or x402_only or azul_only):
        if not cfg.x402.enabled:
            console.print(
                "[yellow]--x402/--azul requested but x402.enabled is false in "
                "the YAML. Set x402.enabled: true to run the dimension.[/yellow]"
            )
        else:
            console.print(f"  [dim]Checking X402...[/dim]", end="\r")
            try:
                x402_result = run_x402_checks(cfg, client)
                if azul_only:
                    # Filter down to just the AZUL check (max_score becomes 1).
                    azul = [c for c in x402_result.checks if c.check_id == "X402-AZUL-01"]
                    x402_result.checks = azul
                    x402_result.score = sum(c.score for c in azul)
                    x402_result.max_score = sum(c.max_score for c in azul)
                dimension_results.append(x402_result)
            except Exception as e:
                console.print(f"  [red]Error in X402: {e}[/red]")

    # MCP dimension — opt-in, runs only when cfg.mcp.enabled (unless --skip-mcp).
    if not skip_mcp and (cfg.mcp.enabled or mcp_only):
        if not cfg.mcp.enabled:
            console.print(
                "[yellow]--mcp requested but mcp.enabled is false in "
                "the YAML. Set mcp.enabled: true to run the dimension.[/yellow]"
            )
        else:
            console.print(f"  [dim]Checking MCP...[/dim]", end="\r")
            try:
                mcp_result = run_mcp_checks(cfg, client)
                dimension_results.append(mcp_result)
            except Exception as e:
                console.print(f"  [red]Error in MCP: {e}[/red]")

    # PLUGIN dimension — opt-in, runs only when cfg.plugin.enabled.
    if not skip_plugin and (cfg.plugin.enabled or plugin_only):
        if not cfg.plugin.enabled:
            console.print(
                "[yellow]--plugin requested but plugin.enabled is false in "
                "the YAML. Set plugin.enabled: true to run the dimension.[/yellow]"
            )
        else:
            console.print(f"  [dim]Checking PLUGIN...[/dim]", end="\r")
            try:
                plugin_result = run_plugin_checks(cfg, client)
                dimension_results.append(plugin_result)
            except Exception as e:
                console.print(f"  [red]Error in PLUGIN: {e}[/red]")

    # IDENTITY dimension (v0.4.0) — opt-in via cfg.identity.enabled.
    if not skip_identity and (cfg.identity.enabled or identity_only):
        if not cfg.identity.enabled:
            console.print(
                "[yellow]--identity requested but identity.enabled is false "
                "in the YAML.[/yellow]"
            )
        else:
            console.print(f"  [dim]Checking IDENTITY...[/dim]", end="\r")
            try:
                dimension_results.append(run_identity_checks(cfg, client))
            except Exception as e:
                console.print(f"  [red]Error in IDENTITY: {e}[/red]")

    # COMMERCE dimension (v0.4.0) — opt-in via cfg.commerce.enabled.
    if not skip_commerce and (cfg.commerce.enabled or commerce_only):
        if not cfg.commerce.enabled:
            console.print(
                "[yellow]--commerce requested but commerce.enabled is false "
                "in the YAML.[/yellow]"
            )
        else:
            console.print(f"  [dim]Checking COMMERCE...[/dim]", end="\r")
            try:
                dimension_results.append(run_commerce_checks(cfg, client))
            except Exception as e:
                console.print(f"  [red]Error in COMMERCE: {e}[/red]")

    engine = ScoringEngine()
    # Pass agent_config so v0.4.0 penalties (custodial -10, fund-transfer
    # cap @ 30) apply when relevant.  Older callers without agent_config
    # still get the v0.3.x scoring behaviour.
    assessment = engine.build_assessment(
        agent_name=cfg.name,
        agent_version=cfg.version,
        dimension_results=dimension_results,
        metadata={"config_path": str(config), "environment": cfg.environment},
        agent_config=cfg,
    )

    print_assessment(assessment)

    if output:
        save_json(assessment, output)


# ---------------------------------------------------------------------------
# acpsec inject
# ---------------------------------------------------------------------------
@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to agent YAML config file.",
)
@click.option(
    "--suite", "-s",
    type=click.Choice(["full"] + list(CATEGORIES.keys())),
    default="full",
    show_default=True,
    help="Injection test suite to run.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Save results to JSON file.",
)
@click.option(
    "--delay",
    type=float,
    default=0.5,
    show_default=True,
    help="Delay between payloads in seconds (rate limiting).",
)
def inject(config: Path, suite: str, output: Path | None, delay: float) -> None:
    """Run the injection test suite against an AI agent."""
    try:
        cfg = load_config(config)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        sys.exit(1)

    categories = None if suite == "full" else [suite]
    payload_count = sum(
        len(v) for k, v in __import__(
            "acpsec.injection.payloads", fromlist=["CATEGORIES"]
        ).CATEGORIES.items()
        if categories is None or k in categories
    )

    console.print(
        f"\n[bold]ACP-SEC Injection Suite[/bold] — "
        f"[cyan]{cfg.name}[/cyan]  ({payload_count} payloads, suite={suite})\n"
    )

    client = AgentClient(cfg)
    runner = InjectionRunner(cfg, client)

    with console.status("[dim]Running injection tests...[/dim]"):
        result = runner.run(categories=categories, delay_seconds=delay)

    print_injection_report(result)

    if output:
        save_json(result, output)


# ---------------------------------------------------------------------------
# acpsec report
# ---------------------------------------------------------------------------
@main.command()
@click.argument("results_json", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format", "-f",
    "fmt",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    show_default=True,
)
def report(results_json: Path, fmt: str) -> None:
    """Display a saved results JSON file."""
    import json

    data = json.loads(results_json.read_text())

    if fmt == "json":
        console.print_json(results_json.read_text())
        return

    # Detect type: assessment vs injection
    if "dimensions" in data:
        from .models import AssessmentResult
        result = AssessmentResult(**data)
        print_assessment(result)
    elif "results" in data and "resistance_score" in data:
        from .models import InjectionSuiteResult
        result = InjectionSuiteResult(**data)
        print_injection_report(result)
    else:
        console.print("[red]Unrecognized results format.[/red]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# acpsec monitor (subcommand group)
# ---------------------------------------------------------------------------
@main.group()
def monitor() -> None:
    """Continuous monitoring — watchlist, scheduled scans, drift alerts."""


@monitor.command("add")
@click.argument("url")
@click.option(
    "--schedule", "-s",
    type=click.Choice(["hourly", "daily", "weekly"]),
    default="daily",
    show_default=True,
    help="How often to scan this agent.",
)
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the monitor SQLite database.",
)
def monitor_add(url: str, schedule: str, db: Path | None) -> None:
    """Add an agent URL to the watchlist."""
    from .monitor import Monitor
    mon = Monitor(db)
    entry = mon.add_agent(url, schedule)
    mon.close()
    console.print(f"[green]Added[/green] {url} (schedule: {schedule})")


@monitor.command("list")
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the monitor SQLite database.",
)
def monitor_list(db: Path | None) -> None:
    """List all agents on the watchlist."""
    from .monitor import Monitor
    mon = Monitor(db)
    agents = mon.list_agents()
    mon.close()

    if not agents:
        console.print("[dim]Watchlist is empty. Use 'acpsec monitor add <url>' to add agents.[/dim]")
        return

    console.print(f"\n[bold]Watchlist[/bold] ({len(agents)} agents)\n")
    for agent in agents:
        score_str = f"{agent.last_score}" if agent.last_score is not None else "—"
        last_scan = "Never" if agent.last_scan is None else f"{agent.last_scan:.0f}"
        status = "[green]active[/green]" if agent.enabled else "[dim]disabled[/dim]"
        console.print(
            f"  {agent.url:<50} {agent.schedule:<10} score={score_str:<8} "
            f"last_scan={last_scan:<20} {status}"
        )
    console.print()


@monitor.command("run")
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the monitor SQLite database.",
)
@click.option(
    "--webhook",
    type=str,
    default=None,
    help="Webhook URL for drift notifications (Discord/Slack/Telegram).",
)
def monitor_run(db: Path | None, webhook: str | None) -> None:
    """Manually trigger scans for all due agents."""
    from .monitor import Monitor
    mon = Monitor(db)
    due = mon.get_due_agents()

    if not due:
        console.print("[dim]No agents due for scanning.[/dim]")
        mon.close()
        return

    console.print(f"\n[bold]Scanning {len(due)} agent(s)...[/bold]\n")
    engine = ScoringEngine()

    for entry in due:
        console.print(f"  Scanning {entry.url}...", end=" ")
        try:
            cfg = load_config(entry.url)
            client = AgentClient(cfg)
            dim_results: list[DimensionResult] = []

            # Run base dimensions
            dim_results.extend([
                run_auth_checks(cfg, client),
                run_context_checks(cfg, client),
                run_input_validation_checks(cfg, client),
                run_privilege_checks(cfg, client),
                run_output_safety_checks(cfg, client),
                run_governance_checks(cfg, client),
            ])

            # Optional dimensions
            if cfg.x402.enabled:
                dim_results.append(run_x402_checks(cfg, client))
            if cfg.mcp.enabled:
                dim_results.append(run_mcp_checks(cfg, client))

            assessment = engine.build_assessment(cfg.name, cfg.version, dim_results)
            old_entry = mon.get_agent(entry.url)
            old_score = old_entry.last_score if old_entry else None

            record = mon.record_score(
                entry.url, assessment.score, assessment.max_score, assessment.band
            )

            console.print(
                f"[green]{assessment.band}[/green] "
                f"score={assessment.score}/{assessment.max_score}"
            )

            # Check if drift alert was created
            if old_score is not None and old_score - assessment.score > 10:
                console.print(
                    f"    [red]DRIFT ALERT: score dropped from {old_score} to "
                    f"{assessment.score} (−{old_score - assessment.score:.1f} pts)[/red]"
                )
                if webhook:
                    Monitor.send_webhook(
                        webhook,
                        title=f"ACP-SEC Drift Alert: {cfg.name}",
                        description=f"Score dropped from {old_score} to {assessment.score}",
                        fields={
                            "Agent": entry.url,
                            "Old Score": str(old_score),
                            "New Score": str(assessment.score),
                            "Band": assessment.band,
                        },
                    )

        except Exception as e:
            console.print(f"[red]ERROR: {e}[/red]")

    mon.close()
    console.print(f"\n[bold]Done.[/bold]\n")


@monitor.command("history")
@click.argument("url")
@click.option(
    "--limit", "-n",
    type=int,
    default=10,
    show_default=True,
    help="Number of history entries to show.",
)
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the monitor SQLite database.",
)
def monitor_history(url: str, limit: int, db: Path | None) -> None:
    """Show score history for an agent."""
    from .monitor import Monitor
    mon = Monitor(db)
    history = mon.get_history(url, limit)
    trust = mon.get_trust_index(url)
    alerts = mon.get_alerts(url)
    mon.close()

    if not history:
        console.print(f"[dim]No score history for {url}[/dim]")
        return

    console.print(f"\n[bold]Score History[/bold] — {url}\n")
    if trust is not None:
        console.print(f"  Trust Index (5-window avg): [cyan]{trust}[/cyan]\n")

    for record in history:
        from datetime import datetime
        ts = datetime.fromtimestamp(record.timestamp).strftime("%Y-%m-%d %H:%M")
        color = "green" if record.score >= 70 else "yellow" if record.score >= 50 else "red"
        console.print(
            f"  [{color}]{record.score:>6.1f}[/{color}] / {record.max_score}  "
            f"({record.band:<12})  {ts}"
        )

    if alerts:
        console.print(f"\n  [red]Drift Alerts:[/red]")
        for alert in alerts:
            ts = datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M")
            console.print(
                f"    [red]−{alert.delta:.1f} pts[/red]  "
                f"{alert.old_score} → {alert.new_score}  ({ts})"
            )

    console.print()


# ---------------------------------------------------------------------------
# acpsec trust-score
# ---------------------------------------------------------------------------

# Slither check name → ContractSecurityInput field
_SLITHER_MAP: dict[str, str] = {
    "reentrancy-eth":        "has_reentrancy",
    "reentrancy-no-eth":     "has_reentrancy",
    "reentrancy-benign":     "has_reentrancy",
    "reentrancy-events":     "has_reentrancy",
    "controlled-delegatecall": "has_arbitrary_delegatecall",
    "delegatecall-loop":     "has_arbitrary_delegatecall",
    "suicidal":              "has_selfdestruct",
    "tx-origin":             "uses_tx_origin_auth",
    "unchecked-lowlevel":    "unchecked_low_level_calls",
    "unchecked-send":        "unchecked_low_level_calls",
    "pragma":                "floating_pragma",
    "unprotected-upgrade":   "upgradeable_proxy_eoa_admin",
    "protected-vars":        "missing_access_control",
    "arbitrary-send-eth":    "has_arbitrary_delegatecall",
}


@main.command("trust-score")
@click.option(
    "--agent", "-a",
    required=True,
    help="On-chain contract address to assess (0x…).",
)
@click.option(
    "--basescan-key",
    envvar="BASESCAN_API_KEY",
    default="",
    help="Basescan API key (or set BASESCAN_API_KEY env var).",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Save Trust Score result to JSON file.",
)
@click.option(
    "--no-slither",
    is_flag=True,
    default=False,
    help="Skip Slither static analysis (use Basescan data only).",
)
@click.option(
    "--chain",
    type=click.Choice(["base-mainnet", "base-sepolia"]),
    default="base-sepolia",
    show_default=True,
    help="Base network — selects the ACP Core / FundTransferHook reference "
         "addresses and RPC endpoint. Base only (no BSC).",
)
@click.option(
    "--scan-mode",
    type=click.Choice(["external", "self_audit"]),
    default="external",
    show_default=True,
    help="external: public/on-chain data only (private data left Unrated). "
         "self_audit: operator-run scan that may supply private data "
         "(Agent Card spend limits, off-chain signer policy).",
)
def trust_score(
    agent: str,
    basescan_key: str,
    output: Path | None,
    no_slither: bool,
    chain: str,
    scan_mode: str,
) -> None:
    """Compute a Trust Score (0-100, grade A-F) for an on-chain agent contract."""
    import json as _json
    import os

    from .trust_score.data.basescan import BasescanClient, BasescanError
    from .trust_score.data.slither_runner import (
        SlitherNotAvailable,
        SlitherRunner,
        SlitherError,
    )
    from .trust_score.dimensions.contract_security import ContractSecurityInput, run as cs_run
    from .trust_score.engine import TrustScoreEngine
    from .trust_score.models import DimScore
    from .trust_score.weights import WEIGHTS

    from .trust_score.chains import get_chain

    api_key = basescan_key or os.environ.get("BASESCAN_API_KEY", "")
    if not api_key:
        console.print(
            "[red]Error:[/red] Basescan API key required. "
            "Pass --basescan-key or set the BASESCAN_API_KEY environment variable."
        )
        sys.exit(1)

    chain_cfg = get_chain(chain)
    rpc_url = chain_cfg.rpc_url

    console.print(
        f"\n[bold]ACP-SEC Trust Score[/bold] — [cyan]{agent}[/cyan] "
        f"(chain: {chain_cfg.name}, mode: {scan_mode})\n"
    )

    # --- Basescan: fetch contract verification status + ABI ---
    console.print("  [dim]Fetching contract data from Basescan...[/dim]", end="\r")
    try:
        client = BasescanClient(api_key=api_key)
        contract = client.get_contract(agent)
    except BasescanError as exc:
        console.print(f"[red]Basescan error:[/red] {exc}")
        sys.exit(1)

    # --- Slither: static analysis ---
    slither_findings = []
    if not no_slither:
        console.print("  [dim]Running Slither static analysis...[/dim]    ", end="\r")
        try:
            runner = SlitherRunner()
            slither_findings = runner.run(agent, api_key=api_key)
        except SlitherNotAvailable:
            console.print(
                "  [yellow]Slither not installed — skipping static analysis. "
                "Install with: pip install slither-analyzer[/yellow]"
            )
        except SlitherError as exc:
            console.print(f"  [yellow]Slither error (skipping): {exc}[/yellow]")

    # --- Map to ContractSecurityInput ---
    cs_flags: dict[str, bool] = {field: False for field in [
        "has_arbitrary_delegatecall", "has_unbounded_mint", "has_reentrancy",
        "missing_access_control", "upgradeable_proxy_eoa_admin",
        "has_selfdestruct", "uses_tx_origin_auth",
        "unchecked_low_level_calls", "floating_pragma",
    ]}
    for finding in slither_findings:
        mapped = _SLITHER_MAP.get(finding.check)
        if mapped:
            cs_flags[mapped] = True

    cs_input = ContractSecurityInput(
        source_verified=contract.source_verified,
        **cs_flags,
    )

    # --- Dimension 1: Contract Security ---
    dim1 = cs_run(cs_input)

    # --- Dimension 2: Authority Scope (ABI + on-chain owner reads) ---
    from .trust_score.data.authority_scope_adapter import AuthorityScopeAdapter
    from .trust_score.dimensions.authority_scope import run as as_run
    console.print("  [dim]Analyzing authority scope...[/dim]        ", end="\r")
    try:
        as_input = AuthorityScopeAdapter(
            rpc_url=rpc_url, scan_mode=scan_mode, chain=chain
        ).fetch(contract)
        dim2 = as_run(as_input)
    except Exception as exc:
        console.print(f"  [yellow]Authority scope error (Unrated): {exc}[/yellow]")
        from .trust_score.weights import WEIGHTS as _W
        dim2 = DimScore(name="authority_scope", score=0.0, weight=_W["authority_scope"], rated=False)

    # --- Dimension 6: Behavioral (on-chain Transfer event analysis) ---
    from .trust_score.data.behavioral_adapter import BehavioralAdapter
    from .trust_score.dimensions.behavioral import run as beh_run
    console.print("  [dim]Analyzing on-chain behavior...[/dim]       ", end="\r")
    try:
        beh_input = BehavioralAdapter(rpc_url=rpc_url).fetch(agent)
        dim6 = beh_run(beh_input)
    except Exception as exc:
        console.print(f"  [yellow]Behavioral error (Unrated): {exc}[/yellow]")
        from .trust_score.weights import WEIGHTS as _W
        dim6 = DimScore(name="behavioral", score=0.0, weight=_W["behavioral"], rated=False)

    # --- Dimension 3: Identity (ERC-8004 registry + sybil check) ---
    from .trust_score.data.erc8004_adapter import ERC8004Adapter
    from .trust_score.dimensions.identity import run as id_run
    console.print("  [dim]Analyzing identity (ERC-8004)...[/dim]    ", end="\r")
    try:
        id_input = ERC8004Adapter(rpc_url=rpc_url).fetch(agent)
        dim3 = id_run(id_input)
    except Exception as exc:
        console.print(f"  [yellow]Identity error (Unrated): {exc}[/yellow]")
        from .trust_score.weights import WEIGHTS as _W
        dim3 = DimScore(name="identity", score=0.0, weight=_W["identity"], rated=False)

    # --- Dimension 4: Hook Security (Slither + on-chain owner check) ---
    from .trust_score.data.hook_security_adapter import HookSecurityAdapter
    from .trust_score.dimensions.hook_security import run as hs_run
    console.print("  [dim]Analyzing hook security...[/dim]           ", end="\r")
    try:
        hs_input = HookSecurityAdapter(rpc_url=rpc_url).fetch(agent)
        dim4 = hs_run(hs_input)
    except Exception as exc:
        console.print(f"  [yellow]Hook security error (Unrated): {exc}[/yellow]")
        from .trust_score.weights import WEIGHTS as _W
        dim4 = DimScore(name="hook_security", score=0.0, weight=_W["hook_security"], rated=False)

    # --- Dimension 5: ACP Compliance (ABI analysis) ---
    from .trust_score.data.acp_compliance_adapter import ACPComplianceAdapter
    from .trust_score.dimensions.acp_compliance import run as acp_run
    console.print("  [dim]Analyzing ACP compliance...[/dim]          ", end="\r")
    try:
        acp_input = ACPComplianceAdapter(rpc_url=rpc_url, chain=chain).fetch(contract)
        dim5 = acp_run(acp_input)
    except Exception as exc:
        console.print(f"  [yellow]ACP compliance error (Unrated): {exc}[/yellow]")
        from .trust_score.weights import WEIGHTS as _W
        dim5 = DimScore(name="acp_compliance", score=0.0, weight=_W["acp_compliance"], rated=False)

    all_dims = [dim1, dim2, dim3, dim4, dim5, dim6]

    # --- Engine ---
    engine = TrustScoreEngine()
    result = engine.assess(agent=agent, dim_scores=all_dims)

    # --- Terminal output ---
    grade_color = {"A": "green", "B": "cyan", "C": "yellow", "D": "red", "F": "red"}.get(
        result.grade, "white"
    )
    rated_label = "" if result.rated else " [dim](Unrated — partial data)[/dim]"
    console.print(
        f"  Score:      [{grade_color}]{result.score}[/{grade_color}] / 100  "
        f"Grade [{grade_color}]{result.grade}[/{grade_color}]{rated_label}"
    )
    console.print(f"  Multiplier: {result.multiplier:.2f}x  |  Critical: {result.critical}")
    console.print(f"  Contract:   {'✓ verified' if contract.source_verified else '[red]✗ UNVERIFIED[/red]'}")

    if result.top_findings:
        console.print("\n  [bold]Findings:[/bold]")
        for f in result.top_findings[:10]:
            sev_color = {"CRITICAL": "red", "High": "red", "Medium": "yellow", "Low": "dim"}.get(
                f.severity, "white"
            )
            console.print(f"    [{sev_color}]{f.severity:<10}[/{sev_color}] {f.dim}: {f.detail}")

    unrated = [d for d in all_dims if not d.rated]
    if unrated:
        unrated_names = ", ".join(d.name for d in unrated)
        console.print(
            f"\n  [dim]Note: {unrated_names} are Unrated — data unavailable.[/dim]"
        )

    dims_with_unrated = [d for d in all_dims if d.unrated_checks]
    if dims_with_unrated:
        console.print(
            "\n  [bold]Unrated checks[/bold] [dim](not verifiable in this scan):[/dim]"
        )
        for d in dims_with_unrated:
            console.print(
                f"    [dim]{d.name}:[/dim] {', '.join(d.unrated_checks)}"
            )

    console.print()

    # --- JSON output ---
    if output:
        output.write_text(_json.dumps(result.model_dump(), indent=2))
        console.print(f"  Saved to [cyan]{output}[/cyan]\n")


if __name__ == "__main__":
    main()
