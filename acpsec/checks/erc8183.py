"""
ERC8183 dimension checks — ERC-8183 protocol lifecycle compliance (10 pts, OPT-IN).

v0.5.0 dimension aligned with the Ethereum Foundation dAI team ERC-8183
specification (@DavideCrapis). Covers job lifecycle disclosure, hook
architecture, evaluator transparency, job typing, and multi-chain support.
Only evaluated when AgentConfig.erc8183.enabled is True.

Five checks, 10 pts total. No CRITICAL checks — compliance is progressive;
partial credit is awarded for ERC-01 and ERC-03 to reward incremental adoption.
"""

from __future__ import annotations

from ..agent_client import AgentClient
from ..models import AgentConfig, CheckResult, DimensionResult, Severity
from ..scorer import OPTIONAL_DIMENSION_WEIGHTS, make_check

DIMENSION_ID = "ERC8183"
DIMENSION_NAME = "ERC-8183 Protocol Compliance"

# Recognised ERC-8183 chains.
ERC8183_CHAINS = frozenset({"base", "ethereum", "arbitrum", "optimism", "bnb", "polygon"})

# Canonical job lifecycle statuses required by ERC-8183.
JOB_LIFECYCLE_STATUSES = ("open", "funded", "submitted", "completed", "rejected", "expired")


def run_erc8183_checks(config: AgentConfig, client: AgentClient | None = None) -> DimensionResult:
    """Run all 5 ERC8183 static checks. Raises if the dimension isn't enabled."""
    if not config.erc8183.enabled:
        raise RuntimeError(
            "run_erc8183_checks called on an agent with erc8183.enabled=false. "
            "Gate the call site on config.erc8183.enabled."
        )

    checks: list[CheckResult] = [
        _erc01_job_lifecycle(config),
        _erc02_hook_architecture(config),
        _erc03_evaluator_fee_split(config),
        _erc04_job_type(config),
        _erc05_multichain(config),
    ]
    expected = OPTIONAL_DIMENSION_WEIGHTS[DIMENSION_ID]
    actual = sum(c.max_score for c in checks)
    assert actual == expected, f"{DIMENSION_ID} check max_scores must sum to {expected} (got {actual})"
    return DimensionResult(
        dimension_id=DIMENSION_ID,
        name=DIMENSION_NAME,
        score=sum(c.score for c in checks),
        max_score=expected,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# ERC-01 (3 pts, HIGH) — Job lifecycle statuses disclosed
# ---------------------------------------------------------------------------
def _erc01_job_lifecycle(config: AgentConfig) -> CheckResult:
    """All six ERC-8183 job lifecycle statuses must be disclosed."""
    erc = config.erc8183
    prompt = (config.system_prompt or "").lower()

    found = [s for s in JOB_LIFECYCLE_STATUSES if s in prompt]
    missing = [s for s in JOB_LIFECYCLE_STATUSES if s not in prompt]

    passed = bool(erc.job_lifecycle_documented) or (len(found) == len(JOB_LIFECYCLE_STATUSES))

    if passed:
        return make_check(
            check_id="ERC-01",
            name="Job lifecycle statuses disclosed",
            dimension=DIMENSION_ID,
            severity=Severity.HIGH,
            max_score=3,
            passed=True,
            evidence=[
                f"erc8183.job_lifecycle_documented={erc.job_lifecycle_documented}",
                f"statuses-found-in-prompt={found}",
            ],
        )

    # Partial credit: >= 3 statuses found in prompt
    if len(found) >= 3:
        return make_check(
            check_id="ERC-01",
            name="Job lifecycle statuses disclosed",
            dimension=DIMENSION_ID,
            severity=Severity.HIGH,
            max_score=3,
            passed=False,
            partial_score=1.5,
            evidence=[
                f"erc8183.job_lifecycle_documented={erc.job_lifecycle_documented}",
                f"statuses-found-in-prompt={found}",
                f"statuses-missing-from-prompt={missing}",
            ],
            recommendations=[
                "Document all ERC-8183 job statuses: Open, Funded, Submitted, Completed, Rejected, Expired",
                "Users need full lifecycle visibility before engaging a fund-transfer agent",
            ],
        )

    return make_check(
        check_id="ERC-01",
        name="Job lifecycle statuses disclosed",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=3,
        passed=False,
        evidence=[
            f"erc8183.job_lifecycle_documented={erc.job_lifecycle_documented}",
            f"statuses-found-in-prompt={found}",
            f"statuses-missing-from-prompt={missing}",
        ],
        recommendations=[
            "Document all ERC-8183 job statuses: Open, Funded, Submitted, Completed, Rejected, Expired",
            "Users need full lifecycle visibility before engaging a fund-transfer agent",
        ],
    )


# ---------------------------------------------------------------------------
# ERC-02 (2 pts, HIGH) — Hook architecture documented
# ---------------------------------------------------------------------------
def _erc02_hook_architecture(config: AgentConfig) -> CheckResult:
    """The agent's hook integration (beforeAction/afterAction) must be documented."""
    erc = config.erc8183
    prompt = (config.system_prompt or "").lower()
    hook_signals = ("beforeaction", "afteraction", "hook contract", "iacphook", "erc-8183 hook")
    prompt_signal = any(sig in prompt for sig in hook_signals)
    passed = bool(erc.hook_architecture_documented) or prompt_signal

    return make_check(
        check_id="ERC-02",
        name="Hook architecture documented",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=passed,
        evidence=[
            f"erc8183.hook_architecture_documented={erc.hook_architecture_documented}",
            f"prompt-mentions-hook={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Document beforeAction/afterAction hook integration",
                "Reference: BaseERC8183Hook.sol selector routing pattern",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# ERC-03 (2 pts, MEDIUM) — Evaluator role and fee split disclosed
# ---------------------------------------------------------------------------
def _erc03_evaluator_fee_split(config: AgentConfig) -> CheckResult:
    """Evaluator role and fee distribution (e.g. 90/5/5) must be disclosed."""
    erc = config.erc8183
    prompt = (config.system_prompt or "").lower()

    evaluator_in_prompt = "evaluator" in prompt
    fee_signals = ("90/5/5", "95/5", "fee split", "fee distribution", "revenue share")
    fee_in_prompt = any(sig in prompt for sig in fee_signals)

    passed = (bool(erc.evaluator_disclosed) and bool(erc.fee_split_documented)) or (
        evaluator_in_prompt and fee_in_prompt
    )

    if passed:
        return make_check(
            check_id="ERC-03",
            name="Evaluator role and fee split disclosed",
            dimension=DIMENSION_ID,
            severity=Severity.MEDIUM,
            max_score=2,
            passed=True,
            evidence=[
                f"erc8183.evaluator_disclosed={erc.evaluator_disclosed}",
                f"erc8183.fee_split_documented={erc.fee_split_documented}",
                f"prompt-mentions-evaluator={evaluator_in_prompt}",
                f"prompt-mentions-fee-split={fee_in_prompt}",
            ],
        )

    # Partial credit: evaluator disclosed only (no fee split)
    evaluator_only = bool(erc.evaluator_disclosed) or (evaluator_in_prompt and not fee_in_prompt)
    if evaluator_only and not (bool(erc.fee_split_documented) or fee_in_prompt):
        return make_check(
            check_id="ERC-03",
            name="Evaluator role and fee split disclosed",
            dimension=DIMENSION_ID,
            severity=Severity.MEDIUM,
            max_score=2,
            passed=False,
            partial_score=1,
            evidence=[
                f"erc8183.evaluator_disclosed={erc.evaluator_disclosed}",
                f"erc8183.fee_split_documented={erc.fee_split_documented}",
                f"prompt-mentions-evaluator={evaluator_in_prompt}",
                f"prompt-mentions-fee-split={fee_in_prompt}",
            ],
            recommendations=[
                "Disclose the evaluator role and fee distribution (e.g. 90/5/5 agent/evaluator/protocol)",
                "Counterparties need to know who verifies job completion and how fees are split",
            ],
        )

    return make_check(
        check_id="ERC-03",
        name="Evaluator role and fee split disclosed",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=2,
        passed=False,
        evidence=[
            f"erc8183.evaluator_disclosed={erc.evaluator_disclosed}",
            f"erc8183.fee_split_documented={erc.fee_split_documented}",
            f"prompt-mentions-evaluator={evaluator_in_prompt}",
            f"prompt-mentions-fee-split={fee_in_prompt}",
        ],
        recommendations=[
            "Disclose the evaluator role and fee distribution (e.g. 90/5/5 agent/evaluator/protocol)",
            "Counterparties need to know who verifies job completion and how fees are split",
        ],
    )


# ---------------------------------------------------------------------------
# ERC-04 (2 pts, MEDIUM) — Job type categorization declared
# ---------------------------------------------------------------------------
def _erc04_job_type(config: AgentConfig) -> CheckResult:
    """The agent must declare whether jobs are fund-transfer or service-only."""
    erc = config.erc8183
    prompt = (config.system_prompt or "").lower()
    job_type_signals = ("fund-transfer", "service-only", "service only", "job type", "job category")
    prompt_signal = any(sig in prompt for sig in job_type_signals)
    passed = bool(erc.job_type_declared) or prompt_signal

    return make_check(
        check_id="ERC-04",
        name="Job type categorization declared",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=2,
        passed=passed,
        evidence=[
            f"erc8183.job_type_declared={erc.job_type_declared}",
            f"prompt-mentions-job-type={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Declare whether jobs are fund-transfer or service-only",
                "Fund-transfer jobs require additional hook and escrow documentation",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# ERC-05 (1 pt, LOW) — Multi-chain support documented
# ---------------------------------------------------------------------------
def _erc05_multichain(config: AgentConfig) -> CheckResult:
    """Supported chains should be declared and include recognised ERC-8183 networks."""
    erc = config.erc8183
    prompt = (config.system_prompt or "").lower()

    config_chains = [c.lower() for c in (erc.supported_chains or [])]
    valid_config_chains = [c for c in config_chains if c in ERC8183_CHAINS]

    prompt_chains = [c for c in ERC8183_CHAINS if c in prompt]

    passed = bool(valid_config_chains) or bool(prompt_chains)

    chains_found = list(dict.fromkeys(valid_config_chains + prompt_chains))  # dedup, preserve order

    return make_check(
        check_id="ERC-05",
        name="Multi-chain support documented",
        dimension=DIMENSION_ID,
        severity=Severity.LOW,
        max_score=1,
        passed=passed,
        evidence=[
            f"erc8183.supported_chains={erc.supported_chains}",
            f"recognised-chains-found={chains_found}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Declare supported chains",
                "Recognised ERC-8183 networks: Base, Ethereum, Arbitrum, Optimism, BNB, Polygon",
            ]
        ),
    )
