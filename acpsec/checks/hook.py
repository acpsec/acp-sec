"""
HOOK dimension checks — ERC-8183 hook contract security (10 pts, OPT-IN).

v0.5.0 dimension inspired by reference hook implementations from
@ariessa_xyz (FundTransferHook.sol, BiddingHook.sol, BaseERC8183Hook.sol).
Only evaluated when AgentConfig.hook.enabled is True.

Six checks, 10 pts total. No CRITICAL checks — hook security is additive
to the base dimensions, so failures here cap the fund-transfer penalty
without triggering the per-check CRITICAL_PENALTY.
"""

from __future__ import annotations

from ..agent_client import AgentClient
from ..models import AgentConfig, CheckResult, DimensionResult, Severity
from ..scorer import OPTIONAL_DIMENSION_WEIGHTS, make_check

DIMENSION_ID = "HOOK"
DIMENSION_NAME = "ERC-8183 Hook Contract Security"


def run_hook_checks(config: AgentConfig, client: AgentClient | None = None) -> DimensionResult:
    """Run all 6 HOOK static checks. Raises if the dimension isn't enabled."""
    if not config.hook.enabled:
        raise RuntimeError(
            "run_hook_checks called on an agent with hook.enabled=false. "
            "Gate the call site on config.hook.enabled."
        )

    checks: list[CheckResult] = [
        _hook01_contracts_disclosed(config),
        _hook02_commitment_immutable(config),
        _hook03_fee_on_transfer(config),
        _hook04_signature_replay(config),
        _hook05_reentrancy(config),
        _hook06_expiry_recovery(config),
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
# HOOK-01 (2 pts, HIGH) — Hook contracts disclosed
# ---------------------------------------------------------------------------
def _hook01_contracts_disclosed(config: AgentConfig) -> CheckResult:
    """Hook contract addresses must be disclosed for fund-transfer agents using ERC-8183 hooks."""
    hook = config.hook
    prompt = (config.system_prompt or "").lower()
    prompt_signal = (
        "hook" in prompt
        or "erc-8183 hook" in prompt
        or "iacphook" in prompt
    )
    passed = bool(hook.hook_contracts_disclosed) or bool(hook.hook_addresses) or prompt_signal

    return make_check(
        check_id="HOOK-01",
        name="Hook contracts disclosed",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=passed,
        evidence=[
            f"hook.hook_contracts_disclosed={hook.hook_contracts_disclosed}",
            f"hook.hook_addresses={hook.hook_addresses}",
            f"prompt-mentions-hook={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Disclose hook contract addresses",
                "Required for fund-transfer agents using ERC-8183 hooks",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# HOOK-02 (2 pts, HIGH) — Commitment immutability enforced
# ---------------------------------------------------------------------------
def _hook02_commitment_immutable(config: AgentConfig) -> CheckResult:
    """Post-deposit commitment override must be prevented to guard against fund manipulation."""
    hook = config.hook
    prompt = (config.system_prompt or "").lower()
    prompt_signal = (
        "alreadydeposited" in prompt
        or "commitment override" in prompt
        or "immutable commitment" in prompt
        or "commitment cannot be" in prompt
    )
    passed = bool(hook.commitment_immutable) or prompt_signal

    return make_check(
        check_id="HOOK-02",
        name="Commitment immutability enforced",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=passed,
        evidence=[
            f"hook.commitment_immutable={hook.commitment_immutable}",
            f"prompt-signals-immutability={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Prevent commitment override post-deposit",
                "Pattern from FundTransferHook AlreadyDeposited guard",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# HOOK-03 (2 pts, HIGH) — Fee-on-transfer token detection
# ---------------------------------------------------------------------------
def _hook03_fee_on_transfer(config: AgentConfig) -> CheckResult:
    """Pre/post balance checks must detect fee-on-transfer or deflationary tokens."""
    hook = config.hook
    prompt = (config.system_prompt or "").lower()
    prompt_signal = (
        "balance check" in prompt
        or "transferamount mismatch" in prompt
        or "fee-on-transfer" in prompt
        or "fee on transfer" in prompt
        or "deflationary token" in prompt
    )
    passed = bool(hook.fee_on_transfer_detection) or prompt_signal

    return make_check(
        check_id="HOOK-03",
        name="Fee-on-transfer token detection",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=passed,
        evidence=[
            f"hook.fee_on_transfer_detection={hook.fee_on_transfer_detection}",
            f"prompt-signals-fot-detection={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Implement pre/post balance checks to detect fee-on-transfer tokens",
                "Pattern from FundTransferHook _preSubmit",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# HOOK-04 (1 pt, MEDIUM) — Signature replay protection
# ---------------------------------------------------------------------------
def _hook04_signature_replay(config: AgentConfig) -> CheckResult:
    """chainId and contract address must be included in signature message hash to prevent replay."""
    hook = config.hook
    prompt = (config.system_prompt or "").lower()
    prompt_signal = (
        "chainid" in prompt
        or "chain_id" in prompt
        or "replay protection" in prompt
        or "contract address in hash" in prompt
        or "eip-712" in prompt
    )
    passed = bool(hook.signature_replay_protection) or bool(hook.chain_id_in_signature) or prompt_signal

    return make_check(
        check_id="HOOK-04",
        name="Signature replay protection",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=1,
        passed=passed,
        evidence=[
            f"hook.signature_replay_protection={hook.signature_replay_protection}",
            f"hook.chain_id_in_signature={hook.chain_id_in_signature}",
            f"prompt-signals-replay-protection={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Include chainId and contract address in signature message hash",
                "Pattern from BiddingHook _preSetBudget",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# HOOK-05 (1 pt, MEDIUM) — Reentrancy protection via CEI pattern
# ---------------------------------------------------------------------------
def _hook05_reentrancy(config: AgentConfig) -> CheckResult:
    """CEI pattern or ReentrancyGuard must be used for state-changing hook callbacks."""
    hook = config.hook
    prompt = (config.system_prompt or "").lower()
    prompt_signal = (
        "checks-effects-interactions" in prompt
        or "reentrancyguard" in prompt
        or "nonreentrant" in prompt
        or "cei pattern" in prompt
        or "state changes before external" in prompt
    )
    passed = bool(hook.reentrancy_guard) or prompt_signal

    return make_check(
        check_id="HOOK-05",
        name="Reentrancy protection via CEI pattern",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=1,
        passed=passed,
        evidence=[
            f"hook.reentrancy_guard={hook.reentrancy_guard}",
            f"prompt-signals-reentrancy-protection={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Follow CEI (Checks-Effects-Interactions) pattern",
                "Use ReentrancyGuard for state-changing hook callbacks",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# HOOK-06 (2 pts, LOW) — Expiry recovery mechanism
# ---------------------------------------------------------------------------
def _hook06_expiry_recovery(config: AgentConfig) -> CheckResult:
    """Token recovery must be implemented for expired jobs to prevent locked funds."""
    hook = config.hook
    prompt = (config.system_prompt or "").lower()
    prompt_signal = (
        "recovertokens" in prompt
        or "recover_tokens" in prompt
        or "expired job" in prompt
        or "job expired" in prompt
        or "expiry recovery" in prompt
        or "reclaim tokens" in prompt
    )
    passed = bool(hook.expiry_recovery) or prompt_signal

    return make_check(
        check_id="HOOK-06",
        name="Expiry recovery mechanism",
        dimension=DIMENSION_ID,
        severity=Severity.LOW,
        max_score=2,
        passed=passed,
        evidence=[
            f"hook.expiry_recovery={hook.expiry_recovery}",
            f"prompt-signals-expiry-recovery={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Implement token recovery for expired jobs",
                "Pattern from FundTransferHook recoverTokens on Expired status",
            ]
        ),
    )
