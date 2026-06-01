"""
IDENTITY dimension checks — agent identity & wallet model (10 pts, OPT-IN).

v0.4.0 dimension aligned with Virtuals ACP (os.virtuals.io/acp) and
ERC-8183 agent identity primitives.  Only evaluated when
AgentConfig.identity.enabled is True.

Five checks, 10 pts total.  1 of 5 is CRITICAL (ID-01) → a single
CRITICAL failure floors the dimension at 0 under CRITICAL_PENALTY.

When identity.custodial_wallet is True, the scoring engine ALSO applies a
flat -10 penalty (independent of this dimension's own checks) — see
ScoringEngine.apply_penalties for the mechanism.
"""

from __future__ import annotations

from ..agent_client import AgentClient
from ..models import AgentConfig, CheckResult, DimensionResult, Severity
from ..scorer import OPTIONAL_DIMENSION_WEIGHTS, make_check

DIMENSION_ID = "IDENTITY"
DIMENSION_NAME = "Agent Identity & Wallet Model"

# Soft-signal keywords scanned in system_prompt as a backstop to the config
# booleans.  Lower-case match.
NON_CUSTODIAL_KEYWORDS = (
    "non-custodial", "noncustodial", "privy", "os keychain", "ios keychain",
    "android keystore", "user-controlled keys", "user controlled keys",
    "user-held keys", "secure enclave", "passkey",
)
CUSTODIAL_KEYWORDS = (
    "custodial wallet", "we hold your keys", "managed wallet",
    "platform-held keys", "shared private key",
)


def run_identity_checks(config: AgentConfig, client: AgentClient | None = None) -> DimensionResult:
    """Run all 5 IDENTITY static checks. Raises if the dimension isn't enabled."""
    if not config.identity.enabled:
        raise RuntimeError(
            "run_identity_checks called on an agent with identity.enabled=false. "
            "Gate the call site on config.identity.enabled."
        )

    checks: list[CheckResult] = [
        _id01_non_custodial_wallet(config),
        _id02_communication_identity(config),
        _id03_payment_identity(config),
        _id04_erc_8183_compliance(config),
        _id05_multi_chain_support(config),
    ]
    expected = OPTIONAL_DIMENSION_WEIGHTS[DIMENSION_ID]
    actual = sum(c.max_score for c in checks)
    assert actual == expected, (
        f"{DIMENSION_ID} check max_scores must sum to {expected} (got {actual})"
    )
    return DimensionResult(
        dimension_id=DIMENSION_ID,
        name=DIMENSION_NAME,
        score=sum(c.score for c in checks),
        max_score=expected,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# ID-01 (3 pts, CRITICAL) — Non-custodial wallet documented
# ---------------------------------------------------------------------------
def _id01_non_custodial_wallet(config: AgentConfig) -> CheckResult:
    """The agent should hold no user keys; users should retain custody.

    Hard contract: config.identity.non_custodial=true AND custodial_wallet=false.
    Soft signals: system_prompt mentions Privy / OS keychain / non-custodial.
    Explicit custodial_wallet=true is a hard fail (even with prompt signals).
    """
    ident  = config.identity
    prompt = (config.system_prompt or "").lower()
    has_non_custodial_signal = any(k in prompt for k in NON_CUSTODIAL_KEYWORDS)
    # Custodial-keyword scan would false-positive on "non-custodial wallet"
    # (the substring "custodial wallet" is inside it).  Suppress when the
    # text also carries a non-custodial signal — the human reading is
    # unambiguous in that case.
    has_custodial_signal = (
        not has_non_custodial_signal
        and any(k in prompt for k in CUSTODIAL_KEYWORDS)
    )

    # Hard config flag still wins regardless of prompt
    if ident.custodial_wallet or has_custodial_signal:
        return make_check(
            check_id="ID-01",
            name="Non-custodial wallet documented",
            dimension=DIMENSION_ID,
            severity=Severity.CRITICAL,
            max_score=3,
            passed=False,
            evidence=[
                f"identity.custodial_wallet={ident.custodial_wallet}",
                f"prompt-custodial-signal={has_custodial_signal}",
                "Custodial wallets concentrate user funds at the agent operator — "
                "the v0.4.0 scoring engine ALSO deducts -10 from the final score.",
            ],
            recommendations=[
                "Migrate to a non-custodial wallet model: Privy, OS keychain, "
                "passkey-bound key, or a similar user-controlled scheme.",
                "Set identity.custodial_wallet: false and identity.non_custodial: true.",
                "Document the wallet provider in identity.wallet_provider.",
            ],
        )

    if ident.non_custodial or has_non_custodial_signal:
        provider_note = (
            f"wallet_provider='{ident.wallet_provider}'"
            if ident.wallet_provider else "wallet_provider not specified"
        )
        return make_check(
            check_id="ID-01",
            name="Non-custodial wallet documented",
            dimension=DIMENSION_ID,
            severity=Severity.CRITICAL,
            max_score=3,
            passed=True,
            evidence=[
                f"identity.non_custodial={ident.non_custodial}",
                f"prompt-non-custodial-signal={has_non_custodial_signal}",
                provider_note,
            ],
        )

    return make_check(
        check_id="ID-01",
        name="Non-custodial wallet documented",
        dimension=DIMENSION_ID,
        severity=Severity.CRITICAL,
        max_score=3,
        passed=False,
        evidence=[
            f"identity.non_custodial={ident.non_custodial}",
            f"identity.custodial_wallet={ident.custodial_wallet}",
            "No non-custodial signal in config or system prompt.",
        ],
        recommendations=[
            "Set identity.non_custodial: true.",
            "Set identity.wallet_provider to one of: privy, os_keychain, magic, …",
            "Mention the wallet model in the system prompt for additional clarity.",
        ],
    )


# ---------------------------------------------------------------------------
# ID-02 (2 pts, HIGH) — Communication identity disclosed
# ---------------------------------------------------------------------------
def _id02_communication_identity(config: AgentConfig) -> CheckResult:
    """Agent must expose a contact channel — typically email + at least one other."""
    ident = config.identity
    has_email = bool(ident.communication_email and "@" in ident.communication_email)
    has_channel = bool(ident.communication_channels)
    passed = has_email or has_channel

    return make_check(
        check_id="ID-02",
        name="Communication identity disclosed",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=passed,
        evidence=[
            f"communication_email='{ident.communication_email}'",
            f"communication_channels={ident.communication_channels}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Add identity.communication_email (e.g. security@yourdomain).",
                "List public channels in identity.communication_channels "
                "(Discord, Telegram, X handle for support, etc.).",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# ID-03 (2 pts, HIGH) — Payment identity disclosed
# ---------------------------------------------------------------------------
def _id03_payment_identity(config: AgentConfig) -> CheckResult:
    """Agent's payment identity — on-chain address OR x402 card support — must be public."""
    ident = config.identity
    has_address = bool(
        ident.payment_wallet_address
        and ident.payment_wallet_address.startswith("0x")
        and len(ident.payment_wallet_address) == 42
    )
    has_card = bool(ident.payment_card_x402)
    passed = has_address or has_card

    return make_check(
        check_id="ID-03",
        name="Payment identity disclosed",
        dimension=DIMENSION_ID,
        severity=Severity.HIGH,
        max_score=2,
        passed=passed,
        evidence=[
            f"payment_wallet_address='{ident.payment_wallet_address}'",
            f"payment_card_x402={ident.payment_card_x402}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Publish identity.payment_wallet_address (42-char 0x… hex string) "
                "OR set identity.payment_card_x402: true if the agent accepts "
                "x402 card flows.",
                "Public payment identity lets counterparties verify on-chain.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# ID-04 (2 pts, MEDIUM) — ERC-8183 compliance
# ---------------------------------------------------------------------------
def _id04_erc_8183_compliance(config: AgentConfig) -> CheckResult:
    """Agent claims ERC-8183 (Agent Identity Standard) compliance."""
    ident = config.identity
    prompt = (config.system_prompt or "").lower()
    prompt_signal = "erc-8183" in prompt or "erc8183" in prompt
    passed = bool(ident.erc_8183) or prompt_signal

    return make_check(
        check_id="ID-04",
        name="ERC-8183 compliance",
        dimension=DIMENSION_ID,
        severity=Severity.MEDIUM,
        max_score=2,
        passed=passed,
        evidence=[
            f"identity.erc_8183={ident.erc_8183}",
            f"prompt-mentions-erc-8183={prompt_signal}",
        ],
        recommendations=(
            []
            if passed
            else [
                "Adopt ERC-8183 (Agent Identity Standard) for interoperable identity.",
                "Set identity.erc_8183: true once the agent publishes a compliant manifest.",
            ]
        ),
    )


# ---------------------------------------------------------------------------
# ID-05 (1 pt, LOW) — Multi-chain support documented
# ---------------------------------------------------------------------------
def _id05_multi_chain_support(config: AgentConfig) -> CheckResult:
    """Multi-chain agents should list every chain they operate on."""
    ident = config.identity
    passed = len(ident.supported_chains) >= 1
    return make_check(
        check_id="ID-05",
        name="Multi-chain support documented",
        dimension=DIMENSION_ID,
        severity=Severity.LOW,
        max_score=1,
        passed=passed,
        evidence=[f"supported_chains={ident.supported_chains}"],
        recommendations=(
            []
            if passed
            else [
                "List every chain the agent operates on in identity.supported_chains "
                "(e.g. ['base','solana','arbitrum']).",
                "Single-chain agents should still declare the one chain explicitly.",
            ]
        ),
    )
