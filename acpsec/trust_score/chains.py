"""Chain registry and ACP conformance reference contracts.

Holds the supported-chain configuration and the canonical ACP deployment
addresses used as conformance ground-truth when scoring lifecycle, fee-split,
and hook checks (Dimensions 4 and 5).

Reference addresses are Base Mainnet ground-truth. Testnet reference
deployments are not yet recorded (left None) — fill in when available.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ReferenceContracts:
    """Known-good ACP deployment addresses used as conformance ground-truth."""

    acp_core: str | None = None
    fund_transfer_hook: str | None = None


@dataclass(frozen=True)
class ChainConfig:
    chain_id: int
    name: str
    rpc_url: str
    references: ReferenceContracts = field(default_factory=ReferenceContracts)


# Base Mainnet (8453) ground-truth ACP deployment.
_BASE_MAINNET_REFS = ReferenceContracts(
    acp_core="0x238E541BfefD82238730D00a2208E5497F1832E0",
    fund_transfer_hook="0x90717828D78731313CB350D6a58b0f91668Ea702",
)

CHAINS: dict[int, ChainConfig] = {
    8453: ChainConfig(
        chain_id=8453,
        name="Base Mainnet",
        rpc_url="https://mainnet.base.org",
        references=_BASE_MAINNET_REFS,
    ),
    84532: ChainConfig(
        chain_id=84532,
        name="Base Sepolia",
        rpc_url="https://sepolia.base.org",
        references=ReferenceContracts(),  # TODO: record testnet ACP deployment addresses
    ),
}

# Name aliases accepted by the CLI --chain flag.
_NAME_ALIASES: dict[str, int] = {
    "base":          8453,
    "base-mainnet":  8453,
    "base-sepolia":  84532,
}

DEFAULT_CHAIN_ID = 8453


class UnknownChainError(ValueError):
    """Raised when a chain id or name cannot be resolved to a supported chain."""


def get_chain(identifier: int | str) -> ChainConfig:
    """Resolve a ChainConfig by chain id (int) or name alias (str)."""
    if isinstance(identifier, bool):  # guard: bool is an int subclass
        raise UnknownChainError(f"invalid chain identifier: {identifier!r}")
    if isinstance(identifier, int):
        chain_id = identifier
    else:
        key = identifier.strip().lower()
        if key not in _NAME_ALIASES:
            raise UnknownChainError(f"unknown chain: {identifier!r}")
        chain_id = _NAME_ALIASES[key]
    if chain_id not in CHAINS:
        raise UnknownChainError(f"unsupported chain id: {chain_id}")
    return CHAINS[chain_id]


def reference_contracts(identifier: int | str) -> ReferenceContracts:
    """Return the conformance reference contracts for a chain."""
    return get_chain(identifier).references
