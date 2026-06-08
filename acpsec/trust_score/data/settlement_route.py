"""Settlement-route resolution for fee-split conformance (Guardrail A).

The 95/5 (no Evaluator) and 90/5/5 (with Evaluator) fee split is enforced by the
official ACP Core Job contract, not by the agent. An agent that settles via the
official ACP Core is conformant by construction and must not be flagged. Only a
custom/forked settlement contract is analysed; an undeterminable path is Unrated.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from .basescan import ContractData

ROUTE_OFFICIAL_CORE = "official_core"
ROUTE_CUSTOM = "custom"

CONFORMANT_SPLITS: frozenset[tuple[int, ...]] = frozenset({(95, 5), (90, 5, 5)})


def is_conformant_split(split: Sequence[int]) -> bool:
    """True if ``split`` is one of the protocol-conformant shapes."""
    return tuple(split) in CONFORMANT_SPLITS


def assess_fee_split(
    route: str | None, split: Sequence[int] | None
) -> bool | None:
    """Tri-state fee-split assessment from a resolved (route, split).

    Returns False (conformant), True (non-conformant), or None (Unrated).
    """
    if route == ROUTE_OFFICIAL_CORE:
        return False
    if route == ROUTE_CUSTOM:
        if split is None:
            return None
        return not is_conformant_split(split)
    return None


class SettlementRouteResolver:
    """Resolve how a contract settles: official ACP Core vs custom fork."""

    def __init__(
        self,
        official_core: str | None = None,
        _split_reader: Callable[[ContractData], Sequence[int] | None] | None = None,
    ) -> None:
        self._official_core = (official_core or "").lower()
        self._split_reader = _split_reader

    def resolve(
        self, contract_data: ContractData
    ) -> tuple[str | None, tuple[int, ...] | None]:
        addr = (contract_data.address or "").lower()
        if self._official_core and addr == self._official_core:
            return (ROUTE_OFFICIAL_CORE, None)

        src = (contract_data.source_code or "").lower()
        if self._official_core and self._official_core in src:
            return (ROUTE_OFFICIAL_CORE, None)

        if self._split_reader is not None:
            try:
                split = self._split_reader(contract_data)
            except Exception:
                return (None, None)
            if split is not None:
                return (ROUTE_CUSTOM, tuple(split))

        return (None, None)
