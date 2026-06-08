"""ERC-8004 Identity adapter (Dimension 3) — registry lookup + agent card fetch.

On-chain: checks a configurable registry contract for agent registration, and
inspects the contract's transaction count for sybil signals.

Off-chain: optionally fetches an agent card JSON (agent_card_url) to verify
owner matching, handle presence, and endpoint TLS.

Injectable callables:
- `_rpc(method, params) -> Any`  — JSON-RPC
- `_fetch_url(url) -> dict`      — HTTP fetch returning parsed JSON
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

from ..dimensions.identity import IdentityInput

DEFAULT_RPC_URL = "https://mainnet.base.org"

# ERC-8004 registry address on Base (placeholder — deploy and configure)
DEFAULT_REGISTRY = "0x0000000000000000000000000000000000000000"

# isRegistered(address) — keccak256("isRegistered(address)")[0:4]
_IS_REGISTERED_SELECTOR = "0x11a44739"

SYBIL_TX_THRESHOLD = 10


def _default_rpc(rpc_url: str) -> Callable[[str, list], Any]:
    def call(method: str, params: list) -> Any:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            rpc_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            payload = json.loads(resp.read().decode())
        if "error" in payload:
            raise RuntimeError(f"rpc error: {payload['error']}")
        return payload.get("result")
    return call


def _default_fetch_url(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())


class ERC8004Adapter:
    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        registry_address: str = DEFAULT_REGISTRY,
        sybil_tx_threshold: int = SYBIL_TX_THRESHOLD,
        _rpc: Callable[[str, list], Any] | None = None,
        _fetch_url: Callable[[str], dict] | None = None,
    ) -> None:
        self._rpc = _rpc or _default_rpc(rpc_url)
        self._fetch_url = _fetch_url or _default_fetch_url
        self._registry = registry_address
        self._sybil_threshold = sybil_tx_threshold

    def fetch(self, address: str, agent_card_url: str | None = None) -> IdentityInput:
        try:
            return self._fetch(address, agent_card_url)
        except Exception:
            return IdentityInput(no_erc8004=True)

    def _fetch(self, address: str, agent_card_url: str | None) -> IdentityInput:
        no_erc8004 = not self._is_registered(address)
        sybil = self._check_sybil(address)

        owner_mismatch = False
        handle_unverified = True
        endpoint_tls_mismatch = False

        if agent_card_url:
            try:
                card = self._fetch_url(agent_card_url)
                card_owner = card.get("owner", "")
                if card_owner:
                    owner_mismatch = card_owner.lower() != address.lower()
                handle_unverified = "handle" not in card
                endpoint = card.get("endpoint", "")
                if endpoint:
                    endpoint_tls_mismatch = not endpoint.startswith("https://")
            except Exception:
                handle_unverified = True
                owner_mismatch = False

        return IdentityInput(
            owner_mismatch=owner_mismatch,
            no_erc8004=no_erc8004,
            handle_unverified=handle_unverified,
            endpoint_tls_mismatch=endpoint_tls_mismatch,
            reputation_registry_inconsistent=False,
            sybil_signals=sybil,
        )

    def _is_registered(self, address: str) -> bool:
        """Check if address is registered in the ERC-8004 registry."""
        try:
            code = self._rpc("eth_getCode", [self._registry, "latest"])
            if not code or code == "0x":
                return False
            padded_addr = "0x" + address.lower().removeprefix("0x").zfill(64)
            data = _IS_REGISTERED_SELECTOR + padded_addr[2:]
            result = self._rpc("eth_call", [{"to": self._registry, "data": data}, "latest"])
            if not result or result == "0x":
                return False
            return int(result, 16) != 0
        except Exception:
            return False

    def _check_sybil(self, address: str) -> bool:
        """Return True if address shows sybil signals (low transaction count)."""
        try:
            count_hex = self._rpc("eth_getTransactionCount", [address, "latest"])
            return int(count_hex, 16) < self._sybil_threshold
        except Exception:
            return False
