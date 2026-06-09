"""Basescan API client — fetches contract source verification status and ABI.

Designed for testability: pass a custom `_fetcher` callable to replace the
default urllib-based HTTP fetch (useful in tests without network access).
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

# Etherscan V2 unified endpoint. V1 chain-specific hosts (api.basescan.org,
# api-sepolia.basescan.org, ...) were sunset 2025-08-15. V2 uses a single host
# and selects the chain via the &chainid= query param; one API key works across
# all supported chains.
DEFAULT_BASE_URL = "https://api.etherscan.io/v2/api"

_ABI_UNVERIFIED_SENTINEL = "Contract source code not verified"


class BasescanError(Exception):
    """Raised when the Basescan API returns an error or unexpected payload."""


@dataclass
class ContractData:
    address: str
    source_verified: bool
    contract_name: str
    abi: list
    source_code: str
    compiler_version: str


def _default_fetcher(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode())


class BasescanClient:
    def __init__(
        self,
        api_key: str,
        chain_id: int,
        base_url: str = DEFAULT_BASE_URL,
        _fetcher: Callable[[str], Any] | None = None,
    ) -> None:
        self._api_key = api_key
        self._chain_id = chain_id
        self._base_url = base_url
        self._fetch = _fetcher or _default_fetcher

    def get_contract(self, address: str) -> ContractData:
        url = (
            f"{self._base_url}"
            f"?chainid={self._chain_id}"
            f"&module=contract&action=getsourcecode"
            f"&address={address}"
            f"&apikey={self._api_key}"
        )
        payload = self._fetch(url)

        if str(payload.get("status")) != "1":
            raise BasescanError(
                f"Basescan API error: {payload.get('message', 'unknown')} — {payload.get('result', '')}"
            )

        results = payload.get("result", [])
        if not results:
            raise BasescanError(f"Basescan returned empty result for address {address}")

        rec = results[0]
        source_code: str = rec.get("SourceCode", "")
        abi_raw: str = rec.get("ABI", "")

        source_verified = bool(source_code)
        abi: list = []
        if abi_raw and abi_raw != _ABI_UNVERIFIED_SENTINEL:
            try:
                abi = json.loads(abi_raw)
            except json.JSONDecodeError:
                abi = []

        return ContractData(
            address=address,
            source_verified=source_verified,
            contract_name=rec.get("ContractName", ""),
            abi=abi,
            source_code=source_code,
            compiler_version=rec.get("CompilerVersion", ""),
        )
