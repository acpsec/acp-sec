"""Smart-account signer-mode reader (Dimension 2).

Virtuals agents use Alchemy Smart Wallets (Modular Account V2) whose session
keys carry on-chain scoped permissions (a contract allowlist) enforced by the
session-key plugin. This reader makes a best-effort on-chain read of that
allowlist and classifies the signer mode against the chain's known-good ACP
reference contracts:

    "Restricted"   — allowlist is non-empty and entirely within the ACP set
    "Unrestricted" — no allowlist (open) or scope reaches beyond the ACP set
    None           — Unrated: not a smart account, RPC failure, allowlist not
                     readable, or no reference set to compare against

The exact Modular Account V2 session-key plugin ABI is not yet wired, so the
allowlist read is injected via ``_allowlist_reader``. Until a real reader is
supplied, smart accounts resolve to None (Unrated) — never penalized.

Injectable callables:
- ``_rpc(method, params) -> Any``                  — JSON-RPC
- ``_allowlist_reader(address) -> list[str] | None`` — session-key allowlist
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable, Iterable

DEFAULT_RPC_URL = "https://mainnet.base.org"

SIGNER_RESTRICTED = "Restricted"
SIGNER_UNRESTRICTED = "Unrestricted"


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


class SmartAccountPermissionReader:
    def __init__(
        self,
        allowed_targets: Iterable[str] | None = None,
        rpc_url: str = DEFAULT_RPC_URL,
        _rpc: Callable[[str, list], Any] | None = None,
        # TODO: default to a real Modular Account V2 session-key allowlist reader
        # once the plugin ABI is wired. Until then, None → smart accounts Unrated.
        _allowlist_reader: Callable[[str], list[str] | None] | None = None,
    ) -> None:
        self._allowed = {t.lower() for t in (allowed_targets or [])}
        self._rpc = _rpc or _default_rpc(rpc_url)
        self._allowlist_reader = _allowlist_reader

    def read_signer_mode(self, address: str) -> str | None:
        if not self._is_smart_account(address):
            return None
        if self._allowlist_reader is None:
            return None
        try:
            allowlist = self._allowlist_reader(address)
        except Exception:
            return None
        if allowlist is None:
            return None
        if len(allowlist) == 0:
            return SIGNER_UNRESTRICTED
        if not self._allowed:
            return None  # cannot judge scope without a reference set
        targets = {a.lower() for a in allowlist}
        return SIGNER_RESTRICTED if targets <= self._allowed else SIGNER_UNRESTRICTED

    def _is_smart_account(self, address: str) -> bool:
        try:
            code = self._rpc("eth_getCode", [address, "latest"])
        except Exception:
            return False
        return bool(code and code != "0x")
