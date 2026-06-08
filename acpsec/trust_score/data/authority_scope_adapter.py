"""Authority Scope adapter (Dimension 2) — ABI analysis + on-chain owner reads.

Injectable `_rpc` signature: (method: str, params: list) -> Any
Default implementation uses the existing urllib-based JSON-RPC helper.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

from .basescan import ContractData
from .smart_account_reader import (
    SIGNER_RESTRICTED,
    SIGNER_UNRESTRICTED,
    SmartAccountPermissionReader,
)
from .virtuals_client import VirtualsClient
from ..chains import DEFAULT_CHAIN_ID, reference_contracts
from ..dimensions.authority_scope import AuthorityScopeInput
from ..models import DEFAULT_SCAN_MODE, ScanMode

DEFAULT_RPC_URL = "https://mainnet.base.org"

# owner() selector: keccak256("owner()")[0:4]
_OWNER_SELECTOR = "0x8da5cb5b"

# ABI keyword matchers (lower-case substring checks)
_WITHDRAWAL_KEYWORDS  = ("withdraw", "claim", "pull")
_CAP_KEYWORDS         = ("cap", "budget", "limit")
_PAUSE_KEYWORDS       = ("pause", "emergencystop")
_TIMELOCK_KEYWORDS    = ("queue", "delay", "eta", "timelock", "execute")
_ROTATION_KEYWORDS    = ("transferownership", "setowner", "changeowner")


def analyze_abi(abi: list[dict]) -> dict[str, bool]:
    """Pure ABI analysis — returns a flag dict, no network calls."""
    fns = [e for e in abi if e.get("type") == "function"]
    names_lower = [f.get("name", "").lower() for f in fns]

    def _any_match(keywords: tuple) -> bool:
        return any(kw in name for name in names_lower for kw in keywords)

    # approve(address,uint256) — two-argument form only
    has_token_approval = any(
        f.get("name", "").lower() == "approve"
        and len(f.get("inputs", [])) == 2
        and f["inputs"][0].get("type") == "address"
        and f["inputs"][1].get("type") == "uint256"
        for f in fns
    )

    return {
        "has_withdrawal":    _any_match(_WITHDRAWAL_KEYWORDS),
        "has_spending_cap":  _any_match(_CAP_KEYWORDS),
        "has_pause":         _any_match(_PAUSE_KEYWORDS),
        "has_timelock":      _any_match(_TIMELOCK_KEYWORDS),
        "has_key_rotation":  _any_match(_ROTATION_KEYWORDS),
        "has_token_approval": has_token_approval,
    }


def _default_rpc(rpc_url: str) -> Callable[[str, list], Any]:
    def call(method: str, params: list) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
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


class AuthorityScopeAdapter:
    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        scan_mode: str | ScanMode = DEFAULT_SCAN_MODE,
        chain: int | str = DEFAULT_CHAIN_ID,
        _rpc: Callable[[str, list], Any] | None = None,
        _signer_reader: SmartAccountPermissionReader | None = None,
        _virtuals_client: VirtualsClient | None = None,
    ) -> None:
        self._rpc = _rpc or _default_rpc(rpc_url)
        refs = reference_contracts(chain)
        allowed = [a for a in (refs.acp_core, refs.fund_transfer_hook) if a]
        self._signer_reader = _signer_reader or SmartAccountPermissionReader(
            allowed_targets=allowed, _rpc=self._rpc,
        )
        self._virtuals = _virtuals_client or VirtualsClient(scan_mode=scan_mode)

    def fetch(self, contract_data: ContractData) -> AuthorityScopeInput:
        abi_flags = analyze_abi(contract_data.abi)
        owner_is_contract = self._read_owner_is_contract(contract_data.address)
        signer_mode = self._signer_reader.read_signer_mode(contract_data.address)
        no_spend_limit = self._virtuals.get_agent_card_no_spend_limit(contract_data.address)
        return self._map(
            abi_flags,
            owner_is_contract=owner_is_contract,
            signer_mode=signer_mode,
            no_spend_limit=no_spend_limit,
        )

    def _read_owner_is_contract(self, address: str) -> bool:
        """Call owner() then eth_getCode on the result. Returns False on any error."""
        try:
            raw = self._rpc("eth_call", [
                {"to": address, "data": _OWNER_SELECTOR}, "latest",
            ])
            if not raw or raw == "0x":
                return False
            # raw is a 32-byte padded address: 0x + 24 zeros + 40 hex chars
            owner_addr = "0x" + raw[-40:]
            code = self._rpc("eth_getCode", [owner_addr, "latest"])
            return bool(code and code != "0x")
        except Exception:
            return False  # conservative: assume EOA on RPC failure

    @staticmethod
    def _map(
        abi_flags: dict[str, bool],
        *,
        owner_is_contract: bool,
        signer_mode: str | None,
        no_spend_limit: bool | None,
    ) -> AuthorityScopeInput:
        signer_unrestricted: bool | None = None
        if signer_mode == SIGNER_UNRESTRICTED:
            signer_unrestricted = True
        elif signer_mode == SIGNER_RESTRICTED:
            signer_unrestricted = False

        return AuthorityScopeInput(
            can_move_arbitrary_funds=False,
            withdrawal_gated_eoa=abi_flags["has_withdrawal"],
            owner_multisig=owner_is_contract,
            owner_mpc_threshold=False,
            no_spending_budget=not abi_flags["has_spending_cap"],
            infinite_token_approvals=abi_flags["has_token_approval"],
            no_timelock=not abi_flags["has_timelock"],
            no_emergency_stop=not abi_flags["has_pause"],
            no_key_rotation=not abi_flags["has_key_rotation"],
            signer_unrestricted=signer_unrestricted,
            agent_card_no_spend_limit=no_spend_limit,
        )
