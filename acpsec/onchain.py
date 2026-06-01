"""
On-chain ACP registration check (v0.4.0).

Queries Base mainnet RPC for activity at the ACP Core contract address
(`0x238E541BfefD82238730D00a2208E5497F1832E0`) that mentions a given
wallet address as one of the indexed log topics.

This is intentionally a **best-effort** check:

  - The exact ACP Core ABI (registration method selector + event topic
    layout) is not pinned in this module.  We instead look for ANY logs
    emitted by the contract that include the wallet's 32-byte padded
    address as a topic — which catches every common pattern
    (Transfer/Approval-style events, custom Registered(address) events,
    etc.) without requiring an ABI.
  - If the RPC fails, or the wallet has no matching logs in the scanned
    block range, we return `registered=None` ("unknown") — never raise.

Callers should treat ``registered=None`` as "could not verify" and
``registered=False`` as "verified-not-found" only for the specific block
window scanned (default: last 50 000 blocks ≈ ~24h on Base).
"""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any, Optional, TypedDict

# v0.4.0 — Virtuals ACP Core on Base mainnet.
# Source: os.virtuals.io/acp/overview (user-provided in the v0.4.0 spec).
ACP_CORE_ADDRESS_BASE: str = "0x238E541BfefD82238730D00a2208E5497F1832E0"

# Public Base mainnet RPC.  No API key required.  Users can override via
# the BASE_RPC_URL environment variable for higher-rate endpoints.
DEFAULT_BASE_RPC_URL: str = "https://mainnet.base.org"

# How many recent blocks to scan when looking for the wallet in ACP logs.
# 50 000 blocks ≈ 24 hours on Base (~2s blocks).  Trades off completeness
# vs RPC latency; most providers also enforce a per-call log cap.
DEFAULT_LOG_BLOCK_RANGE: int = 50_000


_HEX40_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class ACPCheckResult(TypedDict, total=False):
    """Wire-format result for the ACP on-chain registration check."""
    contract: str
    wallet:   str
    rpc_url:  str
    registered: Optional[bool]   # True | False | None (unknown)
    log_count: int
    block_from: Optional[int]
    block_to:   Optional[int]
    error:     Optional[str]


def is_valid_eth_address(addr: str) -> bool:
    """Permissive 0x… 40-hex check.  No checksum validation."""
    return bool(_HEX40_RE.match(addr or ""))


def _padded_topic(addr: str) -> str:
    """Pad a 0x… address to a 32-byte log topic (left-zero-pad)."""
    return "0x" + addr.lower().removeprefix("0x").rjust(64, "0")


def _rpc(url: str, method: str, params: list, timeout: float = 8.0) -> Any:
    """One-shot JSON-RPC call.  Raises on network / decode errors."""
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    }).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    if "error" in payload:
        raise RuntimeError(f"rpc error: {payload['error']}")
    return payload.get("result")


def check_acp_registration(
    wallet_address: str,
    *,
    rpc_url: str | None = None,
    block_range: int = DEFAULT_LOG_BLOCK_RANGE,
) -> ACPCheckResult:
    """Best-effort check: has ``wallet_address`` appeared in any ACP-contract log?

    Returns a dict with ``registered`` set to:
      - True   → matching log found
      - False  → contract exists, no matching log in the scanned window
      - None   → RPC failed or wallet is malformed; check inconclusive

    Never raises.
    """
    out: ACPCheckResult = {
        "contract":   ACP_CORE_ADDRESS_BASE,
        "wallet":     wallet_address,
        "rpc_url":    rpc_url or DEFAULT_BASE_RPC_URL,
        "registered": None,
        "log_count":  0,
        "block_from": None,
        "block_to":   None,
        "error":      None,
    }

    if not is_valid_eth_address(wallet_address):
        out["error"] = "invalid wallet address (expected 0x… 40-hex)"
        return out

    rpc = rpc_url or DEFAULT_BASE_RPC_URL

    try:
        # 1. Get the latest block.
        latest_hex = _rpc(rpc, "eth_blockNumber", [])
        latest = int(latest_hex, 16)
        from_block = max(0, latest - block_range)
        out["block_from"] = from_block
        out["block_to"]   = latest

        # 2. Query logs where the contract is the emitter AND any topic
        #    contains the wallet's padded address.  We don't pin the topic
        #    index; we check every topic position via separate calls,
        #    short-circuiting on the first hit.
        topic_wallet = _padded_topic(wallet_address)
        # Pad on topic[1] is the dominant pattern (indexed first arg).
        # We also try topic[2] and topic[3] before giving up.
        for topic_idx in range(1, 4):
            topics: list[Any] = [None] * 4
            topics[topic_idx] = topic_wallet
            params = [{
                "fromBlock": hex(from_block),
                "toBlock":   hex(latest),
                "address":   ACP_CORE_ADDRESS_BASE,
                "topics":    topics[: topic_idx + 1],
            }]
            try:
                logs = _rpc(rpc, "eth_getLogs", params)
            except RuntimeError:
                continue   # provider may reject some topic queries; try next
            if isinstance(logs, list) and logs:
                out["registered"] = True
                out["log_count"]  = len(logs)
                return out

        out["registered"] = False
        return out

    except Exception as exc:  # noqa: BLE001 — never raise
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
