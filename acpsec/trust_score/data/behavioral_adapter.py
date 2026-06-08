"""Behavioral adapter (Dimension 6) — on-chain Transfer event analysis.

Fetches eth_getLogs for Transfer-shaped events emitted by the contract over a
sliding block window.  topic[1] is treated as the from-address (counterparty);
topic[2] is treated as the to-address (used for burn/loss detection).

Injectable `_rpc` signature: (method: str, params: list) -> Any

Signals not derivable from raw JSON-RPC (dispute/failed-delivery rates) default
to 0.0 — they require a subgraph or off-chain job records.
"""

from __future__ import annotations

import json
import urllib.request
from collections import Counter
from typing import Any, Callable

from ..dimensions.behavioral import BehavioralInput

DEFAULT_RPC_URL = "https://mainnet.base.org"
_ZERO_TOPIC = "0x" + "0" * 64


def _default_rpc(rpc_url: str) -> Callable[[str, list], Any]:
    def call(method: str, params: list) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            rpc_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode())
        if "error" in payload:
            raise RuntimeError(f"rpc error: {payload['error']}")
        return payload.get("result")
    return call


class BehavioralAdapter:
    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        block_window: int = 10_000,
        _rpc: Callable[[str, list], Any] | None = None,
    ) -> None:
        self._rpc = _rpc or _default_rpc(rpc_url)
        self._block_window = block_window

    def fetch(self, address: str) -> BehavioralInput:
        try:
            return self._fetch(address)
        except Exception:
            return BehavioralInput()

    def _fetch(self, address: str) -> BehavioralInput:
        latest_hex = self._rpc("eth_blockNumber", [])
        latest = int(latest_hex, 16)
        from_block = max(0, latest - self._block_window)

        logs = self._rpc("eth_getLogs", [{
            "fromBlock": hex(from_block),
            "toBlock":   hex(latest),
            "address":   address,
        }]) or []

        # --- Counterparty diversity from topic[1] (from-address) ---
        caller_counts: Counter = Counter()
        fund_loss = False

        for log in logs:
            topics = log.get("topics", [])
            if len(topics) >= 2:
                caller_counts[topics[1]] += 1
            if len(topics) >= 3:
                to_topic = topics[2]
                if to_topic == _ZERO_TOPIC:
                    fund_loss = True

        counterparty_jobs = list(caller_counts.values())

        # --- Volume spike: recent quarter vs full window ---
        recent_window = self._block_window // 10
        recent_from = max(0, latest - recent_window)
        recent_logs = self._rpc("eth_getLogs", [{
            "fromBlock": hex(recent_from),
            "toBlock":   hex(latest),
            "address":   address,
        }]) or []

        total_count = len(logs)
        recent_count = len(recent_logs)
        # Spike: recent rate > 2× historical average rate over the same period
        if total_count > 0 and recent_window > 0:
            historical_rate = total_count / self._block_window
            recent_rate = recent_count / recent_window
            volume_spike = recent_rate > 2 * historical_rate
        else:
            volume_spike = False

        return BehavioralInput(
            fund_loss_incident=fund_loss,
            dispute_rate=0.0,
            failed_delivery_rate=0.0,
            counterparty_jobs=counterparty_jobs,
            volume_spike=volume_spike,
        )
