"""Minimal, non-raising JSON-RPC client for B20 reads (stdlib only).

Design:
- chain_id is validated at construction (reject anything but 8453 / 84532).
- Every RPC call is NON-RAISING: any transport error, RPC-level error, or
  malformed response returns ``None`` so the reader can treat the value as
  "unknown / unrated" rather than crashing. The last failure is recorded in
  ``last_error`` for diagnostics, not propagated.
- One retry on transient (exception) failures before giving up.
- HTTP is stdlib ``urllib.request``; JSON is stdlib ``json``. No new deps.
- The transport is injectable (``_transport``) so tests never touch the network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

from .constants import CHAIN_RPC_ENDPOINTS

# Sent on every request. Public Base RPC endpoints sit behind Cloudflare, which
# rejects the default "Python-urllib/*" User-Agent with HTTP 403 (error 1010);
# a project-identifying UA is allowed through.
_USER_AGENT = "acp-sec-b20/0.1"

# A transport takes a JSON-RPC request payload and returns the parsed response
# dict, or raises on a transient/network failure.
Transport = Callable[[dict], dict]


def _default_transport(url: str, timeout: float) -> Transport:
    def call(payload: dict) -> dict:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    return call


class RpcClient:
    def __init__(
        self,
        chain_id: int,
        *,
        timeout: float = 10.0,
        _transport: Optional[Transport] = None,
    ) -> None:
        if chain_id not in CHAIN_RPC_ENDPOINTS:
            raise ValueError(
                f"unsupported chain_id {chain_id!r}; "
                f"expected one of {sorted(CHAIN_RPC_ENDPOINTS)}"
            )
        self.chain_id = chain_id
        self.url = CHAIN_RPC_ENDPOINTS[chain_id]
        self.timeout = timeout
        self._transport = _transport or _default_transport(self.url, timeout)
        self.last_error: Optional[str] = None
        # Connectivity signals (used by the CLI to tell "entirely unreachable"
        # apart from "reachable but every value unrated"). attempts counts logical
        # calls; any_response is True once the node returns anything at all (even
        # an RPC error response — that still proves the endpoint is reachable).
        self.attempts: int = 0
        self.any_response: bool = False

    def _rpc(self, method: str, params: list) -> Optional[Any]:
        self.attempts += 1
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        for _attempt in range(2):  # initial call + one retry on transient error
            try:
                resp = self._transport(payload)
            except urllib.error.HTTPError as exc:
                # The node answered with an HTTP error (e.g. 403/429/5xx). That
                # proves the endpoint is REACHABLE — the per-call result is still
                # a failure, but it is not "entirely unreachable", and retrying a
                # definitive HTTP status won't help, so stop here.
                self.any_response = True
                self.last_error = f"http error: {exc.code} {exc.reason}"
                return None
            except Exception as exc:  # noqa: BLE001 — transient; retry then None
                self.last_error = f"{type(exc).__name__}: {exc}"
                continue
            self.any_response = True
            if not isinstance(resp, dict):
                self.last_error = "malformed response (not an object)"
                return None
            if resp.get("error") is not None:
                self.last_error = f"rpc error: {resp['error']}"
                return None
            if "result" not in resp:
                self.last_error = "malformed response (no result)"
                return None
            self.last_error = None
            return resp["result"]
        return None

    def eth_call(self, to: str, data: str, block: str = "latest") -> Optional[str]:
        return self._rpc("eth_call", [{"to": to, "data": data}, block])

    def eth_get_code(self, addr: str, block: str = "latest") -> Optional[str]:
        return self._rpc("eth_getCode", [addr, block])

    def eth_get_logs(self, filter_obj: dict) -> Optional[list]:
        return self._rpc("eth_getLogs", [filter_obj])

    def eth_get_transaction_count(self, addr: str, block: str = "latest") -> Optional[str]:
        return self._rpc("eth_getTransactionCount", [addr, block])

    def eth_block_number(self) -> Optional[int]:
        """Latest block height as an int, or None on RPC failure."""
        res = self._rpc("eth_blockNumber", [])
        if res is None:
            return None
        try:
            return int(res, 16)
        except (ValueError, TypeError):
            return None
