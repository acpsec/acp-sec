"""Minimal, non-raising JSON-RPC client for B20 reads (stdlib only).

Design:
- chain_id is validated at construction (reject anything but 8453 / 84532).
- The endpoint is per-chain and configurable: ``B20_RPC_URL_<chain_id>`` overrides
  the hardcoded public default (provider URLs embed API keys, so treat as secret).
  Zero-config == today's public endpoint; setting the var is the activation step.
- Every RPC call is NON-RAISING: any transport error, RPC-level error, or malformed
  response ultimately returns ``None`` so the reader treats the value as
  "unknown / unrated" rather than crashing. The last failure is recorded in
  ``last_error`` for diagnostics, not propagated.
- TRANSIENT failures (HTTP 429/5xx, timeouts/connection errors, JSON-RPC
  rate-limit error codes) are retried with BOUNDED exponential backoff
  (``_MAX_ATTEMPTS`` total, small base, per-sleep cap that also bounds any
  honored ``Retry-After``). DEFINITIVE answers — contract reverts, other 4xx,
  malformed responses — are DATA, not noise, and are never retried.
- HTTP is stdlib ``urllib.request``; JSON is stdlib ``json``. No new deps.
- The transport (``_transport``) and sleeper (``_sleep``) are injectable so tests
  never touch the network and never actually wait.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

from .constants import CHAIN_RPC_ENDPOINTS

# Sent on every request. Public Base RPC endpoints sit behind Cloudflare, which
# rejects the default "Python-urllib/*" User-Agent with HTTP 403 (error 1010);
# a project-identifying UA is allowed through.
_USER_AGENT = "acp-sec-b20/0.1"

# Bounded-backoff retry policy (transient failures only). Kept small: the scan
# endpoint is a synchronous HTTP call, so total added latency must stay bounded.
_MAX_ATTEMPTS = 3          # initial call + up to 2 retries
_BACKOFF_BASE = 0.25       # seconds; exponential: 0.25, 0.5, ...
_BACKOFF_CAP = 1.0         # per-sleep ceiling — also caps any honored Retry-After

# JSON-RPC error codes that mean "rate limited / try again", not a definitive
# answer. Kept deliberately narrow; a message-substring check catches the rest.
_TRANSIENT_RPC_ERROR_CODES = frozenset({-32005})
_RATE_LIMIT_MSG_HINTS = ("rate limit", "too many requests", "limit exceeded", "capacity")

# A transport takes a JSON-RPC request payload and returns the parsed response
# dict, or raises on a transient/network failure.
Transport = Callable[[dict], dict]


def resolve_rpc_endpoint(chain_id: int) -> str:
    """Per-chain RPC URL: ``B20_RPC_URL_<chain_id>`` if set, else the public default.

    Zero-config returns exactly today's hardcoded endpoint, so enabling a provider
    is purely a deploy-time env change (no code change, safe to ship first).
    """
    override = os.environ.get(f"B20_RPC_URL_{chain_id}", "").strip()
    return override or CHAIN_RPC_ENDPOINTS[chain_id]


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


def _retry_after_seconds(exc: urllib.error.HTTPError) -> Optional[float]:
    """The ``Retry-After`` header in seconds, or None (absent / HTTP-date form)."""
    try:
        raw = exc.headers.get("Retry-After") if exc.headers is not None else None
    except Exception:  # noqa: BLE001 — header access is best-effort
        return None
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return None  # HTTP-date form — ignore; the per-sleep cap bounds us anyway


def _is_transient_rpc_error(err: Any) -> bool:
    """True for a JSON-RPC error that is a rate-limit (retry), False for a
    definitive answer like a contract revert or invalid params (never retry)."""
    if not isinstance(err, dict):
        return False
    if err.get("code") in _TRANSIENT_RPC_ERROR_CODES:
        return True
    msg = str(err.get("message", "")).lower()
    return any(hint in msg for hint in _RATE_LIMIT_MSG_HINTS)


def _backoff_delay(attempt: int, retry_after: Optional[float]) -> float:
    """Exponential backoff for ``attempt`` (1-based), honoring Retry-After if it
    is larger, then capped at ``_BACKOFF_CAP`` to keep total latency bounded."""
    delay = _BACKOFF_BASE * (2 ** (attempt - 1))
    if retry_after is not None:
        delay = max(delay, retry_after)
    return min(delay, _BACKOFF_CAP)


class RpcClient:
    def __init__(
        self,
        chain_id: int,
        *,
        timeout: float = 10.0,
        _transport: Optional[Transport] = None,
        _sleep: Optional[Callable[[float], None]] = None,
    ) -> None:
        if chain_id not in CHAIN_RPC_ENDPOINTS:
            raise ValueError(
                f"unsupported chain_id {chain_id!r}; "
                f"expected one of {sorted(CHAIN_RPC_ENDPOINTS)}"
            )
        self.chain_id = chain_id
        self.url = resolve_rpc_endpoint(chain_id)
        self.timeout = timeout
        self._transport = _transport or _default_transport(self.url, timeout)
        self._sleep = _sleep or time.sleep
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
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            retry_after: Optional[float] = None
            try:
                resp = self._transport(payload)
            except urllib.error.HTTPError as exc:
                # The node answered with an HTTP status — REACHABLE. 429/5xx are
                # transient (retry); other 4xx are definitive (data, not noise).
                self.any_response = True
                self.last_error = f"http error: {exc.code} {exc.reason}"
                if not (exc.code == 429 or 500 <= exc.code < 600):
                    return None
                retry_after = _retry_after_seconds(exc)
            except Exception as exc:  # noqa: BLE001 — timeout/DNS/connection = transient
                self.last_error = f"{type(exc).__name__}: {exc}"
            else:
                self.any_response = True
                if not isinstance(resp, dict):
                    self.last_error = "malformed response (not an object)"
                    return None
                err = resp.get("error")
                if err is not None:
                    self.last_error = f"rpc error: {err}"
                    if not _is_transient_rpc_error(err):
                        return None  # revert / invalid params — definitive
                    # transient rate-limit RPC error → fall through to backoff
                elif "result" not in resp:
                    self.last_error = "malformed response (no result)"
                    return None
                else:
                    self.last_error = None
                    return resp["result"]
            # Reached only on a TRANSIENT failure — back off (bounded) and retry.
            if attempt < _MAX_ATTEMPTS:
                self._sleep(_backoff_delay(attempt, retry_after))
        return None  # transient retries exhausted — honest failure, never a mask

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
