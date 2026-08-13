"""B20 Preflight: a point-in-time transfer-authorization verdict (read-only).

Answers "will this transfer clear, and if not, why?" for (token, from, to, amount)
over the Cobalt surface. Order matches MockB20Asset.transfer's verified revert
order so a verdict agrees with an eth_call simulation of the real transfer:

    activation gate  ->  pause  ->  sender policy  ->  receiver policy  ->  balance

The PolicyRegistry precompile's ``isAuthorized(uint64,address)`` is the evaluator —
composite (UNION/INTERSECT) logic is resolved on-chain, never reimplemented here.
Every read is non-raising; a failed read yields ``unavailable`` with a diagnostic,
NEVER a false ``allow``. The gate (``supportsInterface(0xa60bf13d)``) is only a
Cobalt PROXY: if it passes but a policy read then reverts, that is ``read_failed``,
not ``allow`` and not ``not_cobalt``.

See docs/b20-preflight-design-v1.md.
"""

from __future__ import annotations

from typing import Optional

from . import constants as C
from .models import PreflightReason, PreflightVerdict
from .reader import _decode_bool, _decode_uint, calldata, enc_address, enc_uint, word
from .rpc import RpcClient


# --- read helpers (all non-raising: None on any RPC failure / revert) ------
def _bytes4_word(hex_id: str) -> str:
    """A bytes4 ABI arg is LEFT-aligned in its 32-byte word (unlike a uint)."""
    h = hex_id[2:] if hex_id.startswith("0x") else hex_id
    return h.ljust(64, "0")


def _supports_interface(rpc, token: str, iface: str) -> Optional[bool]:
    return _decode_bool(
        rpc.eth_call(token, calldata(C.B20_SELECTOR_SUPPORTS_INTERFACE, _bytes4_word(iface)))
    )


def _is_paused_transfer(rpc, token: str) -> Optional[bool]:
    return _decode_bool(
        rpc.eth_call(token, calldata(C.B20_SELECTOR_IS_PAUSED, enc_uint(C.B20_PAUSABLE_TRANSFER)))
    )


def _policy_id(rpc, token: str, scope: str) -> Optional[int]:
    return _decode_uint(rpc.eth_call(token, calldata(C.B20_SELECTOR_POLICY_ID, word(scope))))


def _is_authorized(rpc, policy_id: int, account: str) -> Optional[bool]:
    # Called on the PolicyRegistry precompile, not the token.
    return _decode_bool(
        rpc.eth_call(
            C.POLICY_REGISTRY,
            calldata(C.B20_SELECTOR_IS_AUTHORIZED, enc_uint(policy_id), enc_address(account)),
        )
    )


def _balance_of(rpc, token: str, account: str) -> Optional[int]:
    return _decode_uint(rpc.eth_call(token, calldata(C.B20_SELECTOR_BALANCE_OF, enc_address(account))))


def _probe_definitively_reverted(rpc) -> bool:
    """True iff the activation probe failed because the chain gave a DEFINITIVE
    answer — execution reverted (this contract has no ERC-165) — rather than a
    TRANSPORT failure (timeout / 429 / unreachable node, where nothing answered).

    Uses only the signals ``RpcClient`` already records: it saw a response at all
    (``any_response``) AND the recorded error names a revert (``last_error``). A
    rate-limit or timeout sets ``last_error`` but the error is not a revert (429 is
    reachable but not a contract answer; a timeout leaves ``any_response`` False),
    so both correctly fall through to ``read_failed``. No new classification is
    invented here — see issue #41."""
    last_error = (getattr(rpc, "last_error", None) or "").lower()
    return bool(getattr(rpc, "any_response", False)) and "revert" in last_error


# --- verdict constructors --------------------------------------------------
def _unavailable(code: str, detail: str, as_of: Optional[int] = None) -> PreflightVerdict:
    return PreflightVerdict("unavailable", [PreflightReason(code, detail)], as_of, "unknown")


def _deny(deny_class: str, reason: PreflightReason, as_of: Optional[int]) -> PreflightVerdict:
    return PreflightVerdict("deny", [reason], as_of, "verified", deny_class=deny_class)


# --------------------------------------------------------------------------
def preflight(
    token: str, chain_id: int, from_addr: str, to_addr: str, amount: int, *, rpc=None
) -> PreflightVerdict:
    """Return the point-in-time verdict for transferring ``amount`` from ``from_addr``
    to ``to_addr`` of ``token`` on ``chain_id``. Pure over an injected ``rpc``."""
    if rpc is None:
        rpc = RpcClient(chain_id)

    # 0) Activation gate FIRST. (0xa60bf13d is only a Cobalt proxy.) A `false` gate
    #    is not_cobalt. A failed read splits by WHY it failed: a definitive revert —
    #    the chain answering "this contract has no ERC-165" — is not_cobalt (the
    #    mocks return false, but the real pre-Cobalt precompile REVERTS; see #41),
    #    whereas a transport failure (timeout/429/unreachable) is read_failed. Both
    #    stay `unavailable` — never a false allow.
    gate = _supports_interface(rpc, token, C.B20_IFACE_ERC8056)
    if gate is None:
        if _probe_definitively_reverted(rpc):
            return _unavailable(
                "not_cobalt",
                "activation probe reverted (no ERC-165) — Cobalt surface not active on this chain",
            )
        return _unavailable("read_failed", "activation probe (supportsInterface) read failed")
    if gate is False:
        return _unavailable("not_cobalt", "Cobalt surface not active on this chain")

    # 1) Block anchor for staleness (best-effort; None acceptable).
    as_of = rpc.eth_block_number()

    # 2) Pause — revert order: pause first. deny_class=state (transient).
    paused = _is_paused_transfer(rpc, token)
    if paused is None:
        return _unavailable("read_failed", "pause (isPaused) read failed", as_of)
    if paused is True:
        return _deny("state", PreflightReason("paused", "TRANSFER feature is paused", scope="TRANSFER"), as_of)

    # 3+4) Sender then receiver policy. policyId 0 = always-allow (no registry call).
    #      Gate-passed != policy-surface-live: a revert here is read_failed, not allow.
    #      deny_class=policy (structural — a blocklist/allowlist decision).
    for scope_name, scope_hash, subject in (
        ("TRANSFER_SENDER_POLICY", C.B20_POLICY_TRANSFER_SENDER, from_addr),
        ("TRANSFER_RECEIVER_POLICY", C.B20_POLICY_TRANSFER_RECEIVER, to_addr),
    ):
        pid = _policy_id(rpc, token, scope_hash)
        if pid is None:
            return _unavailable("read_failed", f"policyId({scope_name}) read failed", as_of)
        if pid == 0:
            continue
        authorized = _is_authorized(rpc, pid, subject)
        if authorized is None:
            return _unavailable("read_failed", f"isAuthorized({scope_name}) read failed", as_of)
        if authorized is False:
            return _deny(
                "policy",
                PreflightReason(
                    "policy_forbids",
                    f"{subject} not authorized under {scope_name} (policy {pid})",
                    scope=scope_name, policy_id=pid,
                ),
                as_of,
            )

    # 5) Balance — revert order: after policy. deny_class=balance (transient).
    bal = _balance_of(rpc, token, from_addr)
    if bal is None:
        return _unavailable("read_failed", "balanceOf(from) read failed", as_of)
    if bal < amount:
        return _deny(
            "balance",
            PreflightReason("insufficient_balance", f"balance {bal} < amount {amount}"),
            as_of,
        )

    # 6) Clear.
    return PreflightVerdict("allow", [], as_of, "verified")
