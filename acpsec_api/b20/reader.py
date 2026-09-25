"""B20 token reader: read-only on-chain reads -> ScanInputs.

Reworked against the real B20 interface (base/base-std, see docs/reader-rework-v7.md):
- Activation gate + isB20/isB20Initialized preflight before any reads.
- Variant decoded from the token address byte[10] (no eth_call).
- Role holders reconstructed from RoleGranted/RoleRevoked logs (B20 has no
  role-member enumeration), via a chunked getLogs helper (range-capped RPCs).
- Transfer-policy facts derived from policyId(scope) and role presence.

Every read degrades to None on RPC failure so the engine marks the dimension
unrated. read_token raises ``B20Unavailable`` only for DEFINITIVE negatives
(not a B20 token / not initialized / feature not activated); unknowns proceed.
"""

from __future__ import annotations

import os
import re
import time
from typing import Optional

from . import constants as C
from .models import (
    AnnouncementEvidence,
    EventEvidence,
    RoleHolderEvidence,
    ScanInputs,
    StateEvidence,
)
from .rpc import RANGE_CAP_KIND, RpcClient

_WAD = 10**18  # multiplier precision; multiplier() != WAD means rebasing active

# Per-chain getLogs block-range cap (public RPC limits): Sepolia 2000, mainnet 10000.
# The fallback chunk walk uses resolve_getlogs_chunk() so a provider that allows
# wider ranges (e.g. Coinbase CDP: 100000) can override this per chain via env.
_LOG_BLOCK_CHUNK = {8453: 10000, 84532: 2000}


def resolve_getlogs_chunk(chain_id: int) -> int:
    """Fallback chunk size (blocks) for the range-cap chunk walk.

    ``B20_GETLOGS_CHUNK_<chain_id>`` (a positive int) overrides the public-endpoint
    default in ``_LOG_BLOCK_CHUNK``. Zero-config == today's sizes; set it to a
    provider's own getLogs range cap (e.g. Coinbase CDP's 100000) so the fallback
    walks in far fewer, wider windows. A missing / non-integer / non-positive value
    falls back to the default. Mirrors ``rpc.resolve_rpc_endpoint``'s per-chain env.
    """
    raw = os.environ.get(f"B20_GETLOGS_CHUNK_{chain_id}", "").strip()
    if raw:
        try:
            n = int(raw)
        except ValueError:
            n = 0
        if n > 0:
            return n
    return _LOG_BLOCK_CHUNK.get(chain_id, 2000)

_VARIANT_BY_BYTE = {0: "ASSET", 1: "STABLECOIN"}


class B20Unavailable(Exception):
    """Raised when a target is definitively not a scannable B20 token: not a B20
    address, not initialized, or the feature is not activated on this chain."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# --------------------------------------------------------------------------
# ABI encode/decode helpers (standard EVM ABI; each static arg is a 32-byte word)
# --------------------------------------------------------------------------
def word(hex32: str) -> str:
    h = hex32[2:] if hex32.startswith("0x") else hex32
    return h.lower().rjust(64, "0")


def enc_uint(n: int) -> str:
    return format(n, "064x")


def enc_address(addr: str) -> str:
    h = addr[2:] if addr.startswith("0x") else addr
    return h.lower().rjust(64, "0")


def calldata(selector: str, *words: str) -> str:
    return selector + "".join(words)


def _decode_bool(hexdata: Optional[str]) -> Optional[bool]:
    if not hexdata or hexdata == "0x":
        return None
    try:
        return int(hexdata, 16) != 0
    except ValueError:
        return None


def _decode_uint(hexdata: Optional[str]) -> Optional[int]:
    if not hexdata or hexdata == "0x":
        return None
    try:
        return int(hexdata, 16)
    except ValueError:
        return None


def _decode_address(hexdata: Optional[str]) -> Optional[str]:
    if not hexdata or hexdata == "0x":
        return None
    h = hexdata[2:] if hexdata.startswith("0x") else hexdata
    if len(h) < 40:
        return None
    return "0x" + h[-40:].lower()


def _decode_string(hexdata: Optional[str]) -> Optional[str]:
    """Standard ABI dynamic string (offset word, length word, utf-8 data)."""
    if not hexdata or hexdata == "0x":
        return None
    h = hexdata[2:] if hexdata.startswith("0x") else hexdata
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return None
    if len(raw) < 64:
        return None
    offset = int.from_bytes(raw[0:32], "big")
    if offset + 32 > len(raw):
        return None
    length = int.from_bytes(raw[offset:offset + 32], "big")
    data = raw[offset + 32:offset + 32 + length]
    if len(data) < length:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


# EIP-7702 delegation designator. Post-Cobalt (native AA) an EOA can delegate to a
# smart-account impl; eth_getCode then returns ``0xef0100 || <20-byte delegate>``
# (23 bytes) instead of ``0x``. It is STILL one key — the EOA can re-delegate or
# clear it at will — so it must be classified as an EOA, never a contract/multisig.
_EIP7702_PREFIX = "ef0100"


def _delegation_target(code: Optional[str]) -> Optional[str]:
    """The delegate address of an EIP-7702 designator (``0xef0100||addr``), else None.
    Pure — no RPC. None for empty code, plain bytecode, or a malformed designator."""
    if not code:
        return None
    h = code[2:] if code.startswith("0x") else code
    if h.lower().startswith(_EIP7702_PREFIX) and len(h) == len(_EIP7702_PREFIX) + 40:
        return "0x" + h[len(_EIP7702_PREFIX):]
    return None


def _is_contract(rpc, addr: str) -> Optional[bool]:
    """True if the address is a contract, False if an EOA, None if unreadable.

    An EIP-7702 delegated EOA (code ``0xef0100||addr``) is an EOA — a single key —
    NOT a contract: treating its designator as "has code" was the false-multisig bug
    (a delegated admin/deploy key read as ``admin_is_multisig=True``, suppressing the
    single-EOA-admin critical and hiding a bare mint key). Valid for holder addresses
    — they are ordinary accounts, not the B20 token precompile."""
    code = rpc.eth_get_code(addr)
    if code is None:
        return None
    if _delegation_target(code) is not None:
        return False
    return code not in ("0x", "0x0") and len(code) > 2


# Backoff (seconds) before metadata-read retry attempts 2 and 3. Overridable in tests.
_METADATA_BACKOFF: tuple[float, ...] = (0.2, 0.5)

# Per-chunk retry for the getLogs chunk walk: a transient (non-range-cap) chunk
# failure is retried before aborting, so one flaky chunk doesn't discard a long walk
# (NVDAc had ~20 chunks; one timed out and killed the whole role read). Overridable in tests.
_GETLOGS_CHUNK_ATTEMPTS: int = 3
_GETLOGS_CHUNK_BACKOFF: tuple[float, ...] = (0.3, 0.8)


def _read_metadata_string(rpc, token: str, selector: str) -> Optional[str]:
    """Read a metadata string (name/symbol) with bounded retries + short backoff.

    These reads are LOAD-BEARING for the #66 impersonation check, so a rate-limited
    RPC dropping a single eth_call must not silently disable the defense. Retries the
    METADATA read ONLY (never getLogs). Returns None only after all attempts fail —
    the caller then records a read_diagnostics entry and leaves the verdict None
    (never guesses). Attempts = len(_METADATA_BACKOFF) + 1.
    """
    for i in range(len(_METADATA_BACKOFF) + 1):
        if i:
            time.sleep(_METADATA_BACKOFF[i - 1])
        try:
            value = _decode_string(rpc.eth_call(token, calldata(selector)))
        except Exception:
            value = None
        if value is not None:
            return value
    return None


def _has_role(rpc, token: str, role: str, holder: str) -> Optional[bool]:
    return _decode_bool(rpc.eth_call(token, calldata(C.B20_SELECTOR_HAS_ROLE, word(role), enc_address(holder))))


# --------------------------------------------------------------------------
# Variant (decoded from address byte[10] — no RPC)
# --------------------------------------------------------------------------
def decode_variant(address: str) -> Optional[str]:
    """ASSET (byte[10]==0x00) / STABLECOIN (0x01) / None. Requires the 0xb2 prefix."""
    h = address[2:] if address.startswith("0x") else address
    if len(h) != 40 or h[:2].lower() != "b2":
        return None
    try:
        return _VARIANT_BY_BYTE.get(int(h[20:22], 16))
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Preflight: activation gate + isB20 / isB20Initialized
# --------------------------------------------------------------------------
def is_activated(rpc, variant: Optional[str]) -> Optional[bool]:
    feature = {
        "ASSET": C.B20_FEATURE_ASSET,
        "STABLECOIN": C.B20_FEATURE_STABLECOIN,
    }.get(variant or "")
    if feature is None:
        return None
    return _decode_bool(
        rpc.eth_call(C.ACTIVATION_REGISTRY, calldata(C.B20_SELECTOR_IS_ACTIVATED, word(feature)))
    )


def factory_is_b20(rpc, token: str, chain_id: int) -> Optional[bool]:
    fac = C.OFFICIAL_FACTORY_ADDRESS.get(chain_id)
    if fac is None:
        return None
    return _decode_bool(rpc.eth_call(fac, calldata(C.B20_SELECTOR_IS_B20, enc_address(token))))


def factory_is_b20_initialized(rpc, token: str, chain_id: int) -> Optional[bool]:
    fac = C.OFFICIAL_FACTORY_ADDRESS.get(chain_id)
    if fac is None:
        return None
    return _decode_bool(
        rpc.eth_call(fac, calldata(C.B20_SELECTOR_IS_B20_INITIALIZED, enc_address(token)))
    )


# --------------------------------------------------------------------------
# Chunked getLogs + role-holder reconstruction via event replay
# --------------------------------------------------------------------------
def _get_logs_full_or_chunked(
    rpc, address: str, topics: list, chain_id: int, from_block: int = 0
) -> Optional[list]:
    """Aggregate eth_getLogs over [from_block, latest], provider-agnostically.

    Attempt the WHOLE range in ONE query first — the cheapest path on a provider
    that allows it (a single token's role/announcement events are tiny). Only if
    the provider REJECTS the range with a classified range/size cap
    (``rpc.last_error_kind == RANGE_CAP_KIND``: e.g. public base.org's 2000/10000
    block cap, or Alchemy's block-range / response-size limits) do we fall back to
    the fixed per-chain chunk walk. Any OTHER failure — or a chunk that still fails
    — degrades to None (carrying ``rpc.last_error`` / ``last_error_kind``). No
    adaptive halving, no retry budget: a hard 10-block-cap provider simply yields
    an honest None rather than a chunk storm.

    NOTE: from_block defaults to 0; live use starts from the token's creation block
    to avoid scanning all of history.
    """
    latest = rpc.eth_block_number()
    if latest is None:
        return None

    def query(start: int, end: int) -> Optional[list]:
        return rpc.eth_get_logs({
            "address": address,
            "topics": topics,
            "fromBlock": hex(start),
            "toBlock": hex(end),
        })

    # 1) One full-range query first — the cheapest path on a provider that permits
    # it (ungated / small span).
    full = query(from_block, latest)
    if full is not None:
        return full
    # The full-range query FAILED for ANY reason (range cap, timeout, oversized,
    # transient). Fall back to the chunk walk — gating this on RANGE_CAP_KIND only was
    # the bug: NVDAc's ~2M-block full-range query TIMED OUT (last_error_kind != range
    # cap) and dead-ended here instead of chunking, leaving roles unread.

    # 2) Chunk walk (per-chain size, env-overridable via B20_GETLOGS_CHUNK_<chain_id>).
    # Each chunk is RETRIED on a transient failure (timeout / 429) with short backoff —
    # a long walk (NVDAc: ~20 chunks) must not be discarded because ONE chunk flaked
    # (that was masking the whole read). A chunk that RANGE-CAPS is definitive (chunk
    # still too big for the provider) -> stop; retries exhausted -> honest None.
    size = resolve_getlogs_chunk(chain_id)
    out: list = []
    start = from_block
    while start <= latest:
        end = min(start + size - 1, latest)
        chunk = None
        for attempt in range(_GETLOGS_CHUNK_ATTEMPTS):
            if attempt:
                time.sleep(_GETLOGS_CHUNK_BACKOFF[min(attempt - 1, len(_GETLOGS_CHUNK_BACKOFF) - 1)])
            chunk = query(start, end)
            if chunk is not None:
                break
            if getattr(rpc, "last_error_kind", None) == RANGE_CAP_KIND:
                return None   # chunk still range-capped -> definitive, whole walk doomed
        if chunk is None:
            return None       # transient failures exhausted -> honest None (last_error carried)
        out.extend(chunk)
        start = end + 1
    return out


def get_creation_block(rpc, token: str, chain_id: int) -> Optional[int]:
    """Block at which ``token`` was created, used to bound the role/announcement
    scans to [creation, latest] instead of all of chain history.

    Two-phase strategy:
      1. PRIMARY — binary-search the first block at which the token has bytecode
         (~log2(height) eth_getCode calls). Cheap and exact on an ARCHIVE node.
      2. FALLBACK — when the binary search dead-ends (a non-archive provider that
         cannot serve getCode-by-block), read the factory's ``B20Created`` log,
         filtered by the indexed token, in one getLogs. This keeps aged tokens
         rateable on non-archive providers instead of collapsing to a recent-window
         miss (which wrongly UNRATES issuer_authority).
    Returns None only when BOTH phases fail (token never deployed / reads fail); the
    caller then degrades to a bounded recent window.
    """
    latest = rpc.eth_block_number()
    if latest is None:
        return None
    cb = _creation_block_via_getcode(rpc, token, latest)
    if cb is not None:
        return cb
    # Fallback: the factory's B20Created log, filtered by the indexed token address.
    # The getCode binary search needs an ARCHIVE node (getCode-by-block); a non-archive
    # provider makes it dead-end, which on an AGED token collapses the role scan to a
    # recent-window miss (issuer_authority wrongly UNRATED). The B20Created event is
    # emitted once at creation and indexed by token, so a single filtered getLogs
    # recovers the exact creation block without archive getCode.
    return _creation_block_from_factory(rpc, token, chain_id)


def _creation_block_via_getcode(rpc, token: str, latest: int) -> Optional[int]:
    """Binary-search the first block at which ``token`` has code (~log2(height)
    eth_getCode calls). None if the token has no code now or any read fails —
    including the non-archive case (getCode-by-block unsupported)."""
    code_now = rpc.eth_get_code(token, "latest")
    if code_now is None or code_now in ("0x", "0x0"):
        return None
    lo, hi = 0, latest
    while lo < hi:  # invariant: token has code at hi, not before lo
        mid = (lo + hi) // 2
        code = rpc.eth_get_code(token, hex(mid))
        if code is None:  # RPC failure mid-search (e.g. non-archive) — fall through
            return None
        if code in ("0x", "0x0"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def _creation_block_from_factory(rpc, token: str, chain_id: int) -> Optional[int]:
    """Creation block from the factory's ``B20Created(address indexed token, ...)`` log,
    filtered by the indexed token. None if the factory is unknown, no matching log
    exists, or the read fails. Provider-agnostic (getLogs, no archive getCode)."""
    factory = C.OFFICIAL_FACTORY_ADDRESS.get(chain_id)
    if factory is None:
        return None
    topics = [C.B20_EVENT_B20_CREATED, "0x" + enc_address(token)]
    logs = _get_logs_full_or_chunked(rpc, factory, topics, chain_id)
    if not logs:
        return None
    blocks = [int(lg["blockNumber"], 16) for lg in logs if lg.get("blockNumber")]
    return min(blocks) if blocks else None


def role_holders_detailed(
    rpc, token: str, role: str, chain_id: int, from_block: int = 0
) -> tuple[Optional[list[str]], Optional[str]]:
    """Replay RoleGranted/RoleRevoked logs -> (current holders, first grantee).

    ``holders`` is None on RPC failure, [] when no holders remain. ``first_grantee``
    is the account of the earliest RoleGranted event in range (the historical
    original grantee — e.g. the deployer for DEFAULT_ADMIN), or None if the fetch
    failed or no grant event exists. Both come from a SINGLE getLogs replay, so a
    caller needing the fallback pays no extra RPC.

    ``from_block`` bounds the scan; read_token passes the token's creation block.
    """
    topics = [[C.B20_EVENT_ROLE_GRANTED, C.B20_EVENT_ROLE_REVOKED], role]
    logs = _get_logs_full_or_chunked(rpc, token, topics, chain_id, from_block=from_block)
    if logs is None:
        return None, None
    logs.sort(key=lambda lg: (int(lg["blockNumber"], 16), int(lg.get("logIndex", "0x0"), 16)))
    holders: list[str] = []
    first_grantee: Optional[str] = None
    granted = C.B20_EVENT_ROLE_GRANTED.lower()
    revoked = C.B20_EVENT_ROLE_REVOKED.lower()
    for lg in logs:
        topic_list = lg.get("topics", [])
        if len(topic_list) < 3:
            continue
        acct = _decode_address(topic_list[2])
        if acct is None:
            continue
        ev = topic_list[0].lower()
        if ev == granted:
            if first_grantee is None:
                first_grantee = acct
            if acct not in holders:
                holders.append(acct)
        elif ev == revoked and acct in holders:
            holders.remove(acct)
    return holders, first_grantee


def role_holders(rpc, token: str, role: str, chain_id: int, from_block: int = 0) -> Optional[list[str]]:
    """Current holders of ``role`` (net of grants/revokes). None on RPC failure;
    [] when no holders remain. Thin wrapper over ``role_holders_detailed``.
    """
    holders, _ = role_holders_detailed(rpc, token, role, chain_id, from_block)
    return holders


def _range_cap_reason(rpc, what: str) -> Optional[str]:
    """A human diagnostic if the last aggregated getLogs was rejected by a provider
    range/size cap, else None. Read IMMEDIATELY after the failing aggregation (before
    any later RPC overwrites ``last_error_kind``). Carries the provider string
    verbatim so the limit is diagnosable from the scan, not the provider dashboard.
    """
    if getattr(rpc, "last_error_kind", None) != RANGE_CAP_KIND:
        return None
    return f"{what} unavailable: provider getLogs range cap. {getattr(rpc, 'last_error', None)}"


def _read_fail_reason(rpc, what: str) -> Optional[str]:
    """Human reason an aggregated getLogs failed: the provider range-cap string when it
    was a classified range cap, else the VERBATIM ``last_error`` (timeout / 429 / etc.).
    Never discards the reason — the caller records it so the scan SAYS why the read
    failed instead of the generic Layer-B "no read diagnostic recorded" (NVDAc gap)."""
    cap = _range_cap_reason(rpc, what)
    if cap:
        return cap
    err = getattr(rpc, "last_error", None)
    return f"{what} failed: {err}" if err else f"{what} unavailable (no data from RPC)"


def role_holders_all(
    rpc, token: str, chain_id: int, from_block: int = 0
) -> Optional[dict[str, tuple[list[str], Optional[str], dict]]]:
    """ALL roles from ONE merged getLogs → {role_hash_lower: (holders, first_grantee, holder_grants)}.

    topic0 in [RoleGranted, RoleRevoked] with NO role filter, demuxed client-side by
    topics[1] (the indexed role) / topics[2] (the indexed account). Cuts the five
    per-role replays to a single query while keeping identical per-role semantics.
    None on RPC failure. A role ABSENT from the returned dict simply had no events
    in range (its holders are known-empty); the caller maps that to ([], None, {}).
    ``holders`` is net of grants/revokes; ``first_grantee`` is the earliest RoleGranted
    account; ``holder_grants`` maps each current holder to (tx_hash, block_number,
    log_index) of the grant event that established their current hold.
    """
    topics = [[C.B20_EVENT_ROLE_GRANTED, C.B20_EVENT_ROLE_REVOKED]]
    logs = _get_logs_full_or_chunked(rpc, token, topics, chain_id, from_block=from_block)
    if logs is None:
        return None
    logs.sort(key=lambda lg: (int(lg["blockNumber"], 16), int(lg.get("logIndex", "0x0"), 16)))
    granted = C.B20_EVENT_ROLE_GRANTED.lower()
    revoked = C.B20_EVENT_ROLE_REVOKED.lower()
    by_role: dict[str, tuple[list[str], Optional[str], dict]] = {}
    for lg in logs:
        tl = lg.get("topics", [])
        if len(tl) < 3:
            continue
        role = str(tl[1]).lower()
        acct = _decode_address(tl[2])
        if acct is None:
            continue
        holders, first, holder_grants = by_role.get(role, ([], None, {}))
        ev = str(tl[0]).lower()
        if ev == granted:
            if first is None:
                first = acct
            if acct not in holders:
                holders.append(acct)
            holder_grants[acct] = (
                lg.get("transactionHash"),
                int(lg["blockNumber"], 16),
                int(lg.get("logIndex", "0x0"), 16),
            )
        elif ev == revoked and acct in holders:
            holders.remove(acct)
            holder_grants.pop(acct, None)
        by_role[role] = (holders, first, holder_grants)
    return by_role


# Surfaced (via read_diagnostics) when a role replay SUCCEEDS but observed NO grant
# events — B20 tokens don't emit RoleGranted/RoleRevoked, so an empty replay is not
# proof of revocation (issue #34). The affected dimensions go UNRATED, not clean.
ROLE_NOT_DETERMINABLE = (
    "role holders not determinable from logs for this token "
    "(no RoleGranted/RoleRevoked events observed; an empty replay is not proof of revocation)"
)


def read_roles(rpc, token: str, chain_id: int, from_block: int = 0, *, as_of_block: Optional[int] = None) -> dict:
    # ONE merged getLogs for every role (topic0 [Granted,Revoked], no role filter),
    # demuxed client-side — 1 query instead of 5, identical per-role semantics. The
    # DEFAULT_ADMIN first grantee (origin issuer-proxy fallback for fully-revoked
    # admins) comes from the same replay.
    all_roles = role_holders_all(rpc, token, chain_id, from_block)
    read_error = _read_fail_reason(rpc, "Role reads") if all_roles is None else None

    def detailed(role_hash: str) -> tuple[Optional[list[str]], Optional[str], dict]:
        if all_roles is None:      # merged read failed -> every role unknown
            return None, None, {}
        return all_roles.get(role_hash.lower(), ([], None, {}))  # absent -> known-empty

    def _build_role_ev(role_hash: str, holders: Optional[list[str]], holder_grants: dict) -> list:
        if not holders:
            return []
        role_name = C.ROLE_NAMES.get(role_hash.lower())
        result = []
        for h in holders:
            grant_info = holder_grants.get(h)
            grant_ev = None
            if grant_info:
                tx, blk, li = grant_info
                grant_ev = EventEvidence(tx_hash=tx, block_number=blk, log_index=li)
            confirmed_raw = _has_role(rpc, token, role_hash, h)
            has_role_ev = None
            discrepancy = False
            if confirmed_raw is not None:
                has_role_ev = StateEvidence(block_number=as_of_block, confirmed=confirmed_raw)
                if not confirmed_raw:
                    discrepancy = True
            result.append(RoleHolderEvidence(
                address=h, grant=grant_ev, has_role=has_role_ev,
                discrepancy=discrepancy, role_name=role_name,
            ))
        return result

    admin, admin_first_grantee, admin_grants = detailed(C.B20_ROLE_DEFAULT_ADMIN)
    mint_holders, mint_first, mint_grants = detailed(C.B20_ROLE_MINT)
    burn, burn_first, burn_grants = detailed(C.B20_ROLE_BURN)
    burn_blocked, burn_blocked_first, burn_blocked_grants = detailed(C.B20_ROLE_BURN_BLOCKED)
    seize, seize_first, seize_grants = detailed(C.B20_ROLE_SEIZE)
    pause, pause_first, pause_grants = detailed(C.B20_ROLE_PAUSE)

    role_evidence: dict[str, list] = {}
    for role_hash, holders, grants in [
        (C.B20_ROLE_DEFAULT_ADMIN, admin, admin_grants),
        (C.B20_ROLE_MINT, mint_holders, mint_grants),
        (C.B20_ROLE_BURN, burn, burn_grants),
        (C.B20_ROLE_BURN_BLOCKED, burn_blocked, burn_blocked_grants),
        (C.B20_ROLE_SEIZE, seize, seize_grants),
        (C.B20_ROLE_PAUSE, pause, pause_grants),
    ]:
        ev_list = _build_role_ev(role_hash, holders, grants)
        if ev_list:
            role_evidence[role_hash.lower()] = ev_list

    return {
        "admin": admin,
        "admin_first_grantee": admin_first_grantee,
        "mint": mint_holders,
        "burn": burn,
        # burn_blocked: the DEPRECATED blocked-burn role. It no longer feeds
        # can_seize — that is SEIZE_ROLE now (#37). Retained as a demuxed signal
        # (free from the same merged getLogs) pending a decision on its fate
        # (drop, or surface blocked-burn as its own capability).
        "burn_blocked": burn_blocked,
        "seize": seize,        # the real seize power (gates seizeWithMemo/Seized)
        "pause": pause,
        # Per-role "was a grant EVER observed?" (first_grantee is not None) —
        # distinguishes never-granted (unknown; B20 emits no role events) from
        # granted-then-revoked (KNOWN-absent). Consumed by read_token's tri-state.
        "granted_ever": {
            "admin": admin_first_grantee is not None,
            "burn": burn_first is not None,
            "burn_blocked": burn_blocked_first is not None,
            "seize": seize_first is not None,
            "pause": pause_first is not None,
        },
        "read_error": read_error,
        "role_evidence": role_evidence,
    }


def _classify_multisig(rpc, holders: Optional[list[str]]) -> Optional[bool]:
    if holders is None or len(holders) == 0:
        return None
    flags = [_is_contract(rpc, h) for h in holders]
    if any(f is True for f in flags):
        return True
    if all(f is False for f in flags):
        return False
    return None


def _classify_delegated_eoa(rpc, holders: Optional[list[str]]) -> Optional[bool]:
    """True if ANY holder is an EIP-7702 delegated EOA (honest surfacing: "still one
    key, but with smart-account delegation"). False if all readable and none
    delegated; None if holders None/empty or every code read failed."""
    if not holders:
        return None
    any_known = False
    for h in holders:
        code = rpc.eth_get_code(h)
        if code is None:
            continue
        any_known = True
        if _delegation_target(code) is not None:
            return True
    return False if any_known else None


def _classify_mint_eoa(rpc, holders: Optional[list[str]]) -> Optional[list[str]]:
    """#69: the subset of mint holders that are non-multisig EOAs (bare keys),
    via eth_getCode. Tri-state, honest about unknowns:
      None -> nothing to classify (holders None/empty) OR none was classifiable
              (every eth_getCode read failed) — never falsely reported as "all
              contracts";
      []   -> holders readable and ALL are contracts (no bare EOA key);
      [..] -> these holders are bare EOAs.
    A holder whose code read fails is skipped (not asserted an EOA)."""
    if not holders:
        return None
    eoa: list[str] = []
    any_known = False
    for h in holders:
        c = _is_contract(rpc, h)
        if c is None:              # unreadable — don't assert EOA-ness
            continue
        any_known = True
        if c is False:
            eoa.append(h)
    return eoa if any_known else None


# --------------------------------------------------------------------------
# Supply integrity
# --------------------------------------------------------------------------
def read_supply(rpc, token: str, variant: Optional[str]) -> dict:
    supply_cap = _decode_uint(rpc.eth_call(token, calldata(C.B20_SELECTOR_SUPPLY_CAP)))
    multiplier_active: Optional[bool] = None
    if variant == "ASSET":  # multiplier()/rebasing is an Asset-only feature
        m = _decode_uint(rpc.eth_call(token, calldata(C.B20_SELECTOR_MULTIPLIER)))
        multiplier_active = (m != _WAD) if m is not None else None
    return {"supply_cap": supply_cap, "multiplier_active": multiplier_active}


# --------------------------------------------------------------------------
# Transfer policy (policyId-based)
# --------------------------------------------------------------------------
def _policy_id(rpc, token: str, scope: str) -> Optional[int]:
    return _decode_uint(rpc.eth_call(token, calldata(C.B20_SELECTOR_POLICY_ID, word(scope))))


def read_transfer_policy(rpc, token: str) -> dict:
    sender = _policy_id(rpc, token, C.B20_POLICY_TRANSFER_SENDER)
    receiver = _policy_id(rpc, token, C.B20_POLICY_TRANSFER_RECEIVER)
    executor = _policy_id(rpc, token, C.B20_POLICY_TRANSFER_EXECUTOR)
    mint_receiver = _policy_id(rpc, token, C.B20_POLICY_MINT_RECEIVER)

    can_freeze = (sender != 0) if sender is not None else None

    if sender is not None and receiver is not None:
        asymmetric = (sender != 0) != (receiver != 0)
    else:
        asymmetric = None

    known = [p for p in (sender, receiver, executor, mint_receiver) if p is not None]
    if any(p != 0 for p in known):
        policy_registry_active: Optional[bool] = True
    elif known:
        policy_registry_active = False
    else:
        policy_registry_active = None

    is_paused = _decode_bool(
        rpc.eth_call(token, calldata(C.B20_SELECTOR_IS_PAUSED, enc_uint(C.B20_PAUSABLE_TRANSFER)))
    )
    return {
        "policy_registry_active": policy_registry_active,
        "can_freeze": can_freeze,
        "is_paused": is_paused,
        "asymmetric_policy": asymmetric,
    }


# --------------------------------------------------------------------------
# Variant & config
# --------------------------------------------------------------------------
def read_variant_config(rpc, token: str, variant: Optional[str]) -> dict:
    decimals = _decode_uint(rpc.eth_call(token, calldata(C.B20_SELECTOR_DECIMALS)))
    # name()/symbol() are IB20 (all variants) — read unconditionally (#66 gap fix),
    # WITH retries: symbol() is load-bearing for the impersonation defense, so a
    # rate-limited RPC dropping one eth_call must not silently disable the check.
    name = _read_metadata_string(rpc, token, C.B20_SELECTOR_NAME)
    symbol = _read_metadata_string(rpc, token, C.B20_SELECTOR_SYMBOL)
    currency_code = None
    if variant == "STABLECOIN":
        currency_code = _decode_string(rpc.eth_call(token, calldata(C.B20_SELECTOR_CURRENCY)))
    return {"variant": variant, "decimals": decimals, "currency_code": currency_code,
            "name": name, "symbol": symbol}


# --------------------------------------------------------------------------
# Origin & transparency
# --------------------------------------------------------------------------
_URI_RE = re.compile(r"^(https?://|ipfs://)\S+$", re.IGNORECASE)


def _valid_uri_format(uri: str) -> Optional[bool]:
    """Format-only check (well-formed http(s)/ipfs). NEVER fetches. None when no uri."""
    if not uri:
        return None
    return bool(_URI_RE.match(uri.strip()))


def _decode_announcement(datahex: Optional[str]) -> tuple[str, str, str]:
    """Decode an Announcement event's data → (id, description, uri): three ABI dynamic
    strings. Degrades to empties on any malformed/short data (never raises)."""
    if not datahex or datahex == "0x":
        return "", "", ""
    h = datahex[2:] if datahex.startswith("0x") else datahex
    try:
        b = bytes.fromhex(h)
        out = []
        for i in range(3):
            off = int.from_bytes(b[i * 32:(i + 1) * 32], "big")
            ln = int.from_bytes(b[off:off + 32], "big")
            out.append(b[off + 32:off + 32 + ln].decode("utf-8", "replace"))
        return out[0], out[1], out[2]
    except Exception:
        return "", "", ""


def classify_announcement(description: str, uri: str, seen_stripped: set) -> tuple[bool, str]:
    """#68 substance verdict → (substantive, reason).

    substantive ⟺ len(description.strip()) >= MIN_ANNOUNCEMENT_CHARS AND the stripped
    description is not an EXACT duplicate of one already seen on this token. Junk is
    neutral (never extra-penalized). ``uri`` is format-validated only elsewhere and is
    NEVER fetched — a link can't make issuer-controlled text more true, so it does not
    affect the description verdict.
    """
    s = (description or "").strip()
    if not s:
        return False, "empty"
    if len(s) < C.MIN_ANNOUNCEMENT_CHARS:
        return False, f"under {C.MIN_ANNOUNCEMENT_CHARS} chars"
    if s in seen_stripped:
        return False, "duplicate"
    return True, "substantive"


def read_origin(
    rpc, token: str, admin_holders: Optional[list[str]], chain_id: int,
    from_block: int = 0, *, admin_first_grantee: Optional[str] = None,
) -> dict:
    # Issuer proxy: the current admin, or — for a fully-revoked admin ([]) — the
    # first historical DEFAULT_ADMIN grantee (typically the deployer). None only
    # when there is no admin history at all, or the txcount read itself fails.
    issuer = admin_holders[0] if admin_holders else admin_first_grantee
    issuer_has_history: Optional[bool] = None
    tx_count_read_error: Optional[str] = None
    if issuer is None:
        tx_count_read_error = "no issuer address available to read transaction history"
    else:
        txc = _decode_uint(rpc.eth_get_transaction_count(issuer))
        if txc is not None:
            issuer_has_history = txc > 0
        else:
            tx_count_read_error = "eth_getTransactionCount returned None (RPC error)"

    logs = _get_logs_full_or_chunked(rpc, token, [C.B20_EVENT_ANNOUNCEMENT], chain_id, from_block=from_block)
    announcement_read_error = _range_cap_reason(rpc, "Announcement reads") if logs is None else None
    announcement_events = None if logs is None else len(logs) > 0
    announcement_evidence: list[AnnouncementEvidence] = []
    announcements_total: Optional[int] = None
    announcements_substantive: Optional[int] = None
    if logs is not None:
        # Order matters for exact-duplicate dedup (earlier-seen wins). #68: decode the
        # issuer's self-attested text, classify substance, surface it in evidence.
        logs.sort(key=lambda lg: (int(lg["blockNumber"], 16), int(lg.get("logIndex", "0x0"), 16)))
        seen: set[str] = set()
        substantive_count = 0
        for lg in logs:
            _id, desc, uri = _decode_announcement(lg.get("data"))
            substantive, reason = classify_announcement(desc, uri, seen)
            if substantive:
                substantive_count += 1
            seen.add((desc or "").strip())
            announcement_evidence.append(AnnouncementEvidence(
                tx_hash=lg.get("transactionHash"),
                block_number=int(lg["blockNumber"], 16),
                log_index=int(lg.get("logIndex", "0x0"), 16),
                description=desc, uri=uri,
                substantive=substantive, reason=reason,
                uri_format_ok=_valid_uri_format(uri),
            ))
        announcements_total = len(logs)
        announcements_substantive = substantive_count

    return {
        "issuer_wallet_age_days": None,  # TO BE IMPLEMENTED — needs archive node / indexer
        "issuer_has_history": issuer_has_history,
        "tx_count_read_error": tx_count_read_error,
        "verified_entity": None,         # V1 placeholder (registry)
        "public_docs": None,             # V1 placeholder (off-chain)
        "announcement_events": announcement_events,
        "announcements_total": announcements_total,
        "announcements_substantive": announcements_substantive,
        "announcement_read_error": announcement_read_error,
        "announcement_evidence": announcement_evidence,
    }


# --------------------------------------------------------------------------
# Orchestration: read_token -> ScanInputs
# --------------------------------------------------------------------------
def classify_official_ticker(symbol: Optional[str], chain_id: int, token: str) -> Optional[str]:
    """#66/#55 tokenized-stock impersonation — symbol-only, case-insensitive.

      None            — symbol is not an official ticker (no impersonation signal)
      "verified"      — official ticker AND token == its pinned address on this chain
      "impersonation" — official ticker but a non-official address, OR a chain with no
                        pinned entry for it (e.g. any official ticker on Sepolia)

    Pure: reads ONLY the hardcoded ``constants.OFFICIAL_TOKENIZED_STOCKS`` allowlist —
    never touches the network, so it can never fail on the scan path.
    """
    if not symbol:
        return None
    ticker = symbol.strip().upper()
    if ticker not in C.OFFICIAL_TICKERS:
        return None
    pinned = C.OFFICIAL_TOKENIZED_STOCKS.get(chain_id, {}).get(ticker)
    if pinned is not None and token.lower() == pinned.lower():
        return "verified"
    return "impersonation"


def capability(holders: Optional[list[str]], granted_ever: bool = False) -> Optional[bool]:
    # #70 doctrine restoration: a SUCCESSFUL role read is authoritative.
    #   holders is None  -> read FAILED            -> None (unknown)
    #   holders == []     -> read succeeded, empty  -> False (proven absence)
    #   holders != []     -> read succeeded, held   -> True
    # `None` now means ONLY "read failed". `granted_ever` is retained for
    # call-site compatibility (granted-then-revoked already yields [] -> False)
    # but no longer branches — a successful empty replay is proven absence
    # regardless. See docs/deploy-runbook.md (scanner 0.7.0 semantic shift).
    if holders is None:
        return None
    return len(holders) > 0


def read_token(address: str, chain_id: int, *, rpc=None) -> ScanInputs:
    """Read all B20 config for ``address`` on ``chain_id`` into ScanInputs.

    Raises ``B20Unavailable`` for definitive negatives. Unknown/RPC-failed
    preflight values proceed conservatively (everything ends up unrated).
    """
    if rpc is None:
        rpc = RpcClient(chain_id)

    as_of_block = rpc.eth_block_number()

    variant = decode_variant(address)

    # Preflight — definitive negatives raise; None (unknown/RPC fail) proceeds.
    isb20 = factory_is_b20(rpc, address, chain_id)
    if isb20 is False:
        raise B20Unavailable(
            "the official B20 factory reports this contract is not a B20 token "
            "(factory.isB20 == false), so B20 security reads do not apply"
        )
    if variant is None:
        raise B20Unavailable("address is not a recognized B20 variant (byte[10])")
    if factory_is_b20_initialized(rpc, address, chain_id) is False:
        raise B20Unavailable("B20 token is not initialized")
    if is_activated(rpc, variant) is False:
        raise B20Unavailable(f"B20 {variant} is not activated on chain {chain_id}")

    # Read name/symbol/decimals EARLY — before the getLogs-heavy role/creation scans.
    # The impersonation defense (#66/#55) depends on symbol() reading reliably; on a
    # rate-limited public RPC the getLogs storm can exhaust the budget and make later
    # eth_calls (name/symbol) return None, which would silently skip the check.
    vc = read_variant_config(rpc, address, variant)

    # Bound the historical log scans (roles, announcements) to the token's life.
    # Scanning from genesis would mean ~21K range-capped getLogs calls; starting
    # at creation makes it feasible. If the creation block can't be determined
    # (no B20Created log / RPC failure), DEGRADE to a bounded recent window
    # (last 50k blocks) rather than a full-history scan.
    creation_block = get_creation_block(rpc, address, chain_id)
    if creation_block is None:
        latest = rpc.eth_block_number()
        from_block = max(0, latest - 50_000) if latest is not None else 0
    else:
        from_block = creation_block

    roles = read_roles(rpc, address, chain_id, from_block, as_of_block=as_of_block)
    admin = roles["admin"]
    pause = roles["pause"]
    supply = read_supply(rpc, address, variant)
    policy = read_transfer_policy(rpc, address)
    origin = read_origin(
        rpc, address, admin, chain_id, from_block,
        admin_first_grantee=roles["admin_first_grantee"],
    )

    ge = roles["granted_ever"]

    # Admin revoked ONLY when a grant was observed then fully revoked (the #25
    # revoked-admin path — a KNOWN safest state). A never-granted empty replay is
    # UNKNOWN, not revoked; else issuer_authority would rate 100 on B20's silence.
    if admin is None:
        admin_roles_revoked: Optional[bool] = None
    elif len(admin) > 0:
        admin_roles_revoked = False
    elif ge["admin"]:
        admin_roles_revoked = True
    else:
        admin_roles_revoked = None

    # Read provenance: source-keyed reasons a role/announcement read couldn't rate a
    # dimension — a verbatim provider string for a range cap, or a "not determinable"
    # note when the replay succeeded but B20 emitted no role events. The engine maps
    # each source to the unrated dimension(s) it explains. Empty on a clean scan.
    read_diagnostics: dict[str, str] = {}
    if roles.get("read_error"):
        read_diagnostics["roles"] = roles["read_error"]
    elif admin is not None and admin_roles_revoked is None:
        read_diagnostics["roles"] = ROLE_NOT_DETERMINABLE
    if origin.get("announcement_read_error"):
        read_diagnostics["announcements"] = origin["announcement_read_error"]
    if origin.get("tx_count_read_error"):
        read_diagnostics["tx_count"] = origin["tx_count_read_error"]
    # symbol() unreadable after retries — B20s always have a symbol, so None means a
    # genuine read failure that DISABLED the #66 impersonation check. Say so; the
    # verdict (official_ticker_status) honestly stays None (never guessed).
    if vc["symbol"] is None:
        read_diagnostics["symbol"] = (
            "symbol read failed after retries — official-ticker impersonation check "
            "(#66) could not run"
        )

    deployed_via_factory = C.OFFICIAL_FACTORY_ADDRESS.get(chain_id) if isb20 is True else None

    state_ev: dict[str, StateEvidence] = {}
    if supply["supply_cap"] is not None:
        state_ev["supply_cap"] = StateEvidence(
            block_number=as_of_block, raw_value="0x" + enc_uint(supply["supply_cap"]),
        )
    if vc["decimals"] is not None:
        state_ev["decimals"] = StateEvidence(
            block_number=as_of_block, raw_value="0x" + enc_uint(vc["decimals"]),
        )

    return ScanInputs(
        token=address,
        chain_id=chain_id,
        variant=variant,
        name=vc["name"],
        symbol=vc["symbol"],
        # #66/#55: pure allowlist check over the (just-read) symbol — no network.
        official_ticker_status=classify_official_ticker(vc["symbol"], chain_id, address),
        decimals=vc["decimals"],
        currency_code=vc["currency_code"],
        # issuer authority (role holders via log replay)
        admin_holders=admin,
        admin_is_multisig=_classify_multisig(rpc, admin),
        # EIP-7702: honest note that a single-key admin carries a delegation (still
        # one key). Does NOT change the multisig verdict — _is_contract already reads
        # a delegated EOA as an EOA, so admin_is_multisig stays False.
        admin_is_delegated_eoa=_classify_delegated_eoa(rpc, admin),
        # [] = revoked ONLY if a grant was ever observed (granted-then-revoked); a
        # never-granted empty replay is None (unknown), so issuer_authority goes
        # UNRATED rather than clean-clearing at 100 on silence (issue #34). None also
        # on read fail.
        admin_roles_revoked=admin_roles_revoked,
        mint_role_holders=roles["mint"],
        # #69: classify each mint holder EOA-vs-contract (eth_getCode) so
        # issuer_authority can flag a bare-EOA mint key / admin∩mint overlap.
        mint_holders_eoa=_classify_mint_eoa(rpc, roles["mint"]),
        burn_role_holders=roles["burn"],
        pause_role_holders=pause,
        pause_holder_is_multisig=_classify_multisig(rpc, pause),
        # supply integrity
        supply_cap=supply["supply_cap"],
        multiplier_active=supply["multiplier_active"],
        burn_enabled=capability(roles["burn"], ge["burn"]),
        # transfer policy (memo_required dropped — no analog in B20)
        policy_registry_active=policy["policy_registry_active"],
        can_freeze=policy["can_freeze"],
        # #37: can_seize is the SEIZE_ROLE power (gates seizeWithMemo), NOT
        # BURN_BLOCKED_ROLE (blocked-burn). Same #34 tri-state as every capability.
        # ⚠️ can_seize is a ROLE fact ("someone can call seizeWithMemo"), NOT a policy
        # read. Cobalt's SEIZE_EXEMPT_POLICY (base-std#214) has INVERTED semantics —
        # authorized = EXEMPT (not seizable), unset = seizure closed — so it must NOT be
        # folded in with the transfer-policy reading. If per-holder seizability is ever
        # added, read SEIZE_EXEMPT_POLICY with its own (inverted) evaluator, separate
        # from can_freeze/preflight. See preflight.py + constants.B20_POLICY_SEIZE_EXEMPT.
        can_seize=capability(roles["seize"], ge["seize"]),
        # #37 follow-up: blocked-burn surfaced as its own capability (read-only,
        # unscored). Same demuxed role + #34 tri-state — no extra RPC.
        can_burn_blocked=capability(roles["burn_blocked"], ge["burn_blocked"]),
        can_pause=capability(pause, ge["pause"]),
        is_paused=policy["is_paused"],
        asymmetric_policy=policy["asymmetric_policy"],
        # provenance (factory.isB20 — no token-side factory() getter exists)
        deployed_via_factory=deployed_via_factory,
        factory_is_official=isb20,
        # origin & transparency
        issuer_wallet_age_days=origin["issuer_wallet_age_days"],
        issuer_has_history=origin["issuer_has_history"],
        verified_entity=origin["verified_entity"],
        public_docs=origin["public_docs"],
        announcement_events=origin["announcement_events"],
        announcements_total=origin["announcements_total"],
        announcements_substantive=origin["announcements_substantive"],
        read_diagnostics=read_diagnostics,
        as_of_block=as_of_block,
        role_evidence=roles["role_evidence"],
        announcement_evidence=origin["announcement_evidence"],
        state_evidence=state_ev,
    )
