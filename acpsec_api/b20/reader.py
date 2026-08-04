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

from typing import Optional

from . import constants as C
from .models import ScanInputs
from .rpc import RANGE_CAP_KIND, RpcClient

_WAD = 10**18  # multiplier precision; multiplier() != WAD means rebasing active

# Per-chain getLogs block-range cap (public RPC limits): Sepolia 2000, mainnet 10000.
_LOG_BLOCK_CHUNK = {8453: 10000, 84532: 2000}

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


def _is_contract(rpc, addr: str) -> Optional[bool]:
    """True if the address has code (multisig/contract), False if EOA, None if
    unreadable. Still valid for admin addresses — they are ordinary accounts,
    not the B20 token precompile."""
    code = rpc.eth_get_code(addr)
    if code is None:
        return None
    return code not in ("0x", "0x0") and len(code) > 2


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

    # 1) One full-range query — a single getLogs on any provider that permits it.
    full = query(from_block, latest)
    if full is not None:
        return full
    # Fall back to chunking ONLY for a definitive range/size rejection; a
    # transient-exhausted or otherwise-definitive failure stays honestly unknown.
    if getattr(rpc, "last_error_kind", None) != RANGE_CAP_KIND:
        return None

    # 2) Existing fixed per-chain chunk walk (public-RPC block-range caps).
    size = _LOG_BLOCK_CHUNK.get(chain_id, 2000)
    out: list = []
    start = from_block
    while start <= latest:
        end = min(start + size - 1, latest)
        chunk = query(start, end)
        if chunk is None:
            return None
        out.extend(chunk)
        start = end + 1
    return out


def get_creation_block(rpc, token: str, chain_id: int) -> Optional[int]:
    """Block at which ``token`` was created, used to bound the role/announcement
    scans to [creation, latest] instead of all of chain history.

    We CANNOT find this via the B20Created event: public Base RPC caps eth_getLogs
    at ~2000 blocks (error -32602), so a full-history factory scan would be ~21K
    sequential calls. Instead we exploit that B20 tokens carry bytecode and
    BINARY-SEARCH the first block at which the token has code — O(log height),
    ~25 eth_getCode calls. Returns None if the token has no code (never deployed)
    or any RPC call fails; the caller then degrades to a bounded recent window.
    """
    latest = rpc.eth_block_number()
    if latest is None:
        return None
    # Must have code now; otherwise it's not a deployed token (or RPC is down).
    code_now = rpc.eth_get_code(token, "latest")
    if code_now is None or code_now in ("0x", "0x0"):
        return None
    lo, hi = 0, latest
    while lo < hi:  # invariant: token has code at hi, not before lo
        mid = (lo + hi) // 2
        code = rpc.eth_get_code(token, hex(mid))
        if code is None:  # RPC failure mid-search — abandon, don't guess
            return None
        if code in ("0x", "0x0"):
            lo = mid + 1
        else:
            hi = mid
    return lo


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


def role_holders_all(
    rpc, token: str, chain_id: int, from_block: int = 0
) -> Optional[dict[str, tuple[list[str], Optional[str]]]]:
    """ALL roles from ONE merged getLogs → {role_hash_lower: (holders, first_grantee)}.

    topic0 in [RoleGranted, RoleRevoked] with NO role filter, demuxed client-side by
    topics[1] (the indexed role) / topics[2] (the indexed account). Cuts the five
    per-role replays to a single query while keeping identical per-role semantics.
    None on RPC failure. A role ABSENT from the returned dict simply had no events
    in range (its holders are known-empty); the caller maps that to []. ``holders``
    is net of grants/revokes; ``first_grantee`` is the earliest RoleGranted account.
    """
    topics = [[C.B20_EVENT_ROLE_GRANTED, C.B20_EVENT_ROLE_REVOKED]]
    logs = _get_logs_full_or_chunked(rpc, token, topics, chain_id, from_block=from_block)
    if logs is None:
        return None
    logs.sort(key=lambda lg: (int(lg["blockNumber"], 16), int(lg.get("logIndex", "0x0"), 16)))
    granted = C.B20_EVENT_ROLE_GRANTED.lower()
    revoked = C.B20_EVENT_ROLE_REVOKED.lower()
    by_role: dict[str, tuple[list[str], Optional[str]]] = {}
    for lg in logs:
        tl = lg.get("topics", [])
        if len(tl) < 3:
            continue
        role = str(tl[1]).lower()
        acct = _decode_address(tl[2])
        if acct is None:
            continue
        holders, first = by_role.get(role, ([], None))
        ev = str(tl[0]).lower()
        if ev == granted:
            if first is None:
                first = acct
            if acct not in holders:
                holders.append(acct)
        elif ev == revoked and acct in holders:
            holders.remove(acct)
        by_role[role] = (holders, first)
    return by_role


def read_roles(rpc, token: str, chain_id: int, from_block: int = 0) -> dict:
    # ONE merged getLogs for every role (topic0 [Granted,Revoked], no role filter),
    # demuxed client-side — 1 query instead of 5, identical per-role semantics. The
    # DEFAULT_ADMIN first grantee (origin issuer-proxy fallback for fully-revoked
    # admins) comes from the same replay.
    all_roles = role_holders_all(rpc, token, chain_id, from_block)
    read_error = _range_cap_reason(rpc, "Role reads") if all_roles is None else None

    def detailed(role_hash: str) -> tuple[Optional[list[str]], Optional[str]]:
        if all_roles is None:      # merged read failed -> every role unknown
            return None, None
        return all_roles.get(role_hash.lower(), ([], None))  # absent -> known-empty

    admin, admin_first_grantee = detailed(C.B20_ROLE_DEFAULT_ADMIN)
    return {
        "admin": admin,
        "admin_first_grantee": admin_first_grantee,
        "mint": detailed(C.B20_ROLE_MINT)[0],
        "burn": detailed(C.B20_ROLE_BURN)[0],
        "burn_blocked": detailed(C.B20_ROLE_BURN_BLOCKED)[0],
        "pause": detailed(C.B20_ROLE_PAUSE)[0],
        "read_error": read_error,
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
    currency_code = None
    if variant == "STABLECOIN":
        currency_code = _decode_string(rpc.eth_call(token, calldata(C.B20_SELECTOR_CURRENCY)))
    return {"variant": variant, "decimals": decimals, "currency_code": currency_code}


# --------------------------------------------------------------------------
# Origin & transparency
# --------------------------------------------------------------------------
def read_origin(
    rpc, token: str, admin_holders: Optional[list[str]], chain_id: int,
    from_block: int = 0, *, admin_first_grantee: Optional[str] = None,
) -> dict:
    # Issuer proxy: the current admin, or — for a fully-revoked admin ([]) — the
    # first historical DEFAULT_ADMIN grantee (typically the deployer). None only
    # when there is no admin history at all, or the txcount read itself fails.
    issuer = admin_holders[0] if admin_holders else admin_first_grantee
    issuer_has_history: Optional[bool] = None
    if issuer is not None:
        txc = _decode_uint(rpc.eth_get_transaction_count(issuer))
        if txc is not None:
            issuer_has_history = txc > 0

    logs = _get_logs_full_or_chunked(rpc, token, [C.B20_EVENT_ANNOUNCEMENT], chain_id, from_block=from_block)
    announcement_events = None if logs is None else len(logs) > 0
    announcement_read_error = _range_cap_reason(rpc, "Announcement reads") if logs is None else None

    return {
        "issuer_wallet_age_days": None,  # TO BE IMPLEMENTED — needs archive node / indexer
        "issuer_has_history": issuer_has_history,
        "verified_entity": None,         # V1 placeholder (registry)
        "public_docs": None,             # V1 placeholder (off-chain)
        "announcement_events": announcement_events,
        "announcement_read_error": announcement_read_error,
    }


# --------------------------------------------------------------------------
# Orchestration: read_token -> ScanInputs
# --------------------------------------------------------------------------
def read_token(address: str, chain_id: int, *, rpc=None) -> ScanInputs:
    """Read all B20 config for ``address`` on ``chain_id`` into ScanInputs.

    Raises ``B20Unavailable`` for definitive negatives. Unknown/RPC-failed
    preflight values proceed conservatively (everything ends up unrated).
    """
    if rpc is None:
        rpc = RpcClient(chain_id)

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

    roles = read_roles(rpc, address, chain_id, from_block)
    admin = roles["admin"]
    pause = roles["pause"]
    supply = read_supply(rpc, address, variant)
    policy = read_transfer_policy(rpc, address)
    vc = read_variant_config(rpc, address, variant)
    origin = read_origin(
        rpc, address, admin, chain_id, from_block,
        admin_first_grantee=roles["admin_first_grantee"],
    )

    def has(holders: Optional[list[str]]) -> Optional[bool]:
        return None if holders is None else len(holders) > 0

    # Read provenance: source-keyed reasons a getLogs read was capped (verbatim
    # provider string). The engine maps each source to the unrated dimension(s) it
    # explains. Empty on a clean scan.
    read_diagnostics: dict[str, str] = {}
    if roles.get("read_error"):
        read_diagnostics["roles"] = roles["read_error"]
    if origin.get("announcement_read_error"):
        read_diagnostics["announcements"] = origin["announcement_read_error"]

    deployed_via_factory = C.OFFICIAL_FACTORY_ADDRESS.get(chain_id) if isb20 is True else None

    return ScanInputs(
        token=address,
        chain_id=chain_id,
        variant=variant,
        decimals=vc["decimals"],
        currency_code=vc["currency_code"],
        # issuer authority (role holders via log replay)
        admin_holders=admin,
        admin_is_multisig=_classify_multisig(rpc, admin),
        # A successful replay yielding [] = admin fully revoked (a KNOWN, safest
        # state), not "unknown". Record it so issuer_authority stays rated (and
        # scores best) rather than being wrongly unrated; None only on read fail.
        admin_roles_revoked=(len(admin) == 0) if admin is not None else None,
        mint_role_holders=roles["mint"],
        burn_role_holders=roles["burn"],
        pause_role_holders=pause,
        pause_holder_is_multisig=_classify_multisig(rpc, pause),
        # supply integrity
        supply_cap=supply["supply_cap"],
        multiplier_active=supply["multiplier_active"],
        burn_enabled=has(roles["burn"]),
        # transfer policy (memo_required dropped — no analog in B20)
        policy_registry_active=policy["policy_registry_active"],
        can_freeze=policy["can_freeze"],
        can_seize=has(roles["burn_blocked"]),
        can_pause=has(pause),
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
        read_diagnostics=read_diagnostics,
    )
