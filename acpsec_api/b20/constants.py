"""B20-interface assumptions and scoring constants.

Every value that depends on the B20 on-chain interface lives here so that an
interface change touches one module, not the whole codebase.

The B20 interface section is now CONFIRMED against the Base Standard Library
(github.com/base/base-std) and verified live on Base Sepolia (84532). See
docs/reader-rework-v7.md for the reader changes these confirmed values enable.
"""

from __future__ import annotations

# --- Chains (V1: Base Mainnet + Base Sepolia only) -------------------------
# Public Base RPC endpoints. Overridable per deployment; treated as placeholders
# that any higher-rate endpoint can replace.
CHAIN_RPC_ENDPOINTS: dict[int, str] = {
    8453: "https://mainnet.base.org",
    84532: "https://sepolia.base.org",
}

CHAIN_NAMES: dict[int, str] = {
    8453: "base-mainnet",
    84532: "base-sepolia",
}

# --- Official B20 factory (CONFIRMED) -------------------------------------
# Singleton factory precompile, identical on both chains. CONFIRMED from
# base-std StdPrecompiles.B20_FACTORY_ADDRESS. (It is a precompile, so it has no
# bytecode — eth_getCode returns 0x even though it is live.)
OFFICIAL_FACTORY_ADDRESS: dict[int, str] = {
    8453: "0xB20f000000000000000000000000000000000000",
    84532: "0xB20f000000000000000000000000000000000000",
}

# --- Supply sentinel ------------------------------------------------------
# No-cap sentinel: a supply cap equal to type(uint128).max means uncapped /
# infinite mint (a critical condition). CONFIRMED = B20Constants.MAX_SUPPLY_CAP.
UINT128_MAX: int = 2**128 - 1

# --- Scoring caps / multipliers (mirror acp-sec) --------------------------
CRITICAL_CAP: int = 39          # any critical condition forces composite <= 39 (grade F)
UNRATED_MULTIPLIER: float = 0.50  # applied when any dimension is unrated

# --- Grade bands (mirror acp-sec thresholds) ------------------------------
# Sorted descending by min-score-inclusive; first match wins.
GRADE_BANDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0, "F"),
]

# --- Dimension weights (sum to 1.00) --------------------------------------
DIMENSION_WEIGHTS: dict[str, float] = {
    "issuer_authority": 0.30,
    "supply_integrity": 0.25,
    "transfer_policy": 0.20,
    "variant_config": 0.15,
    "origin_transparency": 0.10,
}

# ==========================================================================
# B20 ON-CHAIN INTERFACE — CONFIRMED from base/base-std (Base Standard Library)
# --------------------------------------------------------------------------
# Selectors are keccak256(signature)[:4]; role/policy ids are keccak256(name);
# event topics are keccak256(eventSignature); feature keys are keccak256(name).
# All verified against github.com/base/base-std and live on Base Sepolia.
#
# Activation status: Sepolia (84532) ALL ACTIVATED. Mainnet (8453) was NOT
# activated at original pin time but is now LIVE — verified on-chain 2026-07-19
# (isActivated == true for ASSET / STABLECOIN / POLICY_REGISTRY; a real mainnet
# B20 token scanned via POST /api/b20/scan {chain_id: 8453} returned a fully
# rated result). See docs/reader-rework-v7.md.
# ==========================================================================

# --- Precompile addresses -------------------------------------------------
ACTIVATION_REGISTRY = "0x8453000000000000000000000000000000000001"
POLICY_REGISTRY = "0x8453000000000000000000000000000000000002"
# (OFFICIAL_FACTORY_ADDRESS = 0xB20f...0000, pinned above.)

# --- Token read selectors (IB20) ------------------------------------------
B20_SELECTOR_DECIMALS = "0x313ce567"          # decimals() -> uint8
B20_SELECTOR_NAME = "0x06fdde03"              # name() -> string
B20_SELECTOR_SYMBOL = "0x95d89b41"            # symbol() -> string
B20_SELECTOR_SUPPLY_CAP = "0x8f770ad0"        # supplyCap() -> uint256
B20_SELECTOR_HAS_ROLE = "0x91d14854"          # hasRole(bytes32,address) -> bool
B20_SELECTOR_IS_PAUSED = "0xbc61e733"         # isPaused(uint8) -> bool (TRANSFER=0, MINT=1, BURN=2)
B20_SELECTOR_PAUSED_FEATURES = "0xde9997e3"   # pausedFeatures() -> uint8[]
B20_SELECTOR_POLICY_ID = "0xdb3de624"         # policyId(bytes32) -> uint64 (0 = always-allow)

# --- Factory selectors (IB20Factory — called on OFFICIAL_FACTORY_ADDRESS) --
B20_SELECTOR_IS_B20 = "0xfa19b927"            # isB20(address) -> bool (structural prefix check, ungated)
B20_SELECTOR_IS_B20_INITIALIZED = "0x6a45ba98"  # isB20Initialized(address) -> bool (actually created)

# --- Activation registry selector -----------------------------------------
B20_SELECTOR_IS_ACTIVATED = "0xba87af80"      # isActivated(bytes32) -> bool

# --- Role getter selectors (each returns the role's bytes32) --------------
B20_SELECTOR_DEFAULT_ADMIN_ROLE = "0xa217fddf"
B20_SELECTOR_MINT_ROLE = "0xe9a9c850"
B20_SELECTOR_BURN_ROLE = "0xb930908f"
B20_SELECTOR_BURN_BLOCKED_ROLE = "0x32ad9be8"   # BURN_BLOCKED_ROLE getter (blocked-burn, NOT seize)
B20_SELECTOR_PAUSE_ROLE = "0x389ed267"
B20_SELECTOR_UNPAUSE_ROLE = "0x309756fb"
B20_SELECTOR_METADATA_ROLE = "0x38841782"

# --- Policy scope getter selectors ----------------------------------------
B20_SELECTOR_TRANSFER_SENDER_POLICY = "0xd116fc21"    # freeze / block-sender scope
B20_SELECTOR_TRANSFER_RECEIVER_POLICY = "0x210f521b"
B20_SELECTOR_TRANSFER_EXECUTOR_POLICY = "0x724e9c53"
B20_SELECTOR_MINT_RECEIVER_POLICY = "0x6e5b013d"

# --- Asset-variant selectors (IB20Asset) ----------------------------------
B20_SELECTOR_MULTIPLIER = "0x1b3ed722"        # multiplier() -> uint256 (WAD=1e18; != 1e18 => rebasing active)
B20_SELECTOR_OPERATOR_ROLE = "0xf5b541a6"

# --- Stablecoin-variant selectors (IB20Stablecoin) ------------------------
B20_SELECTOR_CURRENCY = "0xe5a6b10f"          # currency() -> string  (NOT currencyCode)

# --- Role bytes32 values (B20Constants.sol — keccak256 of the name string) -
B20_ROLE_DEFAULT_ADMIN = "0x" + "00" * 32                                                  # bytes32(0)
B20_ROLE_MINT = "0x154c00819833dac601ee5ddded6fda79d9d8b506b911b3dbd54cdb95fe6c3686"       # keccak256("MINT_ROLE")
B20_ROLE_BURN = "0xe97b137254058bd94f28d2f3eb79e2d34074ffb488d042e3bc958e0a57d2fa22"       # keccak256("BURN_ROLE")
B20_ROLE_BURN_BLOCKED = "0x7408fdc0d31c7bcb349eab611f5d1168acd4303574993f8cdc98b1cd18c41cae"  # keccak256("BURN_BLOCKED_ROLE") — blocked-burn (NOT seize; see B20_ROLE_SEIZE)
B20_ROLE_SEIZE = "0x3469b8b0d89e9604f8510ed143f74a8336d22955d4f83e23bf53d9414e27f432"       # keccak256("SEIZE_ROLE") — seize (gates seizeWithMemo/Seized); cast-verified, distinct from BURN_BLOCKED
B20_ROLE_PAUSE = "0x139c2898040ef16910dc9f44dc697df79363da767d8bc92f2e310312b816e46d"      # keccak256("PAUSE_ROLE")
B20_ROLE_UNPAUSE = "0x265b220c5a8891efdd9e1b1b7fa72f257bd5169f8d87e319cf3dad6ff52b94ae"    # keccak256("UNPAUSE_ROLE")
B20_ROLE_METADATA = "0x6bd6b5318a46e5fff572d5e4258a20774aab40cc35ac7680654b9081fcc82f80"   # keccak256("METADATA_ROLE")
B20_ROLE_OPERATOR = "0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929"   # keccak256("OPERATOR_ROLE") — Asset only

# --- Policy scope bytes32 values ------------------------------------------
B20_POLICY_TRANSFER_SENDER = "0xb81736c875ab819dd97f59f2a6542cfb731ad52b4ae15a6f24df2fb02b0327f5"
B20_POLICY_TRANSFER_RECEIVER = "0x8a4b3fa2d8b921852bc0089c6ef0958aa6961897be36fd731330fe2cd23f8363"
B20_POLICY_TRANSFER_EXECUTOR = "0x10be5173aff2a44e748bd9acd8b19fe34689581398a9db7ba2fb671e786ff7d8"
B20_POLICY_MINT_RECEIVER = "0xa0d5ae037e66a09119acf080a1d807abb9b6d03b6b9130eb19f7c1e6bdb8ffc8"

# --- Event topics (topic0 = keccak256 of the event signature) -------------
B20_EVENT_ROLE_GRANTED = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
B20_EVENT_ROLE_REVOKED = "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b"
B20_EVENT_ANNOUNCEMENT = "0xccebf8218a62875909564adef86a6f4df81503cb617221e793357d62f8e813f7"  # Asset
B20_EVENT_B20_CREATED = "0xfd9bf2730513a1709722ff379a0844dfd8f997d600693c2bcc659e188bbdba0d"   # Factory

# --- Activation feature keys (keccak256 of the feature name string) -------
B20_FEATURE_ASSET = "0xcdcc772fe4cbdb1029f822861176d09e646db96723d4c1e82ddfdeb8163ef54c"
B20_FEATURE_STABLECOIN = "0xecfa0def2c10020caaf65e6155aa69c84b24892aaef76eeac52e0e2b3a0b8601"
B20_FEATURE_POLICY_REGISTRY = "0xb582ebae03f16fee49a6763f78df482fb11ae73f103ed0d330bbe556aa90a43f"

# --- Decimals range (B20Constants.sol) ------------------------------------
B20_MIN_ASSET_DECIMALS = 6
B20_MAX_ASSET_DECIMALS = 18
B20_STABLECOIN_DECIMALS = 6   # hardcoded for the Stablecoin variant

# --- PausableFeature enum values (for isPaused(uint8)) --------------------
B20_PAUSABLE_TRANSFER = 0
B20_PAUSABLE_MINT = 1
B20_PAUSABLE_BURN = 2

# --- Sepolia test tokens (confirmed live via B20Created events) -----------
B20_SEPOLIA_TEST_TOKENS = [
    "0xb20000000000000000000072484eb7abdf1d5a44",  # ASSET, decimals=6, cap=100000000000000
    "0xb200000000000000000001f537f694b33ad0718a",  # STABLECOIN
]
