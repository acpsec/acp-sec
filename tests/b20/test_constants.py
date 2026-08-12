"""Constants module invariants (spec: b20-trust-scoring)."""

from acpsec_api.b20 import constants as C


def test_dimension_weights_sum_to_one():
    # Spec: "The weights MUST sum to 1.00."
    assert round(sum(C.DIMENSION_WEIGHTS.values()), 10) == 1.0


def test_dimension_weight_values():
    assert C.DIMENSION_WEIGHTS == {
        "issuer_authority": 0.30,
        "supply_integrity": 0.25,
        "transfer_policy": 0.20,
        "variant_config": 0.15,
        "origin_transparency": 0.10,
    }


def test_critical_cap_and_unrated_multiplier():
    assert C.CRITICAL_CAP == 39
    assert C.UNRATED_MULTIPLIER == 0.50


def test_uint128_max_sentinel():
    assert C.UINT128_MAX == 2**128 - 1


def test_grade_bands_descending_and_cover_zero():
    thresholds = [t for t, _ in C.GRADE_BANDS]
    assert thresholds == sorted(thresholds, reverse=True)
    assert C.GRADE_BANDS[0] == (90, "A")
    assert C.GRADE_BANDS[-1][0] == 0  # an F band catches everything down to 0


def test_supported_chains():
    assert set(C.CHAIN_RPC_ENDPOINTS) == {8453, 84532}


def test_official_factory_address_present_per_chain():
    assert set(C.OFFICIAL_FACTORY_ADDRESS) == {8453, 84532}


# --- Confirmed B20 interface constants (pinned from base/base-std) ---------
def _is_selector(s: str) -> bool:
    return isinstance(s, str) and s.startswith("0x") and len(s) == 10


def _is_bytes32(s: str) -> bool:
    return isinstance(s, str) and s.startswith("0x") and len(s) == 66


def test_precompile_addresses():
    assert C.OFFICIAL_FACTORY_ADDRESS[8453] == "0xB20f000000000000000000000000000000000000"
    assert C.OFFICIAL_FACTORY_ADDRESS[84532] == "0xB20f000000000000000000000000000000000000"
    assert C.ACTIVATION_REGISTRY == "0x8453000000000000000000000000000000000001"
    assert C.POLICY_REGISTRY == "0x8453000000000000000000000000000000000002"


def test_confirmed_selectors_are_four_bytes():
    for name in (
        "DECIMALS", "NAME", "SYMBOL", "SUPPLY_CAP", "HAS_ROLE", "IS_PAUSED",
        "PAUSED_FEATURES", "POLICY_ID", "IS_B20", "IS_B20_INITIALIZED",
        "IS_ACTIVATED", "MULTIPLIER", "CURRENCY",
        "DEFAULT_ADMIN_ROLE", "MINT_ROLE", "BURN_ROLE", "BURN_BLOCKED_ROLE",
        "PAUSE_ROLE", "UNPAUSE_ROLE", "METADATA_ROLE", "OPERATOR_ROLE",
        "TRANSFER_SENDER_POLICY", "TRANSFER_RECEIVER_POLICY",
        "TRANSFER_EXECUTOR_POLICY", "MINT_RECEIVER_POLICY",
    ):
        sel = getattr(C, f"B20_SELECTOR_{name}")
        assert _is_selector(sel), f"B20_SELECTOR_{name}={sel!r} not a 4-byte selector"


def test_key_selectors_exact_values():
    assert C.B20_SELECTOR_SUPPLY_CAP == "0x8f770ad0"
    assert C.B20_SELECTOR_HAS_ROLE == "0x91d14854"
    assert C.B20_SELECTOR_IS_B20 == "0xfa19b927"
    assert C.B20_SELECTOR_IS_ACTIVATED == "0xba87af80"
    assert C.B20_SELECTOR_CURRENCY == "0xe5a6b10f"


def test_role_and_policy_bytes32():
    assert C.B20_ROLE_DEFAULT_ADMIN == "0x" + "00" * 32
    for name in ("MINT", "BURN", "BURN_BLOCKED", "PAUSE", "UNPAUSE", "METADATA", "OPERATOR"):
        assert _is_bytes32(getattr(C, f"B20_ROLE_{name}"))
    for name in ("TRANSFER_SENDER", "TRANSFER_RECEIVER", "TRANSFER_EXECUTOR", "MINT_RECEIVER"):
        assert _is_bytes32(getattr(C, f"B20_POLICY_{name}"))
    # exact spot-checks
    assert C.B20_ROLE_MINT == "0x154c00819833dac601ee5ddded6fda79d9d8b506b911b3dbd54cdb95fe6c3686"
    assert C.B20_ROLE_BURN_BLOCKED == "0x7408fdc0d31c7bcb349eab611f5d1168acd4303574993f8cdc98b1cd18c41cae"


def test_seize_role_is_distinct_from_burn_blocked():
    # #37: the seize power is SEIZE_ROLE (governs seizeWithMemo/Seized), a DISTINCT
    # role from BURN_BLOCKED_ROLE (blocked-burn). cast-verified keccak256("SEIZE_ROLE").
    assert _is_bytes32(C.B20_ROLE_SEIZE)
    assert C.B20_ROLE_SEIZE == "0x3469b8b0d89e9604f8510ed143f74a8336d22955d4f83e23bf53d9414e27f432"
    assert C.B20_ROLE_SEIZE != C.B20_ROLE_BURN_BLOCKED


def test_event_topics_are_bytes32():
    for name in ("ROLE_GRANTED", "ROLE_REVOKED", "ANNOUNCEMENT", "B20_CREATED"):
        assert _is_bytes32(getattr(C, f"B20_EVENT_{name}"))
    assert C.B20_EVENT_B20_CREATED == "0xfd9bf2730513a1709722ff379a0844dfd8f997d600693c2bcc659e188bbdba0d"


def test_activation_feature_keys():
    for name in ("ASSET", "STABLECOIN", "POLICY_REGISTRY"):
        assert _is_bytes32(getattr(C, f"B20_FEATURE_{name}"))
    assert C.B20_FEATURE_ASSET == "0xcdcc772fe4cbdb1029f822861176d09e646db96723d4c1e82ddfdeb8163ef54c"


def test_decimals_range_and_stablecoin():
    assert C.B20_MIN_ASSET_DECIMALS == 6
    assert C.B20_MAX_ASSET_DECIMALS == 18
    assert C.B20_STABLECOIN_DECIMALS == 6


def test_pausable_feature_enum():
    assert (C.B20_PAUSABLE_TRANSFER, C.B20_PAUSABLE_MINT, C.B20_PAUSABLE_BURN) == (0, 1, 2)


def test_sepolia_test_tokens_are_b20_addresses():
    assert len(C.B20_SEPOLIA_TEST_TOKENS) >= 2
    for addr in C.B20_SEPOLIA_TEST_TOKENS:
        assert addr.lower().startswith("0xb2") and len(addr) == 42
