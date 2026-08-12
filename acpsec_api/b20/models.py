"""Canonical data models for B20 scans.

Two families:
- ``ScanInputs``: the source-agnostic scoring-inputs struct. A reader fills in
  whatever it could read; anything left ``None`` is "unknown" and the engine
  treats it as unrated. This struct carries NO notion of Solidity source — B20
  tokens have none, so there is deliberately no ``source_verified`` field.
- Output models (``Finding``, ``DimensionResult``, ``IssuerPowers``,
  ``ScanResult``): the canonical scan output, serialized via ``to_dict()``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------
# Output models
# --------------------------------------------------------------------------
@dataclass
class Finding:
    # No `dimension` field: findings are already grouped under their dimension in
    # the parent dict (dimensions: {<name>: {findings: [...]}}), so storing it
    # here would be redundant and is never serialized.
    severity: str  # CRITICAL | High | Medium | Low
    detail: str

    def to_dict(self) -> dict:
        return {"severity": self.severity, "detail": self.detail}


@dataclass
class DimensionResult:
    name: str
    score: float
    weight: float
    rated: bool = True
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "weight": self.weight,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class IssuerPowers:
    can_freeze: Optional[bool]
    can_seize: Optional[bool]
    can_burn_blocked: Optional[bool]   # blocked-burn (distinct from seize); read-only chip
    can_pause: Optional[bool]
    can_mint_unbounded: Optional[bool]
    supply_cap: Optional[str]
    admin_addresses: list[str]
    admin_is_multisig: Optional[bool]
    mint_role_holders: list[str]
    pause_role_holders: list[str]

    def to_dict(self) -> dict:
        return {
            "can_freeze": self.can_freeze,
            "can_seize": self.can_seize,
            "can_burn_blocked": self.can_burn_blocked,
            "can_pause": self.can_pause,
            "can_mint_unbounded": self.can_mint_unbounded,
            "supply_cap": self.supply_cap,
            "admin_addresses": list(self.admin_addresses),
            "admin_is_multisig": self.admin_is_multisig,
            "mint_role_holders": list(self.mint_role_holders),
            "pause_role_holders": list(self.pause_role_holders),
        }


@dataclass
class ScanResult:
    token: str
    chain_id: int
    variant: Optional[str]
    name: Optional[str]
    symbol: Optional[str]
    decimals: Optional[int]
    currency_code: Optional[str]
    trust_score: int          # final, confidence-adjusted score
    raw_score: int            # composite before the unrated multiplier
    grade: str                # derived from trust_score (final)
    is_critical: bool
    critical_reasons: list[str]
    rated: bool               # False if any dimension is unrated
    multiplier: float         # 1.0 if all rated, 0.5 if any unrated
    unrated_dimensions: list[str]
    # Why an unrated dimension could not be read, keyed by dimension name, provider
    # string verbatim (e.g. a getLogs range cap). Empty on a clean scan.
    read_diagnostics: dict[str, str]
    dimensions: dict[str, DimensionResult]
    issuer_powers: IssuerPowers
    deployed_via_factory: Optional[str]
    scanner_version: str
    scanned_at: str

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "chain_id": self.chain_id,
            "variant": self.variant,
            "name": self.name,
            "symbol": self.symbol,
            "decimals": self.decimals,
            "currency_code": self.currency_code,
            "trust_score": self.trust_score,
            "raw_score": self.raw_score,
            "grade": self.grade,
            "rated": self.rated,
            "multiplier": self.multiplier,
            "unrated_dimensions": list(self.unrated_dimensions),
            "read_diagnostics": dict(self.read_diagnostics),
            "is_critical": self.is_critical,
            "critical_reasons": list(self.critical_reasons),
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
            "issuer_powers": self.issuer_powers.to_dict(),
            "deployed_via_factory": self.deployed_via_factory,
            "scanner_version": self.scanner_version,
            "scanned_at": self.scanned_at,
        }


# --------------------------------------------------------------------------
# Source-agnostic scoring inputs
# --------------------------------------------------------------------------
@dataclass
class ScanInputs:
    # Identity / metadata
    token: str
    chain_id: int
    variant: Optional[str] = None          # "ASSET" | "STABLECOIN"
    name: Optional[str] = None
    symbol: Optional[str] = None
    decimals: Optional[int] = None
    currency_code: Optional[str] = None

    # Issuer authority
    admin_holders: Optional[list[str]] = None
    admin_is_multisig: Optional[bool] = None
    admin_roles_revoked: Optional[bool] = None
    mint_role_holders: Optional[list[str]] = None
    burn_role_holders: Optional[list[str]] = None
    pause_role_holders: Optional[list[str]] = None
    pause_holder_is_multisig: Optional[bool] = None

    # Supply integrity
    supply_cap: Optional[int] = None
    multiplier_active: Optional[bool] = None   # rebasing
    burn_enabled: Optional[bool] = None

    # Transfer policy
    policy_registry_active: Optional[bool] = None
    can_freeze: Optional[bool] = None
    can_seize: Optional[bool] = None
    # blocked-burn (BURN_BLOCKED_ROLE): a coercive power DISTINCT from seize —
    # destroys a blocked balance rather than moving it. Read-only surface (a UI
    # capability chip); NOT folded into can_seize and NOT yet scored.
    can_burn_blocked: Optional[bool] = None
    can_pause: Optional[bool] = None
    is_paused: Optional[bool] = None
    memo_required: Optional[bool] = None
    asymmetric_policy: Optional[bool] = None

    # Variant & config / provenance
    deployed_via_factory: Optional[str] = None
    factory_is_official: Optional[bool] = None

    # Origin & transparency
    issuer_wallet_age_days: Optional[int] = None
    issuer_has_history: Optional[bool] = None
    # SHARED FIELDS: public_docs and verified_entity feed BOTH dimensions:
    #   - origin_transparency (directly)
    #   - transfer_policy (as the "transparency" signal that softens freeze+seize penalty)
    # The reader should populate both once; missing them makes origin unrated AND
    # raises transfer_policy's freeze+seize penalty from -20 to -40.
    verified_entity: Optional[bool] = None
    public_docs: Optional[bool] = None
    announcement_events: Optional[bool] = None

    # Read provenance — NOT a scoring input. Source-keyed reasons a read could not
    # be completed (e.g. {"roles": "…provider getLogs range cap…"}); the engine maps
    # each source to the unrated dimensions it explains for the scan response.
    read_diagnostics: dict[str, str] = field(default_factory=dict)
