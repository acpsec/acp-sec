"""On-chain evidence models + additive `evidence` block (Phase 1).

See docs/b20-onchain-evidence-design-v1.md.
"""

from acpsec_api.b20 import constants as C
from acpsec_api.b20.engine import assess
from acpsec_api.b20.models import (
    EventEvidence,
    Finding,
    RoleHolderEvidence,
    ScanEvidence,
    ScanInputs,
    StateEvidence,
)


def test_event_evidence_shape():
    e = EventEvidence(tx_hash="0xabc", block_number=10, log_index=2)
    assert e.to_dict() == {"kind": "event", "tx_hash": "0xabc", "block_number": 10, "log_index": 2}


def test_state_evidence_shape():
    s = StateEvidence(block_number=10, raw_value="340282")
    assert s.to_dict() == {"kind": "state", "block_number": 10, "raw_value": "340282", "confirmed": None}


def test_state_evidence_confirmed_variant():
    s = StateEvidence(block_number=10, confirmed=True)
    assert s.to_dict() == {"kind": "state", "block_number": 10, "raw_value": None, "confirmed": True}


def test_role_holder_evidence_shape():
    rhe = RoleHolderEvidence(
        address="0xaa", grant=EventEvidence("0x1", 5, 0),
        has_role=StateEvidence(10, confirmed=True),
    )
    d = rhe.to_dict()
    assert d["address"] == "0xaa"
    assert d["grant"] == {"kind": "event", "tx_hash": "0x1", "block_number": 5, "log_index": 0}
    assert d["revoke"] is None
    assert d["has_role"]["confirmed"] is True
    assert d["discrepancy"] is False


def test_finding_evidence_is_additive():
    # Existing findings serialize with evidence:None (additive key).
    assert Finding("High", "x").to_dict() == {"severity": "High", "detail": "x", "evidence": None}
    f = Finding("High", "x", evidence=StateEvidence(10, raw_value="v"))
    assert f.to_dict()["evidence"]["kind"] == "state"


def test_scan_result_has_additive_evidence_block():
    d = assess(ScanInputs(token="0xB200", chain_id=8453)).to_dict()
    assert "evidence" in d
    assert set(d["evidence"].keys()) == {"as_of_block", "roles", "announcements", "state"}
    # Empty inputs -> empty evidence, never fabricated.
    assert d["evidence"]["roles"] == {}
    assert d["evidence"]["announcements"] == []
    assert d["evidence"]["state"] == {}


# ── Item 1: role name field ──────────────────────────────────────────────────

def test_role_holder_evidence_includes_role_name():
    """to_dict() emits 'role': name so consumers can read it without decoding hashes."""
    rhe = RoleHolderEvidence(address="0xaa", role_name="MINT")
    assert rhe.to_dict()["role"] == "MINT"


def test_role_holder_evidence_null_role_name_emits_null():
    """Unknown hashes stay as null — we never guess a name."""
    rhe = RoleHolderEvidence(address="0xaa")
    assert rhe.to_dict()["role"] is None


def test_role_names_constant_covers_all_tracked_roles():
    """ROLE_NAMES has every role the reader can demux from the merged getLogs."""
    for expected in ("DEFAULT_ADMIN", "MINT", "BURN", "BURN_BLOCKED", "SEIZE", "PAUSE"):
        assert expected in C.ROLE_NAMES.values(), f"ROLE_NAMES missing {expected}"


def test_burn_role_hash_resolves_to_burn():
    """0xe97b...fa22 is BURN_ROLE — previously unreadable from the raw hash alone."""
    assert C.ROLE_NAMES.get(C.B20_ROLE_BURN.lower()) == "BURN"


def test_role_holder_evidence_shape_includes_role_key():
    """role field is always present in to_dict() — fixed schema, never omitted."""
    rhe = RoleHolderEvidence(address="0xaa", grant=EventEvidence("0x1", 5, 0),
                             has_role=StateEvidence(10, confirmed=True), role_name="PAUSE")
    d = rhe.to_dict()
    assert "role" in d
    assert d["role"] == "PAUSE"
    assert d["address"] == "0xaa"
    assert d["discrepancy"] is False


# ── Item 2: StateEvidence fixed shape ────────────────────────────────────────

def test_state_evidence_fixed_shape_both_keys_always_present():
    """Both raw_value and confirmed always appear in to_dict(), null when inapplicable.
    Stable schema: consumers can always do ev['confirmed'] without key-existence checks."""
    has_role_ev = StateEvidence(block_number=10, confirmed=True)
    d = has_role_ev.to_dict()
    assert "raw_value" in d and d["raw_value"] is None   # null, not omitted
    assert d["confirmed"] is True

    supply_ev = StateEvidence(block_number=10, raw_value="0xff")
    d2 = supply_ev.to_dict()
    assert "confirmed" in d2 and d2["confirmed"] is None  # null, not omitted
    assert d2["raw_value"] == "0xff"


def test_scan_evidence_serializes_nested():
    ev = ScanEvidence(
        as_of_block=100,
        roles={"MINT_ROLE": [RoleHolderEvidence(address="0xaa", grant=EventEvidence("0x1", 5, 0))]},
        announcements=[EventEvidence("0x9", 7, 1)],
        state={"supply_cap": StateEvidence(100, raw_value="340282")},
    )
    d = ev.to_dict()
    assert d["as_of_block"] == 100
    assert d["roles"]["MINT_ROLE"][0]["address"] == "0xaa"
    assert d["announcements"][0]["kind"] == "event"
    assert d["state"]["supply_cap"]["raw_value"] == "340282"
