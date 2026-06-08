"""Tests for acpsec/trust_score/models.py — written before implementation (TDD RED)."""

import pytest
from pydantic import ValidationError


class TestFinding:
    def test_finding_stores_dim_severity_detail(self):
        from acpsec.trust_score.models import Finding
        f = Finding(dim="contract_security", severity="High", detail="reentrancy detected")
        assert f.dim == "contract_security"
        assert f.severity == "High"
        assert f.detail == "reentrancy detected"

    def test_finding_severity_must_be_valid(self):
        from acpsec.trust_score.models import Finding
        with pytest.raises((ValidationError, ValueError)):
            Finding(dim="contract_security", severity="INVALID", detail="x")

    def test_finding_accepts_all_valid_severities(self):
        from acpsec.trust_score.models import Finding
        for sev in ("CRITICAL", "High", "Medium", "Low"):
            f = Finding(dim="hook_security", severity=sev, detail="test")
            assert f.severity == sev


class TestDimScore:
    def test_dimscope_stores_name_score_weight(self):
        from acpsec.trust_score.models import DimScore
        d = DimScore(name="contract_security", score=75.0, weight=0.25)
        assert d.name == "contract_security"
        assert d.score == 75.0
        assert d.weight == 0.25

    def test_dimscope_rated_true_by_default(self):
        from acpsec.trust_score.models import DimScore
        d = DimScore(name="behavioral", score=60.0, weight=0.10)
        assert d.rated is True

    def test_dimscope_can_be_unrated(self):
        from acpsec.trust_score.models import DimScore
        d = DimScore(name="behavioral", score=0.0, weight=0.10, rated=False)
        assert d.rated is False

    def test_dimscope_score_floors_at_zero(self):
        from acpsec.trust_score.models import DimScore
        with pytest.raises((ValidationError, ValueError)):
            DimScore(name="behavioral", score=-5.0, weight=0.10)

    def test_dimscope_score_caps_at_100(self):
        from acpsec.trust_score.models import DimScore
        with pytest.raises((ValidationError, ValueError)):
            DimScore(name="behavioral", score=101.0, weight=0.10)

    def test_dimscope_findings_default_empty(self):
        from acpsec.trust_score.models import DimScore
        d = DimScore(name="identity", score=80.0, weight=0.15)
        assert d.findings == []

    def test_dimscope_stores_findings(self):
        from acpsec.trust_score.models import DimScore, Finding
        f = Finding(dim="identity", severity="High", detail="no ERC-8004 registered")
        d = DimScore(name="identity", score=70.0, weight=0.15, findings=[f])
        assert len(d.findings) == 1
        assert d.findings[0].detail == "no ERC-8004 registered"


class TestScanMode:
    def test_external_mode_value(self):
        from acpsec.trust_score.models import ScanMode
        assert ScanMode.EXTERNAL == "external"

    def test_self_audit_mode_value(self):
        from acpsec.trust_score.models import ScanMode
        assert ScanMode.SELF_AUDIT == "self_audit"

    def test_external_is_default(self):
        from acpsec.trust_score.models import DEFAULT_SCAN_MODE, ScanMode
        assert DEFAULT_SCAN_MODE == ScanMode.EXTERNAL

    def test_constructed_from_string(self):
        from acpsec.trust_score.models import ScanMode
        assert ScanMode("self_audit") == ScanMode.SELF_AUDIT

    def test_is_string_subclass(self):
        from acpsec.trust_score.models import ScanMode
        assert isinstance(ScanMode.EXTERNAL, str)


class TestDimScoreUnratedChecks:
    def test_unrated_checks_default_empty(self):
        from acpsec.trust_score.models import DimScore
        d = DimScore(name="authority_scope", score=80.0, weight=0.20)
        assert d.unrated_checks == []

    def test_unrated_checks_stores_names(self):
        from acpsec.trust_score.models import DimScore
        d = DimScore(
            name="authority_scope", score=80.0, weight=0.20,
            unrated_checks=["signer_unrestricted", "agent_card_no_spend_limit"],
        )
        assert d.unrated_checks == ["signer_unrestricted", "agent_card_no_spend_limit"]

    def test_unrated_checks_independent_per_instance(self):
        from acpsec.trust_score.models import DimScore
        a = DimScore(name="a", score=100.0, weight=0.2)
        b = DimScore(name="b", score=100.0, weight=0.2)
        a.unrated_checks.append("x")
        assert b.unrated_checks == []


class TestSubScore:
    def test_subscore_stores_score(self):
        from acpsec.trust_score.models import SubScore
        s = SubScore(score=72)
        assert s.score == 72

    def test_subscore_unrated_checks_default_empty(self):
        from acpsec.trust_score.models import SubScore
        assert SubScore(score=72).unrated_checks == []

    def test_subscore_stores_unrated_checks(self):
        from acpsec.trust_score.models import SubScore
        s = SubScore(score=80, unrated_checks=["fee_split_nonconformant"])
        assert s.unrated_checks == ["fee_split_nonconformant"]

    def test_subscore_unrated_checks_independent_per_instance(self):
        from acpsec.trust_score.models import SubScore
        a = SubScore(score=80)
        b = SubScore(score=80)
        a.unrated_checks.append("x")
        assert b.unrated_checks == []


class TestTrustScoreResult:
    def _make_subscores(self, val: int = 70) -> dict:
        return {
            "contract_security": {"score": val},
            "authority_scope": {"score": val},
            "identity": {"score": val},
            "hook_security": {"score": val},
            "acp_compliance": {"score": val},
            "behavioral": {"score": val},
        }

    def test_result_stores_all_output_fields(self):
        from acpsec.trust_score.models import TrustScoreResult
        r = TrustScoreResult(
            agent="0xABCD",
            erc8004_id="agent.eth",
            score=72,
            grade="C",
            multiplier=0.60,
            critical=False,
            subscores=self._make_subscores(72),
            top_findings=[],
            scanned_at="2026-06-07T00:00:00Z",
            scanner_version="acpsec-v0.5.0",
        )
        assert r.agent == "0xABCD"
        assert r.erc8004_id == "agent.eth"
        assert r.score == 72
        assert r.grade == "C"
        assert r.multiplier == 0.60
        assert r.critical is False
        assert r.scanner_version == "acpsec-v0.5.0"

    def test_result_is_rated_by_default(self):
        from acpsec.trust_score.models import TrustScoreResult
        r = TrustScoreResult(
            agent="0xABCD",
            erc8004_id="",
            score=55,
            grade="D",
            multiplier=0.30,
            critical=False,
            subscores=self._make_subscores(55),
            top_findings=[],
            scanned_at="2026-06-07T00:00:00Z",
            scanner_version="acpsec-v0.5.0",
        )
        assert r.rated is True

    def test_result_can_be_unrated(self):
        from acpsec.trust_score.models import TrustScoreResult
        r = TrustScoreResult(
            agent="0xNEW",
            erc8004_id="",
            score=0,
            grade="F",
            multiplier=0.50,
            critical=False,
            subscores={},
            top_findings=[],
            scanned_at="2026-06-07T00:00:00Z",
            scanner_version="acpsec-v0.5.0",
            rated=False,
        )
        assert r.rated is False
        assert r.multiplier == 0.50

    def test_result_stores_top_findings(self):
        from acpsec.trust_score.models import Finding, TrustScoreResult
        findings = [
            Finding(dim="authority_scope", severity="High", detail="withdrawal gated by single EOA"),
            Finding(dim="acp_compliance", severity="High", detail="no refund path on failed delivery"),
        ]
        r = TrustScoreResult(
            agent="0x1234",
            erc8004_id="",
            score=52,
            grade="D",
            multiplier=0.30,
            critical=False,
            subscores=self._make_subscores(52),
            top_findings=findings,
            scanned_at="2026-06-07T00:00:00Z",
            scanner_version="acpsec-v0.5.0",
        )
        assert len(r.top_findings) == 2
        assert r.top_findings[0].dim == "authority_scope"

    def test_result_critical_flag_true_when_critical_found(self):
        from acpsec.trust_score.models import Finding, TrustScoreResult
        r = TrustScoreResult(
            agent="0xBAD",
            erc8004_id="",
            score=39,
            grade="F",
            multiplier=0.10,
            critical=True,
            subscores=self._make_subscores(39),
            top_findings=[
                Finding(dim="contract_security", severity="CRITICAL", detail="source unverified"),
            ],
            scanned_at="2026-06-07T00:00:00Z",
            scanner_version="acpsec-v0.5.0",
        )
        assert r.critical is True
        assert r.score == 39
        assert r.grade == "F"
