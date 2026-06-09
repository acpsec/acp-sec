"""Unit tests for the acp-sec ACP Provider logic (no chain / no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acpsec.acp_provider import (
    SERVICE_NAME,
    AcceptanceDecision,
    build_deliverable,
    evaluate_request,
    parse_scan_target,
)
from acpsec.acp_provider import executor as executor_mod
from acpsec.acp_provider.executor import ScanError, run_scan

SENTRY = "0x7770ED57E3993d4555951a557cd158a6Fb87A470"


# --- parse_scan_target ------------------------------------------------------

def test_parse_target_from_plain_string():
    assert parse_scan_target(f"scan address {SENTRY} please") == SENTRY


def test_parse_target_from_address_only():
    assert parse_scan_target(SENTRY) == SENTRY


def test_parse_target_from_dict_address_key():
    assert parse_scan_target({"address": SENTRY}) == SENTRY


def test_parse_target_from_dict_value_string():
    req = {"type": "scan-request", "value": f"please scan {SENTRY}"}
    assert parse_scan_target(req) == SENTRY


def test_parse_target_prefers_address_key_over_other_strings():
    other = "0x" + "1" * 40
    req = {"note": f"ignore {other}", "address": SENTRY}
    assert parse_scan_target(req) == SENTRY


def test_parse_target_lowercase_accepted():
    assert parse_scan_target(SENTRY.lower()) == SENTRY.lower()


def test_parse_target_nested_list():
    req = {"items": [{"k": "v"}, {"target": SENTRY}]}
    assert parse_scan_target(req) == SENTRY


def test_parse_target_none_when_absent():
    assert parse_scan_target("nothing here") is None
    assert parse_scan_target({"foo": "bar"}) is None
    assert parse_scan_target(None) is None


def test_parse_target_rejects_too_short():
    assert parse_scan_target("0x1234") is None


# --- evaluate_request -------------------------------------------------------

def test_evaluate_accepts_valid():
    decision = evaluate_request({"address": SENTRY})
    assert isinstance(decision, AcceptanceDecision)
    assert decision.accept is True
    assert decision.target == SENTRY
    assert SENTRY in decision.reason


def test_evaluate_rejects_missing_address():
    decision = evaluate_request({"foo": "bar"})
    assert decision.accept is False
    assert decision.target is None
    assert "0x" in decision.reason  # tells the buyer how to phrase it


# --- build_deliverable ------------------------------------------------------

def _baseline_trust_json() -> dict:
    path = Path(__file__).resolve().parents[1] / "scans" / "baseline-sentryagent-sepolia-2026-06-09.json"
    return json.loads(path.read_text())


def test_build_deliverable_shape():
    trust = _baseline_trust_json()
    deliverable = build_deliverable(trust)
    assert deliverable["type"] == "object"
    assert deliverable["service"] == SERVICE_NAME
    assert deliverable["value"] == trust
    assert "80/100" in deliverable["summary"]
    assert "grade B" in deliverable["summary"]
    # Must be JSON-serializable for the SDK to deliver it.
    json.dumps(deliverable)


def test_build_deliverable_unrated_note():
    deliverable = build_deliverable(
        {"agent": SENTRY, "score": 40, "grade": "D", "rated": False}
    )
    assert "Unrated" in deliverable["summary"]


# --- run_scan (subprocess mocked) -------------------------------------------

def test_run_scan_requires_api_key(monkeypatch):
    monkeypatch.delenv("BASESCAN_API_KEY", raising=False)
    with pytest.raises(ScanError, match="BASESCAN_API_KEY"):
        run_scan(SENTRY)


def test_run_scan_success(monkeypatch, tmp_path):
    trust = _baseline_trust_json()

    def fake_run(cmd, capture_output, text, timeout, env):  # noqa: ARG001
        # The CLI writes JSON to the path given after --output.
        out = Path(cmd[cmd.index("--output") + 1])
        out.write_text(json.dumps(trust))
        # Key must be passed via env, never on argv.
        assert "--basescan-key" not in cmd
        assert env.get("BASESCAN_API_KEY") == "test-key"

        class P:
            returncode = 0
            stdout = ""
            stderr = ""

        return P()

    monkeypatch.setenv("BASESCAN_API_KEY", "test-key")
    monkeypatch.setattr(executor_mod.subprocess, "run", fake_run)
    result = run_scan(SENTRY, chain="base-sepolia")
    assert result["score"] == 80
    assert result["agent"] == trust["agent"]


def test_run_scan_propagates_failure(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout, env):  # noqa: ARG001
        class P:
            returncode = 1
            stdout = ""
            stderr = "boom"

        return P()

    monkeypatch.setenv("BASESCAN_API_KEY", "test-key")
    monkeypatch.setattr(executor_mod.subprocess, "run", fake_run)
    with pytest.raises(ScanError, match="boom"):
        run_scan(SENTRY)


def test_run_scan_missing_output(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout, env):  # noqa: ARG001
        class P:
            returncode = 0
            stdout = ""
            stderr = ""

        return P()  # does not write the output file

    monkeypatch.setenv("BASESCAN_API_KEY", "test-key")
    monkeypatch.setattr(executor_mod.subprocess, "run", fake_run)
    with pytest.raises(ScanError, match="no output"):
        run_scan(SENTRY)
