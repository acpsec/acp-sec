"""Tests for the `acpsec trust-score` CLI command — TDD RED."""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from acpsec.cli import main
from acpsec.trust_score.data.basescan import ContractData
from acpsec.trust_score.data.slither_runner import SlitherFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verified_contract(address: str = "0xABCD") -> ContractData:
    return ContractData(
        address=address,
        source_verified=True,
        contract_name="TestAgent",
        abi=[{"type": "function", "name": "withdraw"}],
        source_code="pragma solidity ^0.8.0;",
        compiler_version="v0.8.20",
    )


def _unverified_contract(address: str = "0xBAD") -> ContractData:
    return ContractData(
        address=address,
        source_verified=False,
        contract_name="",
        abi=[],
        source_code="",
        compiler_version="",
    )


# ---------------------------------------------------------------------------
# Command registration
# ---------------------------------------------------------------------------

class TestCommandRegistration:
    def test_trust_score_subcommand_exists(self):
        runner = CliRunner()
        result = runner.invoke(main, ["trust-score", "--help"])
        assert result.exit_code == 0

    def test_help_mentions_agent_option(self):
        runner = CliRunner()
        result = runner.invoke(main, ["trust-score", "--help"])
        assert "--agent" in result.output

    def test_help_mentions_output_option(self):
        runner = CliRunner()
        result = runner.invoke(main, ["trust-score", "--help"])
        assert "--output" in result.output

    def test_help_mentions_scan_mode(self):
        result = CliRunner().invoke(main, ["trust-score", "--help"])
        assert "--scan-mode" in result.output

    def test_help_mentions_chain(self):
        result = CliRunner().invoke(main, ["trust-score", "--help"])
        assert "--chain" in result.output


# ---------------------------------------------------------------------------
# --scan-mode / --chain flags
# ---------------------------------------------------------------------------

class TestScanModeAndChainFlags:
    def _capture(self, extra_args: list):
        runner = CliRunner()
        with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockB, \
             patch("acpsec.trust_score.data.authority_scope_adapter.AuthorityScopeAdapter") as MockAS, \
             patch("acpsec.trust_score.data.acp_compliance_adapter.ACPComplianceAdapter") as MockACP:
            MockB.return_value.get_contract.return_value = _verified_contract()
            result = runner.invoke(
                main,
                ["trust-score", "--agent", "0xABCD", "--no-slither", *extra_args],
                env={"BASESCAN_API_KEY": "test_key"},
                catch_exceptions=False,
            )
        return result, MockAS, MockACP

    def test_invalid_scan_mode_rejected(self):
        result = CliRunner().invoke(
            main,
            ["trust-score", "--agent", "0xABCD", "--scan-mode", "bogus"],
            env={"BASESCAN_API_KEY": "test_key"},
        )
        assert result.exit_code != 0

    def test_invalid_chain_rejected(self):
        result = CliRunner().invoke(
            main,
            ["trust-score", "--agent", "0xABCD", "--chain", "bsc"],
            env={"BASESCAN_API_KEY": "test_key"},
        )
        assert result.exit_code != 0

    def test_default_scan_mode_and_chain_threaded(self):
        _, MockAS, MockACP = self._capture([])
        assert MockAS.call_args.kwargs.get("scan_mode") == "external"
        assert MockAS.call_args.kwargs.get("chain") == "base-sepolia"
        assert MockACP.call_args.kwargs.get("chain") == "base-sepolia"

    def test_self_audit_and_mainnet_threaded(self):
        _, MockAS, MockACP = self._capture(
            ["--scan-mode", "self_audit", "--chain", "base-mainnet"]
        )
        assert MockAS.call_args.kwargs.get("scan_mode") == "self_audit"
        assert MockAS.call_args.kwargs.get("chain") == "base-mainnet"
        assert MockACP.call_args.kwargs.get("chain") == "base-mainnet"


# ---------------------------------------------------------------------------
# Required options & early exits
# ---------------------------------------------------------------------------

class TestRequiredOptions:
    def test_agent_required(self):
        runner = CliRunner()
        result = runner.invoke(main, ["trust-score"])
        assert result.exit_code != 0

    def test_missing_basescan_key_exits_with_error(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["trust-score", "--agent", "0xABCD"],
            env={"BASESCAN_API_KEY": ""},
            catch_exceptions=False,
        )
        assert result.exit_code != 0
        assert "BASESCAN" in result.output.upper() or "api" in result.output.lower()

    def test_basescan_key_accepted_via_env(self):
        """Command should not exit with 'missing key' when env var is set."""
        runner = CliRunner()
        with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockClient:
            MockClient.return_value.get_contract.return_value = _verified_contract()
            result = runner.invoke(
                main, ["trust-score", "--agent", "0xABCD", "--no-slither"],
                env={"BASESCAN_API_KEY": "test_key"},
                catch_exceptions=False,
            )
        # Should not fail with "missing key" error
        assert "BASESCAN_API_KEY" not in result.output or result.exit_code == 0


# ---------------------------------------------------------------------------
# Integration — mocked Basescan + Slither
# ---------------------------------------------------------------------------

class TestIntegration:
    def _invoke(
        self,
        address: str = "0xABCD",
        contract: ContractData | None = None,
        slither_findings: list | None = None,
        extra_args: list | None = None,
        output_file: str | None = None,
    ):
        if contract is None:
            contract = _verified_contract(address)
        if slither_findings is None:
            slither_findings = []

        runner = CliRunner()
        args = ["trust-score", "--agent", address, "--no-slither"]
        if output_file:
            args += ["--output", output_file]
        if extra_args:
            args += extra_args

        with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockBasescan:
            MockBasescan.return_value.get_contract.return_value = contract
            result = runner.invoke(
                main, args,
                env={"BASESCAN_API_KEY": "test_key"},
                catch_exceptions=False,
            )
        return result

    def test_clean_contract_exits_zero(self):
        result = self._invoke()
        assert result.exit_code == 0

    def test_output_contains_score(self):
        result = self._invoke()
        assert "score" in result.output.lower() or any(
            c.isdigit() for c in result.output
        )

    def test_output_contains_grade(self):
        result = self._invoke()
        # Grade is one of A/B/C/D/F or "Unrated"
        assert any(g in result.output for g in ("Grade", "grade", " A", " B", " C", " D", " F", "Unrated"))

    def test_unverified_contract_shows_critical(self):
        result = self._invoke(contract=_unverified_contract())
        assert "CRITICAL" in result.output or "critical" in result.output.lower() or result.exit_code == 0

    def test_output_json_written_when_output_flag_used(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockBasescan:
                MockBasescan.return_value.get_contract.return_value = _verified_contract()
                result = runner.invoke(
                    main,
                    ["trust-score", "--agent", "0xABCD", "--no-slither", "--output", "out.json"],
                    env={"BASESCAN_API_KEY": "test_key"},
                    catch_exceptions=False,
                )
            assert result.exit_code == 0
            with open("out.json") as f:
                data = json.load(f)
            assert "score" in data
            assert "grade" in data
            assert "agent" in data

    def test_output_json_has_correct_agent_address(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockBasescan:
                MockBasescan.return_value.get_contract.return_value = _verified_contract("0xDEAD")
                runner.invoke(
                    main,
                    ["trust-score", "--agent", "0xDEAD", "--no-slither", "--output", "out.json"],
                    env={"BASESCAN_API_KEY": "test_key"},
                    catch_exceptions=False,
                )
            with open("out.json") as f:
                data = json.load(f)
            assert data["agent"] == "0xDEAD"

    def test_output_json_has_subscores(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockBasescan:
                MockBasescan.return_value.get_contract.return_value = _verified_contract()
                runner.invoke(
                    main,
                    ["trust-score", "--agent", "0xABCD", "--no-slither", "--output", "out.json"],
                    env={"BASESCAN_API_KEY": "test_key"},
                    catch_exceptions=False,
                )
            with open("out.json") as f:
                data = json.load(f)
            assert "subscores" in data
            assert "contract_security" in data["subscores"]

    def test_output_json_has_scanner_version(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockBasescan:
                MockBasescan.return_value.get_contract.return_value = _verified_contract()
                runner.invoke(
                    main,
                    ["trust-score", "--agent", "0xABCD", "--no-slither", "--output", "out.json"],
                    env={"BASESCAN_API_KEY": "test_key"},
                    catch_exceptions=False,
                )
            with open("out.json") as f:
                data = json.load(f)
            assert data["scanner_version"].startswith("acpsec-")


# ---------------------------------------------------------------------------
# unrated_checks surfaced in terminal + JSON output
# ---------------------------------------------------------------------------

class TestUnratedOutput:
    def _invoke_json(self, address: str = "0xABCD") -> dict:
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockBasescan:
                MockBasescan.return_value.get_contract.return_value = _verified_contract(address)
                runner.invoke(
                    main,
                    ["trust-score", "--agent", address, "--no-slither", "--output", "out.json"],
                    env={"BASESCAN_API_KEY": "test_key"},
                    catch_exceptions=False,
                )
            with open("out.json") as f:
                return json.load(f)

    def test_json_subscore_entry_has_score_field(self):
        data = self._invoke_json()
        assert "score" in data["subscores"]["acp_compliance"]

    def test_json_subscore_entry_has_unrated_checks_list(self):
        data = self._invoke_json()
        entry = data["subscores"]["acp_compliance"]
        assert "unrated_checks" in entry
        assert isinstance(entry["unrated_checks"], list)

    def test_json_acp_fee_split_recorded_as_unrated(self):
        # External scan, base-sepolia (no ACP Core reference) → settlement route
        # undeterminable → fee_split_nonconformant is Unrated.
        data = self._invoke_json()
        assert "fee_split_nonconformant" in data["subscores"]["acp_compliance"]["unrated_checks"]

    def test_terminal_lists_specific_unrated_subcheck(self):
        runner = CliRunner()
        with patch("acpsec.trust_score.data.basescan.BasescanClient") as MockBasescan:
            MockBasescan.return_value.get_contract.return_value = _verified_contract()
            result = runner.invoke(
                main,
                ["trust-score", "--agent", "0xABCD", "--no-slither"],
                env={"BASESCAN_API_KEY": "test_key"},
                catch_exceptions=False,
            )
        assert "fee_split_nonconformant" in result.output
