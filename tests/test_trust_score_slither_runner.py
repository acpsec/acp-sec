"""Tests for acpsec/trust_score/data/slither_runner.py — TDD RED."""

import json
import pytest


# ---------------------------------------------------------------------------
# Helpers — stub subprocess runner
# ---------------------------------------------------------------------------

def _subprocess_for(returncode: int, stdout: str, stderr: str = ""):
    """Returns a subprocess callable that yields fixed (returncode, stdout, stderr)."""
    def runner(cmd: list[str]) -> tuple[int, str, str]:
        return returncode, stdout, stderr
    return runner


def _capturing_runner(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """Returns (runner, calls_list) — calls_list collects commands invoked."""
    calls = []
    def runner(cmd: list[str]) -> tuple[int, str, str]:
        calls.append(cmd)
        return returncode, stdout, stderr
    return runner, calls


def _slither_json(detectors: list[dict], success: bool = True) -> str:
    return json.dumps({
        "success": success,
        "error": None if success else "compilation error",
        "results": {"detectors": detectors},
    })


def _detector(check: str, impact: str, confidence: str = "Medium", description: str = "x") -> dict:
    return {"check": check, "impact": impact, "confidence": confidence, "description": description}


# ---------------------------------------------------------------------------
# SlitherFinding — data shape
# ---------------------------------------------------------------------------

class TestSlitherFinding:
    def test_has_expected_fields(self):
        from acpsec.trust_score.data.slither_runner import SlitherFinding
        f = SlitherFinding(check="reentrancy-eth", impact="High", confidence="Medium", description="...")
        assert f.check == "reentrancy-eth"
        assert f.impact == "High"
        assert f.confidence == "Medium"
        assert f.description == "..."


# ---------------------------------------------------------------------------
# SlitherRunner.run — happy path
# ---------------------------------------------------------------------------

class TestRunNoFindings:
    def _client(self, stdout: str = "", returncode: int = 0):
        from acpsec.trust_score.data.slither_runner import SlitherRunner
        return SlitherRunner(_subprocess_run=_subprocess_for(returncode, stdout))

    def test_empty_detectors_returns_empty_list(self):
        client = self._client(_slither_json([]))
        assert client.run("0x1234") == []

    def test_returns_list_type(self):
        client = self._client(_slither_json([]))
        assert isinstance(client.run("0x1234"), list)


class TestRunWithFindings:
    def _client(self, detectors: list[dict], returncode: int = 0):
        from acpsec.trust_score.data.slither_runner import SlitherRunner
        stdout = _slither_json(detectors)
        return SlitherRunner(_subprocess_run=_subprocess_for(returncode, stdout))

    def test_reentrancy_finding_parsed(self):
        client = self._client([_detector("reentrancy-eth", "High")])
        results = client.run("0x1234")
        assert len(results) == 1
        assert results[0].check == "reentrancy-eth"

    def test_high_impact_preserved(self):
        client = self._client([_detector("reentrancy-eth", "High")])
        assert client.run("0x1234")[0].impact == "High"

    def test_medium_impact_preserved(self):
        client = self._client([_detector("tx-origin", "Medium")])
        assert client.run("0x1234")[0].impact == "Medium"

    def test_low_impact_preserved(self):
        client = self._client([_detector("pragma", "Low")])
        assert client.run("0x1234")[0].impact == "Low"

    def test_informational_findings_excluded(self):
        client = self._client([
            _detector("reentrancy-eth", "High"),
            _detector("naming-convention", "Informational"),
        ])
        results = client.run("0x1234")
        assert len(results) == 1
        assert results[0].impact == "High"

    def test_multiple_findings_all_returned(self):
        client = self._client([
            _detector("reentrancy-eth", "High"),
            _detector("tx-origin", "Medium"),
            _detector("suicidal", "High"),
        ])
        assert len(client.run("0x1234")) == 3

    def test_description_stored(self):
        client = self._client([_detector("reentrancy-eth", "High", description="Foo.bar re-enters")])
        assert client.run("0x1234")[0].description == "Foo.bar re-enters"

    def test_nonzero_exit_with_valid_json_still_returns_findings(self):
        # Slither exits non-zero when findings exist — should still parse
        client = self._client([_detector("reentrancy-eth", "High")], returncode=1)
        assert len(client.run("0x1234")) == 1


# ---------------------------------------------------------------------------
# SlitherRunner.run — error cases
# ---------------------------------------------------------------------------

class TestRunErrors:
    def test_success_false_raises_slither_error(self):
        from acpsec.trust_score.data.slither_runner import SlitherRunner, SlitherError
        stdout = _slither_json([], success=False)
        client = SlitherRunner(_subprocess_run=_subprocess_for(2, stdout))
        with pytest.raises(SlitherError):
            client.run("0x1234")

    def test_invalid_json_output_raises_slither_error(self):
        from acpsec.trust_score.data.slither_runner import SlitherRunner, SlitherError
        client = SlitherRunner(_subprocess_run=_subprocess_for(1, "not json at all"))
        with pytest.raises(SlitherError):
            client.run("0x1234")

    def test_slither_not_installed_raises_slither_not_available(self):
        from acpsec.trust_score.data.slither_runner import SlitherRunner, SlitherNotAvailable
        def missing(_cmd):
            raise FileNotFoundError("slither: not found")
        client = SlitherRunner(_subprocess_run=missing)
        with pytest.raises(SlitherNotAvailable):
            client.run("0x1234")


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------

class TestCommandConstruction:
    def test_target_address_in_command(self):
        from acpsec.trust_score.data.slither_runner import SlitherRunner
        runner, calls = _capturing_runner(0, _slither_json([]))
        SlitherRunner(_subprocess_run=runner).run("0xDEAD")
        assert any("0xDEAD" in arg for arg in calls[0])

    def test_json_flag_in_command(self):
        from acpsec.trust_score.data.slither_runner import SlitherRunner
        runner, calls = _capturing_runner(0, _slither_json([]))
        SlitherRunner(_subprocess_run=runner).run("0xDEAD")
        cmd = calls[0]
        assert "--json" in cmd or "-" in cmd

    def test_etherscan_api_key_in_command_when_provided(self):
        from acpsec.trust_score.data.slither_runner import SlitherRunner
        runner, calls = _capturing_runner(0, _slither_json([]))
        SlitherRunner(_subprocess_run=runner).run("0xDEAD", api_key="MY_KEY")
        cmd = calls[0]
        assert "MY_KEY" in cmd

    def test_no_api_key_flag_when_not_provided(self):
        from acpsec.trust_score.data.slither_runner import SlitherRunner
        runner, calls = _capturing_runner(0, _slither_json([]))
        SlitherRunner(_subprocess_run=runner).run("0xDEAD")
        cmd = calls[0]
        assert "--etherscan-apikey" not in cmd

    def test_custom_executable_used(self):
        from acpsec.trust_score.data.slither_runner import SlitherRunner
        runner, calls = _capturing_runner(0, _slither_json([]))
        SlitherRunner(executable="/opt/slither/bin/slither", _subprocess_run=runner).run("0xDEAD")
        assert calls[0][0] == "/opt/slither/bin/slither"
