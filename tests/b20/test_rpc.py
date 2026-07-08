"""JSON-RPC client (task 3.1) — mocked transport, no live network."""

import pytest

from acpsec_api.b20.rpc import RpcClient


def _client(transport):
    return RpcClient(8453, _transport=transport)


def test_unsupported_chain_id_rejected_at_construction():
    with pytest.raises(ValueError):
        RpcClient(1)
    with pytest.raises(ValueError):
        RpcClient(84531)  # near-miss


def test_supported_chains_construct():
    assert RpcClient(8453, _transport=lambda p: {"result": "0x"}).chain_id == 8453
    assert RpcClient(84532, _transport=lambda p: {"result": "0x"}).chain_id == 84532


def test_eth_call_success():
    def transport(payload):
        assert payload["method"] == "eth_call"
        assert payload["params"][0] == {"to": "0xabc", "data": "0xdata"}
        assert payload["params"][1] == "latest"
        return {"jsonrpc": "2.0", "id": 1, "result": "0x01"}
    assert _client(transport).eth_call("0xabc", "0xdata") == "0x01"


def test_rpc_error_response_returns_none():
    def transport(payload):
        return {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}}
    assert _client(transport).eth_call("0xabc", "0x") is None


def test_malformed_response_returns_none():
    def transport(payload):
        return {"jsonrpc": "2.0", "id": 1}  # no result, no error
    assert _client(transport).eth_call("0xabc", "0x") is None


def test_timeout_retries_once_then_returns_none():
    calls = []

    def transport(payload):
        calls.append(1)
        raise TimeoutError("slow")

    assert _client(transport).eth_call("0xabc", "0x") is None
    assert len(calls) == 2  # initial + one retry


def test_transient_error_then_success():
    calls = []

    def transport(payload):
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionError("flaky")
        return {"result": "0xbeef"}

    assert _client(transport).eth_call("0xabc", "0x") == "0xbeef"
    assert len(calls) == 2


def test_eth_get_code_passthrough():
    def transport(payload):
        assert payload["method"] == "eth_getCode"
        return {"result": "0x60016002"}
    assert _client(transport).eth_get_code("0xabc") == "0x60016002"


def test_eth_get_logs_passthrough():
    def transport(payload):
        assert payload["method"] == "eth_getLogs"
        return {"result": [{"topics": ["0xaa"]}]}
    assert _client(transport).eth_get_logs({"address": "0xabc"}) == [{"topics": ["0xaa"]}]


def test_eth_get_transaction_count_passthrough():
    def transport(payload):
        assert payload["method"] == "eth_getTransactionCount"
        return {"result": "0x5"}
    assert _client(transport).eth_get_transaction_count("0xabc") == "0x5"


# --- connectivity tracking (for CLI exit-code 2: entirely unreachable) -----
def test_attempts_and_any_response_start_zero_false():
    c = _client(lambda p: {"result": "0x1"})
    assert c.attempts == 0
    assert c.any_response is False


def test_success_sets_any_response_and_increments_attempts():
    c = _client(lambda p: {"result": "0x1"})
    c.eth_call("0xabc", "0x")
    assert c.attempts == 1
    assert c.any_response is True


def test_all_transport_failures_leave_any_response_false():
    def boom(payload):
        raise TimeoutError("down")
    c = _client(boom)
    c.eth_call("0xabc", "0x")
    assert c.attempts == 1
    assert c.any_response is False


def test_rpc_error_response_still_counts_as_reachable():
    # node responded (with an error) -> reachable, so any_response is True
    c = _client(lambda p: {"error": {"code": -1, "message": "x"}})
    c.eth_call("0xabc", "0x")
    assert c.any_response is True


def test_eth_block_number_decodes_hex():
    c = _client(lambda p: {"result": "0x10"})
    assert c.eth_block_number() == 16


def test_eth_block_number_none_on_failure():
    def boom(payload):
        raise TimeoutError("down")
    assert _client(boom).eth_block_number() is None


# --- User-Agent + HTTPError reachability (Cloudflare 1010 fix) --------------
import urllib.error
import urllib.request

from acpsec_api.b20.rpc import _default_transport


def test_default_user_agent_is_not_python_urllib(monkeypatch):
    # Public Base RPC (Cloudflare) returns 403 error 1010 to the default
    # "Python-urllib/*" UA; we must send a project-identifying UA instead.
    captured = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"jsonrpc":"2.0","id":1,"result":"0x1"}'

    def fake_urlopen(req, timeout=None):
        captured["ua"] = req.get_header("User-agent")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    _default_transport("https://example.test", 10.0)(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})
    ua = captured["ua"]
    assert ua is not None and not ua.startswith("Python-")
    assert "acp-sec-b20" in ua


def _http_error():
    return urllib.error.HTTPError("https://x.test", 403, "Forbidden", {}, None)


def test_http_error_marks_endpoint_reachable():
    # A 4xx/5xx is a definitive reachability signal — the node responded.
    def transport(payload):
        raise _http_error()
    c = _client(transport)
    assert c.eth_call("0xabc", "0x") is None   # the call still fails
    assert c.attempts == 1
    assert c.any_response is True              # ...but the endpoint is reachable


def test_dns_failure_stays_unreachable():
    # Non-HTTP transport failures (DNS/connection/timeout) remain "unreachable".
    def transport(payload):
        raise urllib.error.URLError("name resolution failed")
    c = _client(transport)
    assert c.eth_call("0xabc", "0x") is None
    assert c.any_response is False
