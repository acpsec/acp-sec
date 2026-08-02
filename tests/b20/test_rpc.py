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


def test_transient_exception_retried_then_none():
    calls = []

    def transport(payload):
        calls.append(1)
        raise TimeoutError("slow")

    assert _retry_client(transport).eth_call("0xabc", "0x") is None
    assert len(calls) == _MAX_ATTEMPTS  # bounded retries on a transient exception


def test_transient_error_then_success():
    calls = []

    def transport(payload):
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionError("flaky")
        return {"result": "0xbeef"}

    assert _retry_client(transport).eth_call("0xabc", "0x") == "0xbeef"
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
    c = _retry_client(boom)
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
import urllib.error  # noqa: E402 — grouped with this test section (verbatim port)
import urllib.request  # noqa: E402

from acpsec_api.b20.rpc import _default_transport  # noqa: E402


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
    c = _retry_client(transport)
    assert c.eth_call("0xabc", "0x") is None
    assert c.any_response is False


# ── #24: bounded backoff on TRANSIENT failures + per-chain RPC config ────────
from acpsec_api.b20.constants import CHAIN_RPC_ENDPOINTS  # noqa: E402
from acpsec_api.b20.rpc import (  # noqa: E402
    _BACKOFF_CAP,
    _MAX_ATTEMPTS,
    resolve_rpc_endpoint,
)


def _retry_client(transport, sleep=None):
    # No-op sleeper by default so bounded-backoff retries never actually wait.
    return RpcClient(8453, _transport=transport, _sleep=sleep or (lambda _d: None))


def _http(code, reason, retry_after=None):
    hdrs = {"Retry-After": retry_after} if retry_after is not None else {}
    return urllib.error.HTTPError("https://rpc.test", code, reason, hdrs, None)


def test_transient_429_retried_then_succeeds():
    calls = []

    def transport(payload):
        calls.append(1)
        if len(calls) <= 2:
            raise _http(429, "Too Many Requests")
        return {"result": [{"topics": ["0xaa"]}]}

    assert _retry_client(transport).eth_get_logs({"address": "0x"}) == [{"topics": ["0xaa"]}]
    assert len(calls) == 3  # 429, 429, success


def test_permanent_transient_returns_none_after_bounded_retries():
    calls = []

    def transport(payload):
        calls.append(1)
        raise _http(429, "Too Many Requests")

    assert _retry_client(transport).eth_get_logs({"address": "0x"}) is None
    assert len(calls) == _MAX_ATTEMPTS  # bounded — the loop never masks a real failure


def test_5xx_is_transient_and_retried():
    calls = []

    def transport(payload):
        calls.append(1)
        if len(calls) == 1:
            raise _http(503, "Service Unavailable")
        return {"result": "0x1"}

    assert _retry_client(transport).eth_call("0x", "0x") == "0x1"
    assert len(calls) == 2


def test_json_rpc_rate_limit_code_is_transient_and_retried():
    calls = []

    def transport(payload):
        calls.append(1)
        if len(calls) == 1:
            return {"error": {"code": -32005, "message": "limit exceeded"}}
        return {"result": "0x1"}

    assert _retry_client(transport).eth_call("0x", "0x") == "0x1"
    assert len(calls) == 2


def test_contract_revert_is_not_retried():
    calls = []

    def transport(payload):
        calls.append(1)
        return {"error": {"code": -32000, "message": "execution reverted"}}

    assert _retry_client(transport).eth_call("0x", "0x") is None
    assert len(calls) == 1  # a revert is DATA, not noise — exactly one call


def test_definitive_4xx_is_not_retried():
    calls = []

    def transport(payload):
        calls.append(1)
        raise _http(400, "Bad Request")

    assert _retry_client(transport).eth_call("0x", "0x") is None
    assert len(calls) == 1


def test_retry_after_honored_but_capped():
    slept, calls = [], []

    def transport(payload):
        calls.append(1)
        if len(calls) == 1:
            raise _http(429, "Too Many Requests", retry_after="5")  # server asks 5s
        return {"result": "0x1"}

    c = _retry_client(transport, sleep=lambda d: slept.append(d))
    assert c.eth_call("0x", "0x") == "0x1"
    assert slept == [_BACKOFF_CAP]  # honored, but capped to keep the sync scan bounded


def test_config_per_chain_env_routes_endpoint(monkeypatch):
    monkeypatch.setenv("B20_RPC_URL_8453", "https://mainnet.provider.test/key")
    monkeypatch.delenv("B20_RPC_URL_84532", raising=False)
    assert RpcClient(8453, _transport=lambda p: {}).url == "https://mainnet.provider.test/key"
    # the unset chain keeps its hardcoded public default
    assert RpcClient(84532, _transport=lambda p: {}).url == CHAIN_RPC_ENDPOINTS[84532]


def test_zero_config_is_todays_public_endpoint(monkeypatch):
    monkeypatch.delenv("B20_RPC_URL_8453", raising=False)
    assert resolve_rpc_endpoint(8453) == CHAIN_RPC_ENDPOINTS[8453]
