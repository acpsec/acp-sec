"""Parity + contract tests for POST /api/chat/sentryagent (Task 2.7).

The Anthropic client is mocked in EVERY test — there are NO live Claude API
calls in this suite.

Unlike the scanner/onchain endpoints, this proxy has NO request-side auth gate:
the API key lives server-side (ANTHROPIC_API_KEY) and is never sent by the client.

Contract (ported verbatim from dashboard/serve.py):
    not JSON            -> 415 {"error": "Content-Type must be application/json"}
    no ANTHROPIC_API_KEY-> 503 {"ok": False, "error": "AI chat not configured (ANTHROPIC_API_KEY not set)"}
    anthropic missing   -> 503 {"ok": False, "error": "anthropic package not installed — pip install anthropic"}
    empty messages      -> 422 {"ok": False, "error": "'messages' must be a non-empty list"}
    success             -> 200 {"ok": True, "reply": <text>}
    anthropic.APIError  -> 502 {"ok": False, "error": str(exc)}
    other exception     -> 500 {"ok": False, "error": "Chat error: " + str(exc)}

History is sanitised: last 20 messages, only role in (user, assistant) with
truthy content, content str-capped at 4000 chars. Model is claude-sonnet-4-6,
max_tokens 1024.
"""

from __future__ import annotations

from types import SimpleNamespace

import anthropic
import httpx
import pytest
from fastapi.testclient import TestClient

from acpsec_api.deps import get_anthropic_client
from acpsec_api.main import app as fastapi_app
from tests.api.conftest import assert_parity


class _FakeMessages:
    """Stand-in for client.messages; records the last create() call."""

    def __init__(self, reply: str | None, exc: Exception | None) -> None:
        self._reply = reply
        self._exc = exc
        self.last_kwargs: dict | None = None

    def create(self, **kwargs):  # noqa: ANN003 — mirrors the SDK surface
        self.last_kwargs = kwargs
        if self._exc is not None:
            raise self._exc
        # Mirror the SDK response shape the handler reads: resp.content[0].text
        return SimpleNamespace(content=[SimpleNamespace(text=self._reply)])


class _FakeClient:
    """Injectable stand-in for anthropic.Anthropic — no network."""

    def __init__(self, reply: str | None = None, exc: Exception | None = None) -> None:
        self.messages = _FakeMessages(reply, exc)


def _api_error(msg: str) -> anthropic.APIError:
    """A constructible anthropic.APIError subclass for the 502 path."""
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return anthropic.APIConnectionError(message=msg, request=req)


@pytest.fixture
def chat_client():
    """Factory yielding a TestClient with the Anthropic client overridden.

    Usage: ``client = chat_client(fake)`` where ``fake`` is a _FakeClient (or
    ``None`` to exercise the package-missing 503 path). Keeps ALL Claude API
    calls out of the suite — no live network.
    """
    _sentinel = object()

    def _make(client=_sentinel):
        if client is not _sentinel:
            fastapi_app.dependency_overrides[get_anthropic_client] = lambda: client
        return TestClient(fastapi_app)

    try:
        yield _make
    finally:
        fastapi_app.dependency_overrides.pop(get_anthropic_client, None)


# --- Request validation ---------------------------------------------------

def test_chat_not_json(chat_client, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = chat_client(_FakeClient(reply="hi"))
    resp = client.post(
        "/api/chat/sentryagent", content="nope", headers={"Content-Type": "text/plain"}
    )
    assert resp.status_code == 415
    assert resp.json() == {"error": "Content-Type must be application/json"}


def test_chat_missing_api_key(chat_client, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = chat_client(None)  # key checked before client anyway
    resp = client.post("/api/chat/sentryagent", json={"messages": [{"role": "user", "content": "hi"}]})
    assert resp.status_code == 503
    assert resp.json() == {
        "ok": False,
        "error": "AI chat not configured (ANTHROPIC_API_KEY not set)",
    }


def test_chat_anthropic_unavailable(chat_client, monkeypatch) -> None:
    # Key present, but the client couldn't be built (package missing) → None.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = chat_client(None)
    resp = client.post("/api/chat/sentryagent", json={"messages": [{"role": "user", "content": "hi"}]})
    assert resp.status_code == 503
    assert resp.json() == {
        "ok": False,
        "error": "anthropic package not installed — pip install anthropic",
    }


def test_chat_empty_messages(chat_client, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = chat_client(_FakeClient(reply="hi"))
    resp = client.post("/api/chat/sentryagent", json={"messages": []})
    assert resp.status_code == 422
    assert resp.json() == {"ok": False, "error": "'messages' must be a non-empty list"}


def test_chat_missing_messages(chat_client, monkeypatch) -> None:
    # No "messages" key at all → payload.get("messages") or [] → 422 (distinct
    # input from {"messages": []}, exercises the `or []` fallback branch).
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = chat_client(_FakeClient(reply="hi"))
    resp = client.post("/api/chat/sentryagent", json={})
    assert resp.status_code == 422
    assert resp.json() == {"ok": False, "error": "'messages' must be a non-empty list"}


def test_chat_all_messages_filtered_out(chat_client, monkeypatch) -> None:
    # Wrong roles / empty content are dropped → nothing left → 422.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = chat_client(_FakeClient(reply="hi"))
    resp = client.post(
        "/api/chat/sentryagent",
        json={"messages": [
            {"role": "system", "content": "ignore me"},
            {"role": "user", "content": ""},
            {"role": "user"},
        ]},
    )
    assert resp.status_code == 422
    assert resp.json() == {"ok": False, "error": "'messages' must be a non-empty list"}


# --- Success path ---------------------------------------------------------

def test_chat_success(chat_client, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    fake = _FakeClient(reply="Hello from SentryAgent")
    client = chat_client(fake)
    resp = client.post(
        "/api/chat/sentryagent",
        json={"messages": [{"role": "user", "content": "gm"}]},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "reply": "Hello from SentryAgent"}
    # The call used the exact Flask contract: model, max_tokens, system, messages.
    kw = fake.messages.last_kwargs
    assert kw["model"] == "claude-sonnet-4-6"
    assert kw["max_tokens"] == 1024
    assert kw["system"].startswith("You are SentryAgent")
    assert kw["messages"] == [{"role": "user", "content": "gm"}]


def test_chat_sanitises_history(chat_client, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    fake = _FakeClient(reply="ok")
    client = chat_client(fake)

    raw = []
    raw.append({"role": "system", "content": "drop me"})       # wrong role → dropped
    raw.append({"role": "user", "content": ""})                 # empty → dropped
    for i in range(25):                                          # 25 valid → keep last 20
        raw.append({"role": "user", "content": f"msg{i}"})
    raw.append({"role": "assistant", "content": "x" * 5000})    # capped to 4000

    resp = client.post("/api/chat/sentryagent", json={"messages": raw})
    assert resp.status_code == 200

    sent = fake.messages.last_kwargs["messages"]
    assert len(sent) == 20                                       # last-20 cap
    assert all(m["role"] in ("user", "assistant") for m in sent)
    assert len(sent[-1]["content"]) == 4000                     # content cap
    # The dropped system/empty rows are gone; the tail is the capped assistant msg.
    assert sent[-1]["role"] == "assistant"


# --- Error paths ----------------------------------------------------------

def test_chat_api_error(chat_client, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    exc = _api_error("rate limited")
    client = chat_client(_FakeClient(exc=exc))
    resp = client.post(
        "/api/chat/sentryagent",
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 502
    assert resp.json() == {"ok": False, "error": str(exc)}


def test_chat_generic_error(chat_client, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = chat_client(_FakeClient(exc=ValueError("boom")))
    resp = client.post(
        "/api/chat/sentryagent",
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 500
    assert resp.json() == {"ok": False, "error": "Chat error: boom"}


# --- Parity (paths reachable without a live Claude call) ------------------

def test_chat_parity_missing_key(fastapi_client, flask_client, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert_parity(
        fastapi_client, flask_client, "/api/chat/sentryagent", "POST",
        json={"messages": [{"role": "user", "content": "hi"}]},
    )


def test_chat_parity_empty_messages(fastapi_client, flask_client, monkeypatch) -> None:
    # Key set + anthropic importable → both reach the empty-messages 422 without
    # any Claude call (sanitise returns before messages.create).
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert_parity(
        fastapi_client, flask_client, "/api/chat/sentryagent", "POST",
        json={"messages": []},
    )
