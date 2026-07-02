"""Shared fixtures + parity helper for FastAPI endpoint tests.

Every ported endpoint is validated two ways:
  1. Direct contract assertions against the FastAPI app.
  2. Byte-for-byte parity against the legacy Flask handler in
     ``dashboard/serve.py`` — the migration reference — via ``assert_parity``.

The Flask app is used strictly as a read-only oracle here; the parity tests
must keep passing until cutover, so nothing in this file should mutate it.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from acpsec_api.main import app as fastapi_app
from dashboard.serve import app as flask_app


@pytest.fixture
def fastapi_client() -> TestClient:
    """TestClient bound to the FastAPI app under migration."""
    return TestClient(fastapi_app)


@pytest.fixture
def flask_client():
    """Werkzeug test client bound to the legacy Flask reference app."""
    return flask_app.test_client()


def assert_parity(
    fastapi_client: TestClient,
    flask_client: Any,
    endpoint: str,
    method: str = "GET",
    **kwargs: Any,
) -> None:
    """Hit both apps with identical args; assert identical status + JSON.

    Raises AssertionError with a diff-friendly message on any mismatch so a
    failing parity test points straight at the divergent field.
    """
    method = method.upper()

    fa_resp = fastapi_client.request(method, endpoint, **kwargs)
    fl_resp = flask_client.open(endpoint, method=method, **kwargs)

    assert fa_resp.status_code == fl_resp.status_code, (
        f"status mismatch on {method} {endpoint}: "
        f"FastAPI={fa_resp.status_code} Flask={fl_resp.status_code}"
    )

    fa_json = fa_resp.json()
    fl_json = fl_resp.get_json()
    assert fa_json == fl_json, (
        f"JSON mismatch on {method} {endpoint}:\n"
        f"  FastAPI={fa_json!r}\n"
        f"  Flask  ={fl_json!r}"
    )
