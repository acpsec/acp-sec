"""Shared helpers for acpsec_api routers."""

from __future__ import annotations

from fastapi import Request


def is_json_request(request: Request) -> bool:
    """Mirror Flask/Werkzeug ``request.is_json``: the request mimetype is JSON.

    Consolidated single source (Task 2.9) — previously duplicated verbatim in
    the score/scanner/onchain/chat routers. Used to reproduce Flask's 415
    "Content-Type must be application/json" guard on POST endpoints.
    """
    mimetype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    return mimetype == "application/json" or mimetype.endswith("+json")
