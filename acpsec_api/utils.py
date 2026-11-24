"""Shared helpers for acpsec_api routers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import Request


def atomic_write_text(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` atomically (temp file in the same dir +
    ``os.replace``): a concurrent reader sees the old or the new file, never a
    partial one. Raises OSError like ``Path.write_text``."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def is_json_request(request: Request) -> bool:
    """Mirror Flask/Werkzeug ``request.is_json``: the request mimetype is JSON.

    Consolidated single source (Task 2.9) — previously duplicated verbatim in
    the score/scanner/onchain/chat routers. Used to reproduce Flask's 415
    "Content-Type must be application/json" guard on POST endpoints.
    """
    mimetype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    return mimetype == "application/json" or mimetype.endswith("+json")
