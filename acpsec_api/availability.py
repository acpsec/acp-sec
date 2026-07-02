"""Single source of truth for acpsec package availability.

Mirrors the Flask import probe in dashboard/serve.py: ``ACPSEC_AVAILABLE`` is
True iff the scoring, model, and catalogue modules all import cleanly. Resolved
once at import time so consumers get a cheap flag, not a per-request import.
"""

from __future__ import annotations

try:
    from acpsec.scorer import ScoringEngine  # noqa: F401
    from acpsec.models import CheckStatus  # noqa: F401
    from acpsec.catalogue import get_check_catalogue  # noqa: F401

    ACPSEC_AVAILABLE = True
except ImportError:
    ACPSEC_AVAILABLE = False
