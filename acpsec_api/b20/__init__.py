"""acp-sec/b20 — read-only Trust Score scanner for B20 native tokens on Base.

Vendored verbatim from the standalone ``acp-sec-b20`` repo (Task 7.1a): the
pure-stdlib scoring engine (constants/dimensions/engine/models/reader/rpc) is
copied with zero behaviour change so ``/api/b20/scan`` shares a single origin
with the rest of acpsec_api. The FastAPI layer is NOT vendored — it is
re-expressed as ``acpsec_api.routers.b20``. ``__version__`` is preserved because
the engine surfaces it as ``scanner_version`` in every scan payload.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("acpsec")
except PackageNotFoundError:
    __version__ = "dev"
