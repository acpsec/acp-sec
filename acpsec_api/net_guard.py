"""Outbound fetch guard for user-influenced URLs (SSRF hardening).

Every scanner fetch whose URL or host comes from request input goes through
``guarded_get``. The rules:

* scheme ``http``/``https`` only; port 80 or 443 only (explicit or default)
* host names: no ``localhost``/``*.localhost``, ``*.internal`` (which covers
  ``*.railway.internal``), ``*.local``, or single-label names (those resolve
  through container search domains to internal services)
* addresses: only globally routable unicast — see ``is_forbidden_ip``
* enforced at CONNECT time: the guarded urllib3 connection resolves the host
  once, vets every answer, and dials the vetted address itself, so DNS
  rebinding between a check and the connect cannot happen. An answer set with
  ANY forbidden address is refused outright
* redirects followed manually (at most ``MAX_REDIRECTS``), every hop re-checked
* ``verify=False`` retries take the identical path — only TLS checking differs
* the body is capped at ``max_bytes`` DECODED bytes (decompression is bounded)
* one wall-clock budget (``total_timeout``) spans every hop and the body: a
  watchdog shuts the call's sockets down when it expires, so slow-drip headers
  or bodies cannot hold a worker (name resolution is bounded by the system
  resolver's own timeout)
* environment proxies are ignored: a proxy resolves the target itself, which
  would bypass the connect-time check
"""

from __future__ import annotations

import ipaddress
import socket
import sys
import threading
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from requests.utils import requote_uri
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import (
    ConnectTimeoutError,
    DecodeError,
    LocationParseError,
    NameResolutionError,
    NewConnectionError,
    ProtocolError,
    ReadTimeoutError,
)
from urllib3.exceptions import SSLError as Urllib3SSLError
from urllib3.util import parse_url
from urllib3.util.connection import allowed_gai_family

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})
_DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_REDIRECTS = 5
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_TOTAL_TIMEOUT = 15.0

_BLOCKED_HOSTS = frozenset({"localhost"})
_BLOCKED_HOST_SUFFIXES = (".localhost", ".internal", ".local")

# Spelled out rather than trusting ipaddress's is_global/is_private alone:
# their exact coverage has shifted between Python patch releases.
_FORBIDDEN_V4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",        # "this network"
    "10.0.0.0/8",       # private
    "100.64.0.0/10",    # shared address space (CGNAT)
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local (cloud metadata lives here)
    "172.16.0.0/12",    # private
    "192.0.0.0/24",     # IETF protocol assignments
    "192.0.2.0/24",     # documentation
    "192.88.99.0/24",   # 6to4 relay anycast (deprecated)
    "192.168.0.0/16",   # private
    "198.18.0.0/15",    # benchmarking
    "198.51.100.0/24",  # documentation
    "203.0.113.0/24",   # documentation
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved, incl. 255.255.255.255
))
_FORBIDDEN_V6 = tuple(ipaddress.ip_network(n) for n in (
    "::/96",            # unspecified, loopback, IPv4-compatible (deprecated)
    "::ffff:0:0/96",    # IPv4-mapped — refused whatever the embedded address
    "64:ff9b:1::/48",   # local-use NAT64
    "100::/64",         # discard
    "2001::/32",        # Teredo
    "2001:db8::/32",    # documentation
    "fc00::/7",         # unique local (Railway private networking is fd12::/16)
    "fe80::/10",        # link-local
    "fec0::/10",        # site-local (deprecated)
    "ff00::/8",         # multicast
))
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR = ipaddress.ip_network("2002::/16")

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class BlockedDestination(requests.exceptions.ConnectionError):
    """The guard refused a destination. A ConnectionError subclass, so call
    sites that already treat fetch failures generically need no change."""


class _ForbiddenAddress(Exception):
    """Internal: raised while opening a socket to a refused destination."""


class _BlockedConnection(NewConnectionError):
    """Internal: urllib3-level carrier for a connect-time refusal."""

    def __init__(self, conn: Any, message: str) -> None:
        super().__init__(conn, message)
        self.guard_message = message


# --- Address and URL rules ----------------------------------------------------


def _parse_ip(text: str) -> _IPAddress | None:
    try:
        return ipaddress.ip_address(text.split("%", 1)[0])  # drop an IPv6 zone id
    except ValueError:
        return None


def is_forbidden_ip(ip: str | _IPAddress) -> bool:
    """True unless ``ip`` is globally routable unicast.

    IPv4-mapped IPv6 is refused outright. NAT64 (64:ff9b::/96) and 6to4
    (2002::/16) are judged solely by the IPv4 address they embed — that is
    where the packets actually go. Unparseable input counts as forbidden.
    """
    if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        parsed = _parse_ip(str(ip))
        if parsed is None:
            return True
        ip = parsed
    if ip.version == 6:
        ip = ipaddress.IPv6Address(int(ip))  # normalise away any scope id
        if any(ip in net for net in _FORBIDDEN_V6):
            return True
        if ip in _NAT64:
            return is_forbidden_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip in _SIXTOFOUR:
            return is_forbidden_ip(ip.sixtofour)
    elif any(ip in net for net in _FORBIDDEN_V4):
        return True
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified or not ip.is_global
    )


def check_host(host: str) -> None:
    """Raise BlockedDestination unless ``host`` (name or IP literal) is allowed.

    Name rules only — whether a NAME resolves somewhere forbidden is decided at
    connect time, on the answer actually dialed.
    """
    h = (host or "").strip().strip("[]").rstrip(".").lower()
    if not h:
        raise BlockedDestination("URL has no host")
    ip = _parse_ip(h)
    if ip is not None:
        if is_forbidden_ip(ip):
            raise BlockedDestination("destination address is not publicly routable")
        return
    if "." not in h:
        raise BlockedDestination("single-label host names are not allowed")
    if h in _BLOCKED_HOSTS or h.endswith(_BLOCKED_HOST_SUFFIXES):
        raise BlockedDestination(f"host {h!r} is not allowed")


def check_url(url: str) -> None:
    """Raise BlockedDestination unless ``url``'s scheme, port and host pass.

    Parsed with urllib3's ``parse_url`` — the parser requests itself uses to
    pick the host it connects to, so the check and the fetch cannot disagree.
    """
    try:
        parts = parse_url(url or "")
    except LocationParseError:
        raise BlockedDestination("unparseable URL") from None
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedDestination(f"scheme {scheme or '(none)'!r} is not allowed")
    if not parts.host:
        raise BlockedDestination("URL has no host")
    port = parts.port if parts.port is not None else _DEFAULT_PORTS[scheme]
    if port not in ALLOWED_PORTS:
        raise BlockedDestination(f"port {port} is not allowed")
    check_host(parts.host)


# --- Connect-time enforcement -------------------------------------------------

_CALL = threading.local()  # .deadline — the _Deadline of the guarded_get running on this thread


class _Deadline:
    """One call's wall-clock budget. On expiry, shuts down every socket the
    call opened — via a dup()'d descriptor, so a blocked read wakes up even
    mid-TLS-handshake, and no unrelated socket can ever be hit by fd reuse."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._expires = time.monotonic() + seconds
        self._fired = False
        self._lock = threading.Lock()
        self._watched: list[socket.socket] = []
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def remaining(self) -> float:
        return self._expires - time.monotonic()

    def expired(self) -> bool:
        return self._fired or self.remaining() <= 0

    def watch(self, sock: socket.socket) -> None:
        dup = sock.dup()
        with self._lock:
            self._watched.append(dup)
            fired = self._fired
        if fired:
            _shutdown(dup)

    def _fire(self) -> None:
        with self._lock:
            self._fired = True
            for dup in self._watched:
                _shutdown(dup)

    def close(self) -> None:
        self._timer.cancel()
        with self._lock:
            for dup in self._watched:
                try:
                    dup.close()
                except OSError:
                    pass
            self._watched.clear()


def _shutdown(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _open_vetted_socket(
    host: str, port: int, timeout: Any, source_address: Any, socket_options: Any
) -> socket.socket:
    """Resolve once, vet every answer, then dial only the vetted addresses.

    Mirrors urllib3.util.connection.create_connection, plus the checks.
    """
    if port not in ALLOWED_PORTS:
        raise _ForbiddenAddress(f"port {port} is not allowed")
    try:
        check_host(host)
    except BlockedDestination as exc:
        raise _ForbiddenAddress(str(exc)) from None

    infos = socket.getaddrinfo(host.strip("[]"), port, allowed_gai_family(), socket.SOCK_STREAM)
    if not infos:
        raise OSError("getaddrinfo returns an empty list")
    if any(is_forbidden_ip(sockaddr[0]) for *_, sockaddr in infos):
        raise _ForbiddenAddress("destination address is not publicly routable")

    err: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in infos:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            for opt in socket_options or ():
                sock.setsockopt(*opt)
            if timeout is None or isinstance(timeout, (int, float)):
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            err = exc
            if sock is not None:
                sock.close()
    assert err is not None
    raise err


class _GuardedConnectionMixin:
    """urllib3 connection whose socket comes from ``_open_vetted_socket``."""

    def _new_conn(self) -> socket.socket:
        # Same error mapping as urllib3.connection.HTTPConnection._new_conn.
        try:
            sock = _open_vetted_socket(
                self._dns_host, self.port, self.timeout,  # type: ignore[attr-defined]
                self.source_address, self.socket_options,  # type: ignore[attr-defined]
            )
        except _ForbiddenAddress as exc:
            raise _BlockedConnection(self, str(exc)) from None
        except socket.gaierror as exc:
            raise NameResolutionError(self.host, self, exc) from exc  # type: ignore[attr-defined]
        except TimeoutError as exc:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out. (connect timeout={self.timeout})",  # type: ignore[attr-defined]
            ) from exc
        except OSError as exc:
            raise NewConnectionError(self, f"Failed to establish a new connection: {exc}") from exc  # type: ignore[arg-type]

        deadline = getattr(_CALL, "deadline", None)
        if deadline is not None:
            deadline.watch(sock)
        sys.audit("http.client.connect", self, self.host, self.port)  # type: ignore[attr-defined]
        return sock


class _GuardedHTTPConnection(_GuardedConnectionMixin, HTTPConnection):
    pass


class _GuardedHTTPSConnection(_GuardedConnectionMixin, HTTPSConnection):
    pass


class _GuardedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _GuardedHTTPConnectionPool,
            "https": _GuardedHTTPSConnectionPool,
        }

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        raise BlockedDestination("proxies are not used for guarded fetches")


def _session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False  # no env proxies (see module docstring), no .netrc
    adapter = _GuardedAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# --- The fetch ------------------------------------------------------------------


def _budget_exceeded(deadline: _Deadline) -> requests.exceptions.ReadTimeout:
    return requests.exceptions.ReadTimeout(f"total time budget of {deadline.seconds:g}s exceeded")


def _hop_timeout(timeout: Any, deadline: _Deadline) -> tuple[float, float]:
    remaining = deadline.remaining()
    if remaining <= 0:
        raise _budget_exceeded(deadline)
    connect, read = timeout if isinstance(timeout, tuple) else (timeout, timeout)
    return (
        remaining if connect is None else min(connect, remaining),
        remaining if read is None else min(read, remaining),
    )


def _read_capped(resp: requests.Response, max_bytes: int, deadline: _Deadline) -> None:
    """Read at most ``max_bytes`` decoded bytes into ``resp`` (``resp.truncated``).

    ``read1`` makes one socket read per call, so the budget is re-checked
    between reads; urllib3 bounds each decode step to the requested size.
    """
    buf = bytearray()
    try:
        while len(buf) <= max_bytes:
            if deadline.expired():
                raise _budget_exceeded(deadline)
            chunk = resp.raw.read1(min(65536, max_bytes + 1 - len(buf)), decode_content=True)
            if not chunk:
                break
            buf += chunk
    except ReadTimeoutError as exc:
        raise requests.exceptions.ReadTimeout(exc, request=resp.request) from None
    except DecodeError as exc:
        raise requests.exceptions.ContentDecodingError(exc, request=resp.request) from None
    except Urllib3SSLError as exc:
        raise requests.exceptions.SSLError(exc, request=resp.request) from None
    except (ProtocolError, OSError) as exc:
        raise requests.exceptions.ChunkedEncodingError(exc, request=resp.request) from None
    finally:
        resp.close()
    if deadline.expired():  # a watchdog shutdown can look like a clean EOF
        raise _budget_exceeded(deadline)
    resp._content = bytes(buf[:max_bytes])
    resp._content_consumed = True
    resp.truncated = len(buf) > max_bytes  # type: ignore[attr-defined]


def _follow(
    session: requests.Session,
    url: str,
    headers: Mapping[str, str] | None,
    timeout: Any,
    deadline: _Deadline,
    max_bytes: int,
    verify: bool,
    max_redirects: int,
) -> requests.Response:
    history: list[requests.Response] = []
    current = url
    for hop in range(max_redirects + 1):
        check_url(current)
        resp = session.get(
            current, headers=headers, timeout=_hop_timeout(timeout, deadline),
            allow_redirects=False, verify=verify, stream=True,
        )
        target = session.get_redirect_target(resp)
        if target is None:
            _read_capped(resp, max_bytes, deadline)
            resp.history = history
            return resp
        resp.close()
        history.append(resp)
        if hop == max_redirects:
            raise requests.exceptions.TooManyRedirects(
                f"Exceeded {max_redirects} redirects.", response=resp
            )
        current = urljoin(resp.url, requote_uri(target))
    raise AssertionError("unreachable")


def _blocked_message(exc: BaseException) -> str | None:
    """The guard's refusal message buried in a requests/urllib3 error, if any."""
    seen: set[int] = set()
    stack: list[Any] = [exc]
    while stack:
        e = stack.pop()
        if not isinstance(e, BaseException) or id(e) in seen:
            continue
        seen.add(id(e))
        if isinstance(e, _BlockedConnection):
            return e.guard_message
        stack.extend([getattr(e, "reason", None), e.__cause__, e.__context__, *e.args])
    return None


def guarded_get(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: Any = (5, 10),
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    verify: bool = True,
    max_redirects: int = MAX_REDIRECTS,
) -> requests.Response:
    """GET ``url`` under the guard (see module docstring).

    Returns a fully read ``requests.Response`` (``.content``/``.text`` hold at
    most ``max_bytes``; ``.truncated`` says whether more was available;
    ``.history`` lists the redirect hops). Raises BlockedDestination,
    TooManyRedirects, Timeout (budget exceeded), or any other requests error.
    """
    deadline = _Deadline(total_timeout)
    previous = getattr(_CALL, "deadline", None)
    _CALL.deadline = deadline
    session = _session()
    try:
        return _follow(session, url, headers, timeout, deadline, max_bytes, verify, max_redirects)
    except BlockedDestination:
        raise
    except requests.exceptions.RequestException as exc:
        blocked = _blocked_message(exc)
        if blocked is not None:
            raise BlockedDestination(blocked) from None
        if deadline.expired():
            raise _budget_exceeded(deadline) from None
        raise
    finally:
        _CALL.deadline = previous
        deadline.close()
        session.close()
