"""Tests for the outbound fetch guard (acpsec_api/net_guard.py).

No public network is touched. Address/URL rules are pure functions; the
connect-time tests swap ``socket.getaddrinfo`` / ``socket.socket`` for fakes;
the end-to-end tests talk to a throwaway HTTP server on 127.0.0.1, which they
reach only by explicitly re-allowing that one loopback address and the
server's port for the duration of the test.
"""

from __future__ import annotations

import gzip
import http.server
import ipaddress
import socket
import threading
import time
import urllib.parse

import pytest
import requests

from acpsec_api import net_guard
from acpsec_api.net_guard import BlockedDestination, check_url, guarded_get, is_forbidden_ip

# --- Address classes --------------------------------------------------------

FORBIDDEN_IPS = [
    # IPv4
    "0.0.0.0", "0.1.2.3",                       # 0.0.0.0/8 "this network"
    "10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1",   # private
    "127.0.0.1", "127.255.255.254",             # loopback
    "169.254.169.254", "169.254.0.1",           # link-local (cloud metadata)
    "100.64.0.1", "100.127.255.254",            # 100.64/10 shared / CGNAT
    "224.0.0.1", "239.255.255.250",             # multicast
    "240.0.0.1", "255.255.255.255",             # reserved / broadcast
    "192.0.0.1", "198.18.0.1",                  # IETF / benchmarking
    "192.0.2.1", "198.51.100.1", "203.0.113.1", # documentation
    # IPv6
    "::", "::1",                                # unspecified / loopback
    "fc00::1", "fd12:3456:789a::1",             # ULA (Railway private net is fd12::/16)
    "fe80::1", "fe80::1%1",                     # link-local (with zone id)
    "fec0::1",                                  # site-local (deprecated)
    "ff02::1", "ff05::2",                       # multicast
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:8.8.8.8",  # IPv4-mapped: always
    "64:ff9b::a00:1", "64:ff9b::7f00:1",        # NAT64 → 10.0.0.1 / 127.0.0.1
    "64:ff9b:1::1",                             # local-use NAT64
    "2002:a00:1::1", "2002:7f00:1::1",          # 6to4 → 10.0.0.1 / 127.0.0.1
    "2001::1",                                  # Teredo
    "100::1", "2001:db8::1",                    # discard / documentation
]

ALLOWED_IPS = [
    "8.8.8.8", "1.1.1.1", "93.184.215.14", "104.16.0.1",
    "2606:4700:4700::1111", "2a00:1450:4001::200e",
    "64:ff9b::808:808",                         # NAT64 of a public IPv4
]


@pytest.mark.parametrize("ip", FORBIDDEN_IPS)
def test_forbidden_ip_classes(ip) -> None:
    assert is_forbidden_ip(ip) is True


@pytest.mark.parametrize("ip", ALLOWED_IPS)
def test_public_ips_allowed(ip) -> None:
    assert is_forbidden_ip(ip) is False


def test_is_forbidden_ip_accepts_ipaddress_objects() -> None:
    assert is_forbidden_ip(ipaddress.ip_address("10.1.2.3")) is True
    assert is_forbidden_ip(ipaddress.ip_address("8.8.4.4")) is False


# --- URL rules (no resolution, no network) ----------------------------------

FORBIDDEN_URLS = [
    "ftp://example.com/", "file:///etc/passwd", "gopher://example.com/",
    "javascript:alert(1)", "data:text/html,x", "//example.com/",
    "http://example.com:8080/", "https://example.com:8443/", "http://example.com:22/",
    "http://example.com:6379/", "http://example.com:0/",
    "http://localhost/", "http://LOCALHOST./", "http://foo.localhost/",
    "http://api-prod.railway.internal/", "http://x.railway.internal:443/",
    "http://metadata.google.internal/", "http://printer.local/",
    "http://redis/", "http://2130706433/",       # single-label (incl. decimal IPv4)
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fd12::1]/",
    "http://10.0.0.1:80/", "https://0.0.0.0/",
    "http:///nohost", "",
]

ALLOWED_URLS = [
    "https://example.com/", "http://example.com/", "http://example.com:80/x",
    "https://example.com:443/a?b=c", "https://EXAMPLE.com./", "https://sub.example.co.uk/",
    "https://8.8.8.8/", "https://[2606:4700:4700::1111]/",
]


@pytest.mark.parametrize("url", FORBIDDEN_URLS)
def test_forbidden_urls(url) -> None:
    with pytest.raises(BlockedDestination):
        check_url(url)


@pytest.mark.parametrize("url", ALLOWED_URLS)
def test_allowed_urls(url) -> None:
    check_url(url)  # no raise


def test_blocked_destination_is_a_requests_connection_error() -> None:
    # Existing call sites treat it like any other fetch failure.
    assert issubclass(BlockedDestination, requests.exceptions.ConnectionError)


# --- Connect-time checks (fake resolver / fake socket) ----------------------


class _FakeSocket:
    """Records the sockaddr the guard dials; refuses so the test ends fast."""

    dialed: list = []

    def __init__(self, *a, **k) -> None:
        pass

    def setsockopt(self, *a) -> None:
        pass

    def settimeout(self, *a) -> None:
        pass

    def bind(self, *a) -> None:
        pass

    def connect(self, sa) -> None:
        _FakeSocket.dialed.append(sa)
        raise ConnectionRefusedError("fake: refused")

    def close(self) -> None:
        pass


@pytest.fixture
def fake_net(monkeypatch):
    """Fake DNS answers per host (list of IPs, or a callable per call) + fake sockets."""
    answers: dict = {}
    calls: list = []

    def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        spec = answers[host]
        ips = spec(len([c for c in calls if c == host])) if callable(spec) else spec
        out = []
        for ip in ips:
            if ":" in ip:
                out.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, port, 0, 0)))
            else:
                out.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)))
        return out

    _FakeSocket.dialed = []
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
    monkeypatch.setattr(socket, "socket", _FakeSocket)
    return answers, calls


def test_name_resolving_to_private_is_blocked_before_dialing(fake_net) -> None:
    answers, _ = fake_net
    answers["innocent.example"] = ["10.0.0.7"]
    with pytest.raises(BlockedDestination):
        guarded_get("http://innocent.example/")
    assert _FakeSocket.dialed == []


def test_any_forbidden_answer_blocks_the_host(fake_net) -> None:
    # Mixed public + private records: refuse outright rather than gamble.
    answers, _ = fake_net
    answers["mixed.example"] = ["93.184.215.14", "127.0.0.1"]
    with pytest.raises(BlockedDestination):
        guarded_get("http://mixed.example/")
    assert _FakeSocket.dialed == []


def test_dns_rebinding_window_is_closed(fake_net) -> None:
    # A rebinding resolver answers public first, private on any later lookup.
    # The guard must resolve ONCE and dial exactly the address it vetted —
    # never re-resolve between the check and the connect.
    answers, calls = fake_net
    answers["rebind.example"] = lambda n: ["93.184.215.14"] if n == 1 else ["127.0.0.1"]
    with pytest.raises(requests.exceptions.ConnectionError) as exc:
        guarded_get("http://rebind.example/")
    assert not isinstance(exc.value, BlockedDestination)  # refused by the fake, not blocked
    assert calls == ["rebind.example"]
    assert _FakeSocket.dialed == [("93.184.215.14", 80)]


def test_rebinding_to_private_on_connect_is_blocked(fake_net) -> None:
    # Even if some earlier lookup (e.g. a caller's own pre-check) saw a public
    # address, the connect-time answer is the one that is enforced.
    answers, calls = fake_net
    answers["rebind2.example"] = lambda n: ["93.184.215.14"] if n == 1 else ["169.254.169.254"]
    socket.getaddrinfo("rebind2.example", 80)  # the "pre-check" consumes the public answer
    with pytest.raises(BlockedDestination):
        guarded_get("http://rebind2.example/")
    assert _FakeSocket.dialed == []


def test_ipv6_answer_checked_too(fake_net) -> None:
    answers, _ = fake_net
    answers["v6.example"] = ["fd12::1"]
    with pytest.raises(BlockedDestination):
        guarded_get("https://v6.example/")
    assert _FakeSocket.dialed == []


def test_verify_false_goes_through_the_same_guard(fake_net) -> None:
    answers, _ = fake_net
    answers["insecure.example"] = ["192.168.0.10"]
    with pytest.raises(BlockedDestination):
        guarded_get("https://insecure.example/", verify=False)
    with pytest.raises(BlockedDestination):
        guarded_get("https://10.0.0.1/", verify=False)
    assert _FakeSocket.dialed == []


# --- End-to-end against a local server ---------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a) -> None:  # keep test output quiet
        pass

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        if not any(k.lower() == "content-length" for k, _ in headers):
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 — http.server API
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/ok":
            return self._send(200, b"hello")
        if u.path.startswith("/redirect/"):
            n = int(u.path.rsplit("/", 1)[1])
            if n == 0:
                return self._send(200, b"done")
            return self._send(302, headers=[("Location", f"/redirect/{n - 1}")])
        if u.path == "/to":
            return self._send(302, headers=[("Location", q["u"])])
        if u.path == "/big":
            return self._send(200, b"a" * int(q["n"]))
        if u.path == "/gzipbomb":
            body = gzip.compress(b"\0" * int(q["n"]), compresslevel=9)
            return self._send(200, body, headers=[("Content-Encoding", "gzip")])
        if u.path == "/drip":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            try:
                for _ in range(int(q["count"])):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(float(q["delay"]))
            except OSError:
                pass
            return None
        if u.path == "/slowheaders":
            try:
                self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                for _ in range(int(q["count"])):
                    self.wfile.write(b"X-Pad: 1\r\n")
                    self.wfile.flush()
                    time.sleep(float(q["delay"]))
            except OSError:
                pass
            return None
        return self._send(404, b"nope")


@pytest.fixture
def local_server(monkeypatch):
    """Serve _Handler on 127.0.0.1 and re-allow exactly that address + port."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()

    real_is_forbidden = net_guard.is_forbidden_ip

    def _allow_test_loopback(ip) -> bool:
        if str(ip) == "127.0.0.1":
            return False
        return real_is_forbidden(ip)

    monkeypatch.setattr(net_guard, "is_forbidden_ip", _allow_test_loopback)
    monkeypatch.setattr(net_guard, "ALLOWED_PORTS", net_guard.ALLOWED_PORTS | {port})
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_plain_fetch_works(local_server) -> None:
    resp = guarded_get(local_server + "/ok")
    assert resp.status_code == 200
    assert resp.text == "hello"
    assert resp.truncated is False
    assert resp.url == local_server + "/ok"


def test_redirects_followed_manually_up_to_five(local_server) -> None:
    resp = guarded_get(local_server + "/redirect/5")
    assert resp.status_code == 200
    assert resp.text == "done"
    assert len(resp.history) == 5
    assert resp.url == local_server + "/redirect/0"


def test_sixth_redirect_is_refused(local_server) -> None:
    with pytest.raises(requests.exceptions.TooManyRedirects):
        guarded_get(local_server + "/redirect/6")


@pytest.mark.parametrize(
    "target",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://api-prod.railway.internal/",
        "http://localhost/",
        "file:///etc/passwd",
        "gopher://example.com/",
    ],
)
def test_redirect_to_forbidden_target_is_blocked(local_server, target) -> None:
    with pytest.raises(BlockedDestination):
        guarded_get(local_server + "/to?u=" + urllib.parse.quote(target, safe=""))


def test_redirect_to_disallowed_port_is_blocked(local_server) -> None:
    target = "http://127.0.0.1:6379/"  # same (re-allowed) address, port not allowed
    with pytest.raises(BlockedDestination):
        guarded_get(local_server + "/to?u=" + urllib.parse.quote(target, safe=""))


def test_redirect_hop_is_rechecked_at_connect_time(local_server, monkeypatch) -> None:
    # Hop 2 names a host that only reveals itself as private when resolved.
    port = int(local_server.rsplit(":", 1)[1])
    real = socket.getaddrinfo

    def _getaddrinfo(host, *a, **k):
        if host == "sneaky.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port))]
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
    target = f"http://sneaky.example:{port}/ok"
    with pytest.raises(BlockedDestination):
        guarded_get(local_server + "/to?u=" + urllib.parse.quote(target, safe=""))


def test_relative_redirects_resolve_against_current_url(local_server) -> None:
    resp = guarded_get(local_server + "/to?u=" + urllib.parse.quote("/ok", safe=""))
    assert resp.text == "hello"
    scheme_relative = "//" + local_server.split("://", 1)[1] + "/ok"
    resp = guarded_get(local_server + "/to?u=" + urllib.parse.quote(scheme_relative, safe=""))
    assert resp.text == "hello"


def test_body_is_capped(local_server) -> None:
    resp = guarded_get(local_server + "/big?n=300000", max_bytes=100_000)
    assert len(resp.content) == 100_000
    assert resp.truncated is True


def test_body_at_exact_cap_is_not_truncated(local_server) -> None:
    resp = guarded_get(local_server + "/big?n=100000", max_bytes=100_000)
    assert len(resp.content) == 100_000
    assert resp.truncated is False


def test_decompression_bomb_is_capped_on_decoded_bytes(local_server) -> None:
    # ~50 MiB of zeros gzip to ~50 KiB; only max_bytes may ever be decoded.
    resp = guarded_get(local_server + f"/gzipbomb?n={50 * 1024 * 1024}", max_bytes=1_000_000)
    assert len(resp.content) == 1_000_000
    assert resp.truncated is True


def test_total_timeout_bounds_a_dripping_body(local_server) -> None:
    # Every byte arrives well inside the per-read timeout; only the total
    # wall-clock budget can stop this.
    t0 = time.monotonic()
    with pytest.raises(requests.exceptions.Timeout):
        guarded_get(local_server + "/drip?count=200&delay=0.05", timeout=(2, 2), total_timeout=1.0)
    assert time.monotonic() - t0 < 3.5


def test_total_timeout_bounds_dripping_headers(local_server) -> None:
    t0 = time.monotonic()
    with pytest.raises(requests.exceptions.Timeout):
        guarded_get(local_server + "/slowheaders?count=200&delay=0.05", timeout=(2, 2), total_timeout=1.0)
    assert time.monotonic() - t0 < 3.5


def test_environment_proxies_are_ignored(local_server, monkeypatch) -> None:
    # A proxy would resolve the target itself, bypassing the connect-time
    # check, so env proxy settings must never apply. This one is unroutable.
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(var, "http://10.255.255.1:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    resp = guarded_get(local_server + "/ok", total_timeout=5.0)
    assert resp.text == "hello"
