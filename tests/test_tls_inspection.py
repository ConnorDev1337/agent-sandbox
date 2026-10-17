"""TLS inspection: certificate minting and the intercepting proxy, end to end in-process.

Certificates are created with the openssl command line tool, as in the gateway
image; the tests are skipped where it is not installed.
"""

import asyncio
import contextlib
import gzip
import shutil
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from agent_sandbox.canary import generate
from agent_sandbox.gateway import certs
from agent_sandbox.gateway.alerts import EventLog
from test_gateway import ProxyHarness, read_jsonl

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


@pytest.fixture(scope="module")
def sandbox_ca(tmp_path_factory):
    return certs.CertificateAuthority.load_or_create(tmp_path_factory.mktemp("sandbox-ca"))


@pytest.fixture(scope="module")
def issuer(sandbox_ca, tmp_path_factory):
    return certs.LeafIssuer(sandbox_ca, tmp_path_factory.mktemp("leaves"))


@pytest.fixture(scope="module")
def upstream_ca(tmp_path_factory):
    """A separate CA standing in for the public PKI the gateway verifies against."""
    return certs.CertificateAuthority.load_or_create(tmp_path_factory.mktemp("public-ca"))


class TLSUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received: ClassVar[list] = []

    def log_message(self, *args):
        pass

    def _respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        TLSUpstream.received.append((self.command, self.path, body, dict(self.headers)))
        payload = b"hello over tls"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_DELETE = _respond


@pytest.fixture(scope="module")
def tls_upstream(upstream_ca, tmp_path_factory):
    leaves = certs.LeafIssuer(upstream_ca, tmp_path_factory.mktemp("upstream-leaves"))
    context = asyncio.run(leaves.context_for("127.0.0.1"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), TLSUpstream)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def canaries():
    return generate()


@pytest.fixture
def log(tmp_path):
    return EventLog(tmp_path / "logs", stream=None)


@pytest.fixture
def inspecting(canaries, log, issuer, upstream_ca, tls_upstream):
    """Start an inspecting proxy that allows the TLS upstream with the given rules."""
    TLSUpstream.received = []
    made = []

    def _make(*rules, trust_upstream=True, tls_issuer=issuer):
        target = f"127.0.0.1:{tls_upstream}"
        allow = [{"host": target, **rule} for rule in rules] or [target]
        upstream_tls = certs.upstream_context(str(upstream_ca.cert) if trust_upstream else None)
        h = ProxyHarness(allow, canaries, log, tls_issuer=tls_issuer, upstream_tls=upstream_tls)
        made.append(h)
        return h

    yield _make
    for h in made:
        h.close()


def https(port, target, payload, cafile, *, alpn=None):
    """Send ``payload`` through a CONNECT tunnel over TLS; return (response, ALPN)."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
        assert sock.recv(4096).startswith(b"HTTP/1.1 200")
        context = ssl.create_default_context(cafile=cafile)
        if alpn:
            context.set_alpn_protocols(alpn)
        with context.wrap_socket(sock, server_hostname=target.rsplit(":", 1)[0]) as tls:
            tls.sendall(payload)
            chunks = []
            with contextlib.suppress(TimeoutError, OSError):
                while chunk := tls.recv(65536):
                    chunks.append(chunk)
            return b"".join(chunks), tls.selected_alpn_protocol()


def memory_handshake(client_context, server_context, server_hostname):
    """Run a TLS handshake between two contexts without sockets."""
    bios = [ssl.MemoryBIO() for _ in range(4)]
    client = client_context.wrap_bio(bios[0], bios[1], server_hostname=server_hostname)
    server = server_context.wrap_bio(bios[2], bios[3], server_side=True)
    for _ in range(10):
        finished = 0
        for side in (client, server):
            try:
                side.do_handshake()
                finished += 1
            except ssl.SSLWantReadError:
                pass
        bios[2].write(bios[1].read())
        bios[0].write(bios[3].read())
        if finished == 2:
            return client
    raise AssertionError("handshake did not finish")


# ---------------------------------------------------------------------------- certificates


def test_ca_is_created_once_and_published_without_its_key(tmp_path):
    ca = certs.CertificateAuthority.load_or_create(tmp_path / "ca")
    fingerprint = ca.fingerprint()
    assert len(fingerprint.split(":")) == 32
    again = certs.CertificateAuthority.load_or_create(tmp_path / "ca")
    assert again.fingerprint() == fingerprint  # kept across gateway restarts
    system = tmp_path / "system.crt"
    system.write_text("-----BEGIN CERTIFICATE-----\nsystem\n-----END CERTIFICATE-----", "ascii")
    bundle = ca.write_bundle(tmp_path / "published", system)
    published = {p.name: p.read_text(encoding="ascii") for p in bundle.parent.iterdir()}
    assert set(published) == {"ca.crt", "ca-bundle.crt"}
    assert published["ca-bundle.crt"].startswith("-----BEGIN CERTIFICATE-----\nsystem")
    assert published["ca-bundle.crt"].endswith(published["ca.crt"])
    assert not any("PRIVATE KEY" in text for text in published.values())
    assert "PRIVATE KEY" in ca.key.read_text(encoding="ascii")
    if sys.platform != "win32":
        assert ca.key.stat().st_mode & 0o077 == 0
    ca.write_bundle(tmp_path / "no-system", None)
    assert (tmp_path / "no-system" / "ca-bundle.crt").read_text("ascii") == ca.pem()


def test_leaf_certificates_verify_strictly_and_are_cached(sandbox_ca, issuer):
    client = ssl.create_default_context(cafile=str(sandbox_ca.cert))
    client.verify_flags |= ssl.VERIFY_X509_STRICT
    context = asyncio.run(issuer.context_for("pypi.org"))
    assert asyncio.run(issuer.context_for("pypi.org")) is context
    session = memory_handshake(client, context, "pypi.org")
    issuer_name = dict(item[0] for item in session.getpeercert()["issuer"])
    assert issuer_name["organizationName"] == "agent-sandbox"
    ip_context = asyncio.run(issuer.context_for("93.184.216.34"))
    memory_handshake(client, ip_context, "93.184.216.34")
    with pytest.raises(ssl.SSLError):  # server name other than the one minted for
        memory_handshake(client, context, "evil.example")


def test_concurrent_requests_share_one_mint_and_cache_is_bounded(sandbox_ca, tmp_path):
    issuer = certs.LeafIssuer(sandbox_ca, tmp_path / "leaves", max_entries=2)

    async def scenario():
        first, second = await asyncio.gather(
            issuer.context_for("a.example"), issuer.context_for("a.example")
        )
        assert first is second
        await issuer.context_for("b.example")
        await issuer.context_for("c.example")
        return list(issuer._cache)

    assert asyncio.run(scenario()) == ["b.example", "c.example"]
    assert sorted(p.name for p in (tmp_path / "leaves").iterdir()) == [
        "leaf.cnf",
        "leaf.csr",
        "leaf.key",
    ]


def test_openssl_failures_are_reported(tmp_path, monkeypatch, sandbox_ca):
    with pytest.raises(certs.CertificateError, match="openssl"):
        certs.CertificateAuthority.load_or_create(tmp_path / "ca", openssl=str(tmp_path / "nope"))
    assert not (tmp_path / "ca" / "ca.key").exists()
    broken = certs.LeafIssuer(sandbox_ca, tmp_path / "leaves")
    broken.ca = certs.CertificateAuthority(tmp_path / "missing", sandbox_ca.openssl)
    with pytest.raises(certs.CertificateError, match="cannot mint"):
        asyncio.run(broken.context_for("x.example"))
    monkeypatch.setattr(certs.shutil, "which", lambda name: None)
    with pytest.raises(certs.CertificateError, match="required"):
        certs.find_openssl()


def test_prepare_publishes_bundle_and_returns_issuer(tmp_path):
    issuer = certs.prepare(tmp_path / "ca", tmp_path / "tls", tmp_path / "work")
    assert (tmp_path / "tls" / "ca.crt").read_text("ascii") == issuer.ca.pem()
    assert certs.subject_alt_name("::1") == "IP:::1"
    assert certs.subject_alt_name("pypi.org") == "DNS:pypi.org"


# ---------------------------------------------------------------------------- interception


def test_inspected_requests_reach_upstream(inspecting, tls_upstream, sandbox_ca, log):
    target = f"127.0.0.1:{tls_upstream}"
    h = inspecting()
    payload = (
        f"GET /one HTTP/1.1\r\nHost: {target}\r\n\r\n"
        f"POST /two HTTP/1.1\r\nHost: {target}\r\nContent-Length: 5\r\nConnection: close\r\n"
        "\r\nhello"
    ).encode()
    response, alpn = https(h.port, target, payload, str(sandbox_ca.cert), alpn=["h2", "http/1.1"])
    assert alpn == "http/1.1"  # HTTP/2 is never negotiated, so requests stay parsable
    assert response.count(b"hello over tls") == 2
    assert [(r[0], r[1], r[2]) for r in TLSUpstream.received] == [
        ("GET", "/one", b""),
        ("POST", "/two", b"hello"),
    ]
    events = read_jsonl(log.directory / "events.jsonl")
    connect = next(e for e in events if e["kind"] == "egress.allowed")
    assert connect["inspected"] is True and connect["tls"] is True
    requests = [e for e in events if e["kind"] == "egress.request"]
    assert [(e["method"], e["path"], e["tls"]) for e in requests] == [
        ("GET", "/one", True),
        ("POST", "/two", True),
    ]


def test_canary_in_https_body_is_blocked(inspecting, tls_upstream, sandbox_ca, canaries, log):
    target = f"127.0.0.1:{tls_upstream}"
    secret = next(c for c in canaries if c.kind == "aws").secrets[1]
    body = f"description=see {secret}".encode()
    payload = (
        f"POST /gists HTTP/1.1\r\nHost: {target}\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    response, _ = https(inspecting().port, target, payload, str(sandbox_ca.cert))
    assert response.startswith(b"HTTP/1.1 403") and b"canary" in response
    assert TLSUpstream.received == []
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "canary.exfiltration" and alert["tls"] is True
    assert alert["where"] == "request body" and "decrypted TLS" in alert["message"]
    assert secret not in (log.directory / "events.jsonl").read_text(encoding="utf-8")


def test_canary_in_gzip_https_body_is_blocked(inspecting, tls_upstream, sandbox_ca, canaries, log):
    target = f"127.0.0.1:{tls_upstream}"
    secret = next(c for c in canaries if c.kind == "github").secrets[0]
    body = gzip.compress(f'{{"token": "{secret}"}}'.encode())
    payload = (
        f"POST /api HTTP/1.1\r\nHost: {target}\r\nContent-Encoding: gzip\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    response, _ = https(inspecting().port, target, payload, str(sandbox_ca.cert))
    assert response.startswith(b"HTTP/1.1 403") and b"canary" in response
    assert TLSUpstream.received == []
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["tls"] is True and alert["encoding"] == "plain in gzip"


def test_method_rules_apply_inside_tls(inspecting, tls_upstream, sandbox_ca, log):
    target = f"127.0.0.1:{tls_upstream}"
    h = inspecting({"methods": ["GET", "HEAD"]})
    payload = f"DELETE /repo HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
    response, _ = https(h.port, target, payload, str(sandbox_ca.cert))
    assert response.startswith(b"HTTP/1.1 403") and b"DELETE /repo is not allowed" in response
    assert TLSUpstream.received == []
    denied = read_jsonl(log.directory / "events.jsonl")[-1]
    assert denied["kind"] == "egress.denied" and denied["method"] == "DELETE"


def test_upstream_certificate_is_verified(inspecting, tls_upstream, sandbox_ca, log):
    target = f"127.0.0.1:{tls_upstream}"
    h = inspecting(trust_upstream=False)
    payload = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
    response, _ = https(h.port, target, payload, str(sandbox_ca.cert))
    assert response.startswith(b"HTTP/1.1 502") and b"failed verification" in response
    assert TLSUpstream.received == []
    error = next(
        e for e in read_jsonl(log.directory / "events.jsonl") if e["kind"] == "egress.tls_error"
    )
    assert "certificate" in error["error"]


def test_clients_that_do_not_trust_the_sandbox_ca_fail_closed(
    inspecting, tls_upstream, upstream_ca, log
):
    target = f"127.0.0.1:{tls_upstream}"
    h = inspecting()
    with pytest.raises(ssl.SSLCertVerificationError):
        https(h.port, target, b"GET / HTTP/1.1\r\n\r\n", str(upstream_ca.cert))
    for _ in range(50):
        kinds = [e["kind"] for e in read_jsonl(log.directory / "events.jsonl")]
        if "tls.client_rejected" in kinds:
            break
        threading.Event().wait(0.05)
    assert "tls.client_rejected" in kinds
    assert TLSUpstream.received == []


def test_minting_failure_closes_the_tunnel(inspecting, tls_upstream, sandbox_ca, log):
    class Broken:
        async def context_for(self, host):
            raise certs.CertificateError("openssl exploded")

    target = f"127.0.0.1:{tls_upstream}"
    h = inspecting(tls_issuer=Broken())
    with pytest.raises((ssl.SSLError, OSError)):
        https(h.port, target, b"GET / HTTP/1.1\r\n\r\n", str(sandbox_ca.cert))
    for _ in range(50):
        events = read_jsonl(log.directory / "events.jsonl")
        if any(e["kind"] == "tls.error" for e in events):
            break
        threading.Event().wait(0.05)
    assert any(e["kind"] == "tls.error" and "exploded" in e["error"] for e in events)
