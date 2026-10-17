"""TLS inspection: certificate minting and the intercepting proxy, end to end in-process.

Certificates are created with the openssl command line tool, as in the gateway
image. The certificate tests run once per OpenSSL-compatible binary found:
``openssl`` on the PATH, ``/usr/bin/openssl`` (LibreSSL on macOS) and every
binary listed in the ``OPENSSL`` environment variable (separated like PATH),
which must exist, e.g. ``OPENSSL=/usr/bin/libressl`` on Alpine. The other
tests use the first binary found. Everything is skipped where there is none.
"""

import asyncio
import contextlib
import gzip
import os
import shutil
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from agent_sandbox.canary import generate
from agent_sandbox.gateway import certs
from agent_sandbox.gateway.alerts import EventLog
from test_gateway import ProxyHarness, _client_hello, read_jsonl


def openssl_binaries() -> list[tuple[str, str]]:
    """Return ``(path, version)`` for each distinct binary to mint certificates with."""
    required = [path for path in os.environ.get("OPENSSL", "").split(os.pathsep) if path]
    missing = [path for path in required if shutil.which(path) is None]
    if missing:
        raise RuntimeError(f"OPENSSL lists binaries that cannot be run: {', '.join(missing)}")
    found: dict[str, tuple[str, str]] = {}
    for candidate in (shutil.which("openssl"), "/usr/bin/openssl", *required):
        path = shutil.which(candidate) if candidate else None
        if path is not None:
            found.setdefault(os.path.realpath(path), (path, certs.openssl_version(path)))
    return list(found.values())


OPENSSL = openssl_binaries()
pytestmark = pytest.mark.skipif(not OPENSSL, reason="openssl not installed")


@pytest.fixture(
    scope="module",
    params=[path for path, _ in OPENSSL],
    ids=["-".join(version.split()[:2]) for _, version in OPENSSL],
)
def openssl(request):
    """Each OpenSSL-compatible binary in turn (OpenSSL, LibreSSL)."""
    return request.param


@pytest.fixture(scope="module")
def sandbox_ca(tmp_path_factory):
    directory = tmp_path_factory.mktemp("sandbox-ca")
    return certs.CertificateAuthority.load_or_create(directory, OPENSSL[0][0])


@pytest.fixture(scope="module")
def issuer(sandbox_ca, tmp_path_factory):
    return certs.LeafIssuer(sandbox_ca, tmp_path_factory.mktemp("leaves"))


@pytest.fixture(scope="module")
def upstream_ca(tmp_path_factory):
    """A separate CA standing in for the public PKI the gateway verifies against."""
    directory = tmp_path_factory.mktemp("public-ca")
    return certs.CertificateAuthority.load_or_create(directory, OPENSSL[0][0])


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


def test_openssl_flavour_is_detected(openssl):
    version = certs.openssl_version(openssl)
    assert version.split()[0] in {"OpenSSL", "LibreSSL"}, version
    with pytest.raises(certs.CertificateError, match="cannot run"):
        certs.openssl_version(openssl + "-missing")


def test_ca_is_created_once_and_published_without_its_key(tmp_path, openssl):
    ca = certs.CertificateAuthority.load_or_create(tmp_path / "ca", openssl)
    fingerprint = ca.fingerprint()
    assert len(fingerprint.split(":")) == 32
    again = certs.CertificateAuthority.load_or_create(tmp_path / "ca", openssl)
    assert again.fingerprint() == fingerprint  # kept across gateway restarts
    assert sorted(p.name for p in (tmp_path / "ca").iterdir()) == ["ca.crt", "ca.key"]
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


def test_leaf_certificates_verify_strictly_and_are_cached(tmp_path, openssl):
    ca = certs.CertificateAuthority.load_or_create(tmp_path / "ca", openssl)
    issuer = certs.LeafIssuer(ca, tmp_path / "leaves")
    client = ssl.create_default_context(cafile=str(ca.cert))
    client.verify_flags |= ssl.VERIFY_X509_STRICT
    context = asyncio.run(issuer.context_for("pypi.org"))
    assert asyncio.run(issuer.context_for("pypi.org")) is context
    leaf = memory_handshake(client, context, "pypi.org").getpeercert()
    issuer_name = dict(item[0] for item in leaf["issuer"])
    assert issuer_name["organizationName"] == "agent-sandbox"
    assert leaf["subjectAltName"] == (("DNS", "pypi.org"),)
    days = (ssl.cert_time_to_seconds(leaf["notAfter"]) - time.time()) / 86400
    assert certs.LEAF_DAYS - 2 < days <= certs.LEAF_DAYS
    ip_context = asyncio.run(issuer.context_for("93.184.216.34"))
    ip_leaf = memory_handshake(client, ip_context, "93.184.216.34").getpeercert()
    assert ip_leaf["subjectAltName"] == (("IP Address", "93.184.216.34"),)
    assert ip_leaf["serialNumber"] != leaf["serialNumber"]
    with pytest.raises(ssl.SSLError):  # server name other than the one minted for
        memory_handshake(client, context, "evil.example")
    # Only the shared key, request and configuration stay on disk.
    assert sorted(p.name for p in (tmp_path / "leaves").iterdir()) == [
        "leaf.cnf",
        "leaf.csr",
        "leaf.key",
    ]


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


def test_openssl_failures_are_reported(tmp_path, monkeypatch, sandbox_ca, openssl):
    with pytest.raises(certs.CertificateError, match="openssl"):
        certs.CertificateAuthority.load_or_create(tmp_path / "ca", openssl=str(tmp_path / "nope"))
    assert not (tmp_path / "ca" / "ca.key").exists()
    broken = certs.LeafIssuer(certs.CertificateAuthority(sandbox_ca.directory, openssl), tmp_path)
    broken.ca = certs.CertificateAuthority(tmp_path / "missing", openssl)
    with pytest.raises(certs.CertificateError, match="cannot mint"):
        asyncio.run(broken.context_for("x.example"))
    monkeypatch.setattr(certs.shutil, "which", lambda name: f"/opt/bin/{name}")
    assert certs.find_openssl() == "/opt/bin/openssl"
    monkeypatch.setattr(certs.shutil, "which", lambda name: None)
    with pytest.raises(certs.CertificateError, match="required"):
        certs.find_openssl()


def test_prepare_publishes_bundle_and_returns_issuer(tmp_path, openssl):
    issuer = certs.prepare(tmp_path / "ca", tmp_path / "tls", tmp_path / "work", openssl=openssl)
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


def test_http2_only_clients_get_a_clear_refusal(inspecting, tls_upstream, sandbox_ca, log):
    target = f"127.0.0.1:{tls_upstream}"
    h = inspecting()
    with pytest.raises(ssl.SSLError, match=r"(?i)no.application.protocol"):
        https(h.port, target, b"", str(sandbox_ca.cert), alpn=["h2"])
    for _ in range(50):
        events = read_jsonl(log.directory / "events.jsonl")
        if any(e["kind"] == "egress.protocol_refused" for e in events):
            break
        threading.Event().wait(0.05)
    refused = next(e for e in events if e["kind"] == "egress.protocol_refused")
    assert refused["protocol"] == "h2" and refused["tls"] is True
    assert TLSUpstream.received == []


def test_websocket_upgrade_inside_tls_is_refused(inspecting, tls_upstream, sandbox_ca, log):
    target = f"127.0.0.1:{tls_upstream}"
    payload = (
        f"GET /socket HTTP/1.1\r\nHost: {target}\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    response, _ = https(inspecting().port, target, payload, str(sandbox_ca.cert))
    assert response.startswith(b"HTTP/1.1 501")
    refused = read_jsonl(log.directory / "events.jsonl")[-1]
    assert refused["kind"] == "egress.protocol_refused" and refused["protocol"] == "websocket"
    assert TLSUpstream.received == []


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


# ---------------------------------------------------------------------------- passthrough


def wait_for_event(log, kind):
    for _ in range(50):
        events = read_jsonl(log.directory / "events.jsonl")
        if any(e["kind"] == kind for e in events):
            return events
        threading.Event().wait(0.05)
    raise AssertionError(f"no {kind} event")


def test_passthrough_hosts_get_the_upstream_certificate(
    inspecting, tls_upstream, upstream_ca, canaries, log
):
    target = f"127.0.0.1:{tls_upstream}"
    secret = next(c for c in canaries if c.kind == "aws").secrets[1]
    body = f"k={secret}".encode()
    payload = (
        f"POST /upload HTTP/1.1\r\nHost: {target}\r\nContent-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    h = inspecting({"inspect": False})
    # A client that trusts only the upstream CA completes its handshake with the
    # real server, as a client that pins its certificate would.
    response, alpn = https(h.port, target, payload, str(upstream_ca.cert))
    assert response.endswith(b"hello over tls") and alpn is None
    # The documented trade-off: a canary inside the tunnel is not visible.
    assert TLSUpstream.received[0][2] == body
    assert read_jsonl(log.directory / "alerts.jsonl") == []
    events = wait_for_event(log, "egress.tls_passthrough")
    kinds = [e["kind"] for e in events]
    assert "egress.allowed" not in kinds and "egress.request" not in kinds
    passed = next(e for e in events if e["kind"] == "egress.tls_passthrough")
    assert passed["host"] == "127.0.0.1" and passed["port"] == tls_upstream
    assert passed["sni"] is None  # no SNI for an IP address


def test_passthrough_skips_the_http_1_only_policy(inspecting, tls_upstream, upstream_ca, log):
    target = f"127.0.0.1:{tls_upstream}"
    h = inspecting({"inspect": False})
    payload = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode()
    response, _ = https(h.port, target, payload, str(upstream_ca.cert), alpn=["h2"])
    assert response.endswith(b"hello over tls")
    kinds = [e["kind"] for e in wait_for_event(log, "egress.tls_passthrough")]
    assert "egress.protocol_refused" not in kinds


def test_passthrough_still_checks_the_server_name(inspecting, tls_upstream, log):
    h = inspecting({"inspect": False})
    h.raw(
        f"CONNECT 127.0.0.1:{tls_upstream} HTTP/1.1\r\n\r\n".encode(),
        read_after=_client_hello("evil.example"),
    )
    (alert,) = read_jsonl(log.directory / "alerts.jsonl")
    assert alert["kind"] == "egress.sni_mismatch" and alert["sni"] == "evil.example"
    kinds = [e["kind"] for e in read_jsonl(log.directory / "events.jsonl")]
    assert "egress.tls_passthrough" not in kinds
    assert TLSUpstream.received == []
