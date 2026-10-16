"""Allowlisting forward proxy (HTTP and CONNECT) with canary detection.

The agent container has no route to the internet; this proxy is its only way
out. Every request is checked against the allowlist, and every byte the agent
sends that the gateway can read (request lines, headers, plain-HTTP bodies,
non-TLS tunnels, TLS SNI) is scanned for canary values.

Requests the gateway can parse (plain HTTP, and plaintext tunnels to hosts
with method or path rules) are relayed one by one so the allowlist rules and
the ``Host`` header can be enforced on each of them.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
from typing import Any, Protocol
from urllib.parse import urlsplit

from ..allowlist import Allowlist, normalize_host
from ..canary import CanaryHit, CanaryMatcher, StreamScanner
from .alerts import EventLog
from .http1 import (
    MAX_HEAD,
    BufferedReader,
    ProxyError,
    Request,
    body_length,
    chunk,
    chunk_size,
    parse_head,
    serialize_head,
)
from .tls import hello_complete, looks_like_tls, server_name

__all__ = ["MAX_HEAD", "Proxy", "ProxyError", "Request", "parse_head", "serve", "split_host_port"]

CHUNK = 64 * 1024
SCAN_OVERLAP = 4096  # bytes kept between chunks so split values are still found
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "expect",
    }
)


class Sink(Protocol):
    """The writing half of a connection (a StreamWriter or a TLS session)."""

    def write(self, data: bytes) -> None: ...
    async def drain(self) -> None: ...
    def can_write_eof(self) -> bool: ...
    def write_eof(self) -> None: ...
    def close(self) -> None: ...


def is_public(address: str) -> bool:
    """Return True for globally routable unicast addresses."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def split_host_port(authority: str, default_port: int) -> tuple[str, int]:
    host, port = authority, default_port
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif authority.count(":") == 1:
        host, _, port_text = authority.partition(":")
        port = int(port_text)
    normalized = normalize_host(host)
    if normalized is None or not 0 < port < 65536:
        raise ValueError(authority)
    return normalized, port


class Proxy:
    def __init__(
        self,
        allowlist: Allowlist,
        matcher: CanaryMatcher,
        log: EventLog,
        *,
        max_body: int = 10 * 1024 * 1024,
        connect_timeout: float = 10.0,
        idle_timeout: float = 300.0,
    ) -> None:
        self.allowlist = allowlist
        self.matcher = matcher
        self.log = log
        self.max_body = max_body
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout

    # ------------------------------------------------------------------ entry point

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client = writer.get_extra_info("peername")
        client_ip = client[0] if client else "?"
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.idle_timeout)
            if len(head) > MAX_HEAD:
                raise ProxyError(431, "request head too large")
            request = parse_head(head)
            self._check_canaries(request.head, client_ip, where="request head")
            if request.method == "CONNECT":
                await self._tunnel(request, reader, writer, client_ip)
            else:
                await self._forward(request, reader, writer, client_ip)
        except ProxyError as exc:
            await self._reply(writer, exc.status, exc.reason)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
            pass
        except (ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    @staticmethod
    async def _reply(writer: Sink, status: int, reason: str) -> None:
        body = f"agent-sandbox gateway: {reason}\n".encode()
        head = (
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode("latin-1", "replace")
        with contextlib.suppress(Exception):
            writer.write(head + body)
            await writer.drain()

    # ------------------------------------------------------------------ policy

    def _check_canaries(
        self, data: bytes, client: str, *, where: str, host: str | None = None, tls: bool = False
    ) -> None:
        hits = self.matcher.scan(data)
        if hits:
            self._exfiltration(hits, client, where=where, host=host, tls=tls)

    def _exfiltration(
        self, hits: list[CanaryHit], client: str, *, where: str, host: str | None, tls: bool
    ) -> None:
        for hit in hits:
            self.log.alert(
                "canary.exfiltration",
                "critical",
                f"canary {hit.kind} ({hit.encoding}) found in {where}"
                + (f" to {host}" if host else "")
                + (" (decrypted TLS)" if tls else ""),
                canary_id=hit.canary_id,
                canary_kind=hit.kind,
                encoding=hit.encoding,
                where=where,
                host=host,
                tls=tls,
                client=client,
            )
        raise ProxyError(403, "blocked: canary credential detected in outbound data")

    def _authorize(self, host: str, port: int, method: str, client: str) -> None:
        hits = self.matcher.scan_hostname(host)
        if hits:
            self._exfiltration(hits, client, where="destination host", host=host, tls=False)
        if not self.allowlist.allows(host, port):
            self.log.event("egress.denied", host=host, port=port, method=method, client=client)
            raise ProxyError(403, f"blocked: {host}:{port} is not in the allowlist")

    def _check_request(self, host: str, port: int, method: str, path: str, client: str) -> None:
        """Apply the method and path rules of the allowlist to one visible request."""
        if not self.allowlist.permits(host, port, method, path):
            self.log.event(
                "egress.denied",
                host=host,
                port=port,
                method=method,
                path=path[:200],
                reason="method or path not allowed",
                client=client,
            )
            raise ProxyError(403, f"blocked: {method} {path[:100]} is not allowed for {host}")

    def _check_authority(
        self, authority: str, host: str, port: int, client: str, *, tls: bool
    ) -> None:
        """Refuse a ``Host`` (or absolute target) naming another server than the connection.

        Behind a shared front end (CDN, cloud load balancer) the ``Host`` header
        selects the backend, so a mismatch would reach a host that is not in the
        allowlist (domain fronting).
        """
        try:
            name, named_port = split_host_port(authority.rsplit("@", 1)[-1], port)
        except ValueError:
            raise ProxyError(400, "invalid Host header") from None
        if (name, named_port) != (host, port):
            self.log.alert(
                "egress.host_mismatch",
                "warning",
                f"request for {name}:{named_port} sent over a connection to {host}:{port}",
                host=host,
                port=port,
                requested=f"{name}:{named_port}",
                tls=tls,
                client=client,
            )
            raise ProxyError(403, f"blocked: Host {name} does not match {host}")

    async def _resolve(self, host: str, port: int) -> list[str]:
        """Return the public addresses of ``host``, IPv4 first.

        Allowlisted names that resolve only to private, loopback or link-local
        addresses are refused (DNS rebinding, cloud metadata endpoints). IP
        literals are returned as is: the allowlist only accepts them when listed.
        """
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return [host]
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), self.connect_timeout
            )
        except (OSError, TimeoutError) as exc:
            self.log.event("egress.error", host=host, port=port, error=str(exc) or "timeout")
            raise ProxyError(502, f"cannot resolve {host}") from None
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
        public = sorted((a for a in addresses if is_public(a)), key=lambda a: ":" in a)
        if not public:
            self.log.alert(
                "egress.private_address",
                "warning",
                f"{host} resolves only to non-public addresses",
                host=host,
                addresses=addresses[:5],
            )
            raise ProxyError(403, f"blocked: {host} resolves to a non-public address")
        return public

    async def _open(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        error = "no address"
        for address in await self._resolve(host, port):
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(address, port), self.connect_timeout
                )
            except (OSError, TimeoutError) as exc:
                error = str(exc) or "timeout"
        self.log.event("egress.error", host=host, port=port, error=error)
        raise ProxyError(502, f"cannot reach {host}:{port}")

    # ------------------------------------------------------------------ CONNECT tunnels

    async def _tunnel(
        self,
        request: Request,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client: str,
    ) -> None:
        try:
            host, port = split_host_port(request.target, 443)
        except ValueError:
            raise ProxyError(400, "invalid CONNECT target") from None
        self._authorize(host, port, "CONNECT", client)
        upstream_reader, upstream_writer = await self._open(host, port)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        first = await asyncio.wait_for(reader.read(CHUNK), self.idle_timeout)
        tls = looks_like_tls(first)
        if tls:
            first = await self._read_hello(reader, first)
            sni = server_name(first)
            if sni is not None and sni != host:
                self.log.alert(
                    "egress.sni_mismatch",
                    "warning",
                    f"TLS server name {sni} does not match CONNECT target {host}",
                    host=host,
                    sni=sni,
                    client=client,
                )
                upstream_writer.close()
                return
        elif self.allowlist.restricted(host, port):
            # Method and path rules apply to plaintext tunnels as well.
            self.log.event(
                "egress.allowed",
                host=host,
                port=port,
                method="CONNECT",
                inspected=True,
                client=client,
            )
            source = BufferedReader(lambda: reader.read(CHUNK), first)
            await self._relay_session(
                source, writer, upstream_reader, upstream_writer, host, port, client, tls=False
            )
            return
        else:
            self._check_canaries(first, client, where="tunnel data", host=host)
        self.log.event("egress.allowed", host=host, port=port, method="CONNECT", client=client)
        upstream_writer.write(first)
        await upstream_writer.drain()
        try:
            await asyncio.gather(
                self._pump(reader, upstream_writer, client, host, scan=not tls),
                self._pump(upstream_reader, writer, client, host, scan=False),
                return_exceptions=True,
            )
        finally:
            upstream_writer.close()

    async def _read_hello(self, reader: asyncio.StreamReader, first: bytes) -> bytes:
        """Buffer the whole ClientHello so a fragmented one cannot hide its SNI."""
        data = first
        while not hello_complete(data):
            more = await asyncio.wait_for(reader.read(CHUNK), self.idle_timeout)
            if not more:
                break
            data += more
        return data

    async def _pump(
        self,
        source: Any,
        sink: Sink,
        client: str,
        host: str,
        *,
        scan: bool,
    ) -> None:
        window = b""
        try:
            while True:
                data = await asyncio.wait_for(source.read(CHUNK), self.idle_timeout)
                if not data:
                    break
                if scan:
                    window = window[-SCAN_OVERLAP:] + data
                    self._check_canaries(window, client, where="tunnel data", host=host)
                sink.write(data)
                await sink.drain()
        except asyncio.CancelledError:
            raise  # The owner of the connection decides what happens to the sink.
        except BaseException:
            # A blocked or failed direction tears down the whole connection.
            with contextlib.suppress(Exception):
                sink.close()
            raise
        # Propagate a half-close so the other direction can finish its reply.
        with contextlib.suppress(Exception):
            if sink.can_write_eof():
                sink.write_eof()
            else:
                sink.close()

    # ------------------------------------------------------------------ inspected sessions

    async def _relay_session(
        self,
        source: BufferedReader,
        client_writer: Sink,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        host: str,
        port: int,
        client: str,
        *,
        tls: bool,
    ) -> None:
        """Relay parsed requests upstream and raw responses back until either side ends."""
        relay = asyncio.ensure_future(
            self._relay_requests(source, upstream_writer, host, port, client, tls=tls)
        )
        pump = asyncio.ensure_future(
            self._pump(upstream_reader, client_writer, client, host, scan=False)
        )
        try:
            await asyncio.wait({relay, pump}, return_when=asyncio.FIRST_COMPLETED)
            if not relay.done():
                return  # The server closed the connection; the finally clause cleans up.
            error = relay.exception()
            if error is None and upstream_writer.can_write_eof():
                # The client half-closed after its last request: let the reply through.
                upstream_writer.write_eof()
                await asyncio.gather(pump, return_exceptions=True)
            pump.cancel()
            await asyncio.gather(pump, return_exceptions=True)
            if isinstance(error, ProxyError):
                await self._reply(client_writer, error.status, error.reason)
        finally:
            for task in (relay, pump):
                task.cancel()
            await asyncio.gather(relay, pump, return_exceptions=True)
            upstream_writer.close()

    def _request_path(self, request: Request, host: str, port: int, client: str, tls: bool) -> str:
        """Validate the target and ``Host`` of a request inside a tunnel; return its path."""
        target = request.target
        if request.method == "CONNECT":
            raise ProxyError(400, "CONNECT is not supported inside a tunnel")
        if target == "*" and request.method == "OPTIONS":
            path = "*"
        elif target.startswith("/"):
            path = target.split("?", 1)[0]
        else:
            url = urlsplit(target)
            if url.scheme not in {"http", "https"} or not url.netloc:
                raise ProxyError(400, "invalid request target")
            self._check_authority(url.netloc, host, port, client, tls=tls)
            path = url.path or "/"
        hosts = request.header_values("host")
        if len(hosts) > 1 or (not hosts and request.version == "HTTP/1.1"):
            raise ProxyError(400, "exactly one Host header is required")
        if hosts:
            self._check_authority(hosts[0], host, port, client, tls=tls)
        return path

    async def _relay_requests(
        self,
        source: BufferedReader,
        upstream: asyncio.StreamWriter,
        host: str,
        port: int,
        client: str,
        *,
        tls: bool,
    ) -> None:
        """Forward HTTP/1.x requests one by one, enforcing the policy on each."""
        while True:
            try:
                head = await asyncio.wait_for(source.readuntil(b"\r\n\r\n"), self.idle_timeout)
            except asyncio.IncompleteReadError as exc:
                if exc.partial:
                    raise ProxyError(400, "incomplete request head") from None
                return
            except asyncio.LimitOverrunError:
                raise ProxyError(431, "request head too large") from None
            request = parse_head(head)
            self._check_canaries(head, client, where="request head", host=host, tls=tls)
            path = self._request_path(request, host, port, client, tls)
            self._check_request(host, port, request.method, path, client)
            if request.header("upgrade") is not None:
                raise ProxyError(501, "protocol upgrades are not supported by the gateway")
            length = body_length(request)
            upstream.write(serialize_head(request))
            await self._relay_body(source, upstream, length, host, client, tls=tls)
            self.log.event(
                "egress.request",
                host=host,
                port=port,
                method=request.method,
                path=path[:200],
                tls=tls,
                client=client,
            )

    async def _relay_body(
        self,
        source: BufferedReader,
        sink: asyncio.StreamWriter,
        length: int | None,
        host: str,
        client: str,
        *,
        tls: bool,
    ) -> None:
        """Stream a request body upstream, scanning it without releasing a partial canary."""
        scanner = StreamScanner(self.matcher)
        chunked = length is None

        async def take(size: int) -> int:
            """Consume up to ``size`` body bytes and forward what is proven clean."""
            data = await asyncio.wait_for(source.read(min(size, CHUNK)), self.idle_timeout)
            if not data:
                raise ProxyError(400, "request body ended early")
            safe, hits = scanner.feed(data)
            if hits:
                self._exfiltration(hits, client, where="request body", host=host, tls=tls)
            if safe:
                sink.write(chunk(safe) if chunked else safe)
                await sink.drain()
            return len(data)

        if length is not None:
            while length:
                length -= await take(length)
            sink.write(scanner.flush())
            await sink.drain()
            return
        while True:
            size = chunk_size(await asyncio.wait_for(source.readuntil(b"\r\n"), self.idle_timeout))
            if size == 0:
                trailers = b""
                while (line := await source.readuntil(b"\r\n")) != b"\r\n":
                    trailers += line
                    if len(trailers) > MAX_HEAD:
                        raise ProxyError(431, "trailer section too large")
                # Trailers are scanned but not forwarded: they are rarely needed and
                # would have to be validated like headers.
                self._check_canaries(trailers, client, where="request body", host=host, tls=tls)
                tail = scanner.flush()
                sink.write((chunk(tail) if tail else b"") + b"0\r\n\r\n")
                await sink.drain()
                return
            while size:
                size -= await take(size)
            if await source.readexactly(2) != b"\r\n":
                raise ProxyError(400, "malformed chunked body")

    # ------------------------------------------------------------------ plain HTTP

    async def _read_body(self, request: Request, reader: asyncio.StreamReader) -> bytes:
        length = body_length(request)
        if length is None:
            body = bytearray()
            while True:
                size = chunk_size(await reader.readuntil(b"\r\n"))
                if size == 0:
                    while await reader.readuntil(b"\r\n") != b"\r\n":
                        pass  # trailer section (ignored)
                    return bytes(body)
                if len(body) + size > self.max_body:
                    raise ProxyError(413, "request body too large")
                body += await reader.readexactly(size)
                if await reader.readexactly(2) != b"\r\n":
                    raise ProxyError(400, "malformed chunked body")
        if length > self.max_body:
            raise ProxyError(413, "request body too large")
        return await reader.readexactly(length)

    async def _forward(
        self,
        request: Request,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client: str,
    ) -> None:
        url = urlsplit(request.target)
        if url.scheme != "http" or not url.netloc:
            raise ProxyError(400, "only absolute http:// URLs and CONNECT are supported")
        try:
            host, port = split_host_port(url.netloc.rsplit("@", 1)[-1], 80)
        except ValueError:
            raise ProxyError(400, "invalid host") from None
        self._authorize(host, port, request.method, client)
        host_header = request.header("host")
        if host_header is not None:
            self._check_authority(host_header, host, port, client, tls=False)
        path = url.path or "/"
        self._check_request(host, port, request.method, path, client)
        if (request.header("expect") or "").lower() == "100-continue":
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()
        body = await self._read_body(request, reader)
        self._check_canaries(body, client, where="request body", host=host)

        if url.query:
            path += "?" + url.query
        lines = [f"{request.method} {path} HTTP/1.1"]
        lines += [f"{k}: {v}" for k, v in request.headers if k.lower() not in HOP_BY_HOP]
        lines = [line for line in lines if not line.lower().startswith("content-length:")]
        if body or request.method in {"POST", "PUT", "PATCH"}:
            lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        upstream_reader, upstream_writer = await self._open(host, port)
        self.log.event(
            "egress.allowed", host=host, port=port, method=request.method, client=client
        )
        upstream_writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
        await upstream_writer.drain()
        await self._pump(upstream_reader, writer, client, host, scan=False)
        upstream_writer.close()


async def serve(proxy: Proxy, host: str, port: int) -> asyncio.Server:
    return await asyncio.start_server(proxy.handle, host, port, limit=MAX_HEAD)
