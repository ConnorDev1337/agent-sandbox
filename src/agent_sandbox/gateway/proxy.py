"""Allowlisting forward proxy (HTTP and CONNECT) with canary detection.

The agent container has no route to the internet; this proxy is its only way
out. Every request is checked against the allowlist, and every byte the agent
sends that the gateway can read (request lines, headers, plain-HTTP bodies,
non-TLS tunnels, TLS SNI) is scanned for canary values.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..allowlist import Allowlist, normalize_host
from ..canary import CanaryHit, CanaryMatcher
from .alerts import EventLog
from .tls import hello_complete, looks_like_tls, server_name

MAX_HEAD = 64 * 1024
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


class ProxyError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    head: bytes

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)


def is_public(address: str) -> bool:
    """Return True for globally routable unicast addresses."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def parse_head(head: bytes) -> Request:
    try:
        text = head.decode("iso-8859-1")
        lines = text.split("\r\n")
        method, target, version = lines[0].split(" ", 2)
    except (UnicodeDecodeError, ValueError):
        raise ProxyError(400, "malformed request line") from None
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            raise ProxyError(400, "malformed header")
        headers.append((name.strip(), value.strip()))
    return Request(method.upper(), target, version, headers, head)


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
    async def _reply(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
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
        self, data: bytes, client: str, *, where: str, host: str | None = None
    ) -> None:
        hits = self.matcher.scan(data)
        if hits:
            self._exfiltration(hits, client, where=where, host=host)

    def _exfiltration(
        self, hits: list[CanaryHit], client: str, *, where: str, host: str | None
    ) -> None:
        for hit in hits:
            self.log.alert(
                "canary.exfiltration",
                "critical",
                f"canary {hit.kind} ({hit.encoding}) found in {where}"
                + (f" to {host}" if host else ""),
                canary_id=hit.canary_id,
                canary_kind=hit.kind,
                encoding=hit.encoding,
                where=where,
                host=host,
                client=client,
            )
        raise ProxyError(403, "blocked: canary credential detected in outbound data")

    def _authorize(self, host: str, port: int, method: str, client: str) -> None:
        hits = self.matcher.scan_hostname(host)
        if hits:
            self._exfiltration(hits, client, where="destination host", host=host)
        if not self.allowlist.allows(host, port):
            self.log.event("egress.denied", host=host, port=port, method=method, client=client)
            raise ProxyError(403, f"blocked: {host}:{port} is not in the allowlist")

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
        if looks_like_tls(first):
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
        else:
            self._check_canaries(first, client, where="tunnel data", host=host)
        self.log.event("egress.allowed", host=host, port=port, method="CONNECT", client=client)
        upstream_writer.write(first)
        await upstream_writer.drain()
        try:
            await asyncio.gather(
                self._pump(reader, upstream_writer, client, host, scan=not looks_like_tls(first)),
                self._pump(upstream_reader, writer, client, host, scan=False),
                return_exceptions=True,
            )
        finally:
            upstream_writer.close()

    async def _read_hello(self, reader: asyncio.StreamReader, first: bytes) -> bytes:
        """Buffer the whole ClientHello so a fragmented one cannot hide its SNI."""
        data = first
        while not hello_complete(data):
            chunk = await asyncio.wait_for(reader.read(CHUNK), self.idle_timeout)
            if not chunk:
                break
            data += chunk
        return data

    async def _pump(
        self,
        source: asyncio.StreamReader,
        sink: asyncio.StreamWriter,
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

    # ------------------------------------------------------------------ plain HTTP

    async def _read_body(self, request: Request, reader: asyncio.StreamReader) -> bytes:
        if (request.header("transfer-encoding") or "").lower() == "chunked":
            body = bytearray()
            while True:
                size_line = await reader.readuntil(b"\r\n")
                try:
                    size = int(size_line.split(b";")[0].strip(), 16)
                except ValueError:
                    raise ProxyError(400, "malformed chunked body") from None
                if size == 0:
                    await reader.readuntil(b"\r\n")  # trailer section (ignored)
                    return bytes(body)
                if len(body) + size > self.max_body:
                    raise ProxyError(413, "request body too large")
                body += await reader.readexactly(size)
                await reader.readexactly(2)
        length_text = request.header("content-length")
        if not length_text:
            return b""
        try:
            length = int(length_text)
        except ValueError:
            raise ProxyError(400, "invalid Content-Length") from None
        if length < 0 or length > self.max_body:
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
        if (request.header("expect") or "").lower() == "100-continue":
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()
        body = await self._read_body(request, reader)
        self._check_canaries(body, client, where="request body", host=host)

        path = url.path or "/"
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
