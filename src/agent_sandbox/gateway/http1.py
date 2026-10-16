"""HTTP/1.x request parsing for traffic the gateway can read.

The gateway forwards what it parsed, so parsing is strict: anything two HTTP
implementations could frame differently (bare CR or LF, whitespace before a
colon, both Content-Length and Transfer-Encoding, odd chunk sizes) is refused
instead of being guessed at.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

MAX_HEAD = 64 * 1024
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_VERSION = re.compile(r"^HTTP/1\.[01]$")
_CHUNK_SIZE = re.compile(rb"^[0-9A-Fa-f]{1,16}$")
# Proxy-only headers that must not travel past the gateway.
_PROXY_HEADERS = frozenset({"proxy-authorization", "proxy-connection"})


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

    def header_values(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


def parse_head(head: bytes) -> Request:
    """Parse a request head that ends with an empty line."""
    try:
        text = head.decode("iso-8859-1")
        lines = text.split("\r\n")
        method, target, version = lines[0].split(" ", 2)
    except (UnicodeDecodeError, ValueError):
        raise ProxyError(400, "malformed request line") from None
    if any("\r" in line or "\n" in line or "\0" in line for line in lines):
        raise ProxyError(400, "bare CR, LF or NUL in request head")
    if not _TOKEN.match(method) or not target or " " in target or not _VERSION.match(version):
        raise ProxyError(400, "malformed request line")
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not _TOKEN.match(name):
            raise ProxyError(400, "malformed header")
        headers.append((name, value.strip(" \t")))
    return Request(method.upper(), target, version, headers, head)


def body_length(request: Request) -> int | None:
    """Return the request body length, or ``None`` for a chunked body."""
    encodings = request.header_values("transfer-encoding")
    lengths = request.header_values("content-length")
    if encodings:
        if lengths:
            raise ProxyError(400, "both Transfer-Encoding and Content-Length")
        if len(encodings) != 1 or encodings[0].strip().lower() != "chunked":
            raise ProxyError(501, "unsupported Transfer-Encoding")
        return None
    if not lengths:
        return 0
    values = {value.strip() for value in lengths}
    value = values.pop()
    if values or not value.isdigit() or len(value) > 18:
        raise ProxyError(400, "invalid Content-Length")
    return int(value)


def chunk_size(line: bytes) -> int:
    """Parse a chunk-size line (extensions ignored)."""
    size = line.rstrip(b"\r\n").split(b";", 1)[0].strip(b" \t")
    if not _CHUNK_SIZE.match(size):
        raise ProxyError(400, "malformed chunked body")
    return int(size, 16)


def serialize_head(request: Request) -> bytes:
    """Rebuild a request head from its parsed form, minus proxy-only headers."""
    lines = [f"{request.method} {request.target} {request.version}"]
    lines += [f"{k}: {v}" for k, v in request.headers if k.lower() not in _PROXY_HEADERS]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")


def chunk(data: bytes) -> bytes:
    return b"%x\r\n%s\r\n" % (len(data), data)


class BufferedReader:
    """Pull-based reader over an async byte source.

    It accepts bytes that were already read from the source (the first bytes of
    a tunnel, inspected before deciding how to handle it) and only reads more
    when asked, so the sender is naturally back-pressured.
    """

    def __init__(
        self, source: Callable[[], Awaitable[bytes]], initial: bytes = b"", limit: int = MAX_HEAD
    ) -> None:
        self._source = source
        self._buffer = bytearray(initial)
        self._limit = limit
        self._eof = False

    async def _fill(self) -> bool:
        if self._eof:
            return False
        data = await self._source()
        if not data:
            self._eof = True
            return False
        self._buffer += data
        return True

    def _take(self, size: int) -> bytes:
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    async def readuntil(self, separator: bytes) -> bytes:
        start = 0
        while True:
            index = self._buffer.find(separator, start)
            if index >= 0:
                return self._take(index + len(separator))
            if len(self._buffer) > self._limit:
                raise asyncio.LimitOverrunError("separator not found", len(self._buffer))
            start = max(len(self._buffer) - len(separator) + 1, 0)
            if not await self._fill():
                raise asyncio.IncompleteReadError(self._take(len(self._buffer)), None)

    async def read(self, size: int) -> bytes:
        if not self._buffer:
            await self._fill()
        return self._take(size)

    async def readexactly(self, size: int) -> bytes:
        while len(self._buffer) < size:
            if not await self._fill():
                raise asyncio.IncompleteReadError(self._take(len(self._buffer)), size)
        return self._take(size)
