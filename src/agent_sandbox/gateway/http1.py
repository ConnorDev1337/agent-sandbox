"""HTTP/1.x request parsing for traffic the gateway can read.

The gateway forwards what it parsed, so parsing is strict: anything two HTTP
implementations could frame differently (bare CR or LF, control characters,
whitespace before a colon, both Content-Length and Transfer-Encoding, framing
values other than digits or exactly ``chunked``, odd chunk sizes) is refused
instead of being guessed at.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

MAX_HEAD = 64 * 1024
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_VERSION = re.compile(r"HTTP/1\.[01]")
# Visible ASCII but "#": no whitespace, control characters, fragment or raw
# non-ASCII bytes (which servers may decode differently, e.g. as overlong UTF-8).
_TARGET = re.compile(r"[\x21\x22\x24-\x7e]+")
_FIELD_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")  # control characters but HTAB
_LENGTH = re.compile(r"[0-9]{1,18}")
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,16}")
_METHOD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
# Whitespace that lenient servers skip before a request line, and accept after
# the method (the first four), as RFC 9112 (section 3) allows.
_LENIENT_SPACE = b" \t\x0b\x0c\r\n"
# Proxy-only headers that must not travel past the gateway.
_PROXY_HEADERS = frozenset({"proxy-authorization", "proxy-connection"})
# The start of the HTTP/2 connection preface (RFC 9113, section 3.4), as read
# up to its first empty line, and the reply refusing it: an empty SETTINGS
# frame, then GOAWAY with HTTP_1_1_REQUIRED so the client can fall back.
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\n"
H2_REFUSAL = (
    b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    b"\x00\x00\x08\x07\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x0d"
)


class ProxyError(Exception):
    """A request refused by the gateway, answered with ``status`` or a raw ``response``."""

    def __init__(self, status: int, reason: str, response: bytes | None = None) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.response = response


def request_start(data: bytes) -> bool | None:
    """Tell whether a byte stream starts like an HTTP/1 request line.

    The answer errs towards a request: whatever a lenient server could read as
    one (after leading whitespace or empty lines, with other whitespace than a
    space after the method, with a long method) is then parsed, and refused by
    the strict parser, instead of being relayed unparsed. Returns ``None``
    while ``data`` could still be the start of a method, so the answer does not
    depend on how the stream was split into reads.
    """
    if data[:1] and data[0] in _LENIENT_SPACE:
        return True
    match = _METHOD.match(data)
    if match is None:
        return False
    if match.end() == len(data):
        return None if len(data) < MAX_HEAD else True
    return data[match.end()] in _LENIENT_SPACE[:4]


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
    """Parse a request head that ends with its first empty line."""
    lines = head.decode("iso-8859-1").split("\r\n")
    if any("\r" in line or "\n" in line or "\0" in line for line in lines):
        raise ProxyError(400, "bare CR, LF or NUL in request head")
    if len(lines) < 3 or lines[-2:] != ["", ""] or "" in lines[:-2]:
        raise ProxyError(400, "malformed request head")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ProxyError(400, "malformed request line")
    method, target, version = parts
    valid = _TOKEN.fullmatch(method) and _TARGET.fullmatch(target) and _VERSION.fullmatch(version)
    if not valid:
        raise ProxyError(400, "malformed request line")
    headers = []
    for line in lines[1:-2]:
        name, sep, value = line.partition(":")
        if not sep or not _TOKEN.fullmatch(name):
            raise ProxyError(400, "malformed header")
        if _FIELD_CONTROL.search(value):
            raise ProxyError(400, "control character in header value")
        headers.append((name, value.strip(" \t")))
    return Request(method.upper(), target, version, headers, head)


def body_length(request: Request) -> int | None:
    """Return the request body length, or ``None`` for a chunked body."""
    encodings = request.header_values("transfer-encoding")
    lengths = request.header_values("content-length")
    if encodings:
        if lengths:
            raise ProxyError(400, "both Transfer-Encoding and Content-Length")
        if request.version == "HTTP/1.0":
            # Such framing is faulty (RFC 9112, section 6.1): servers may ignore it.
            raise ProxyError(400, "Transfer-Encoding in an HTTP/1.0 request")
        # Values are stripped of SP and HTAB only: with anything else around it,
        # a server might not recognize the coding as chunked.
        if len(encodings) != 1 or encodings[0].lower() != "chunked":
            raise ProxyError(501, "unsupported Transfer-Encoding")
        return None
    if not lengths:
        return 0
    values = set(lengths)
    value = values.pop()
    if values or not _LENGTH.fullmatch(value):
        raise ProxyError(400, "invalid Content-Length")
    return int(value)


def chunk_size(line: bytes) -> int:
    """Parse a chunk-size line ending with CRLF (extensions ignored)."""
    content = line.removesuffix(b"\r\n")
    size = content.split(b";", 1)[0].strip(b" \t")
    if b"\r" in content or b"\n" in content or not _CHUNK_SIZE.fullmatch(size):
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
