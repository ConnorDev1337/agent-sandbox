"""TLS helpers: ClientHello parsing (SNI) and server-side TLS over memory BIOs."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import struct
from dataclasses import dataclass

_HANDSHAKE = 0x16
_READ_SIZE = 64 * 1024
_CLIENT_HELLO = 0x01
_SERVER_NAME = 0x0000
_ALPN = 0x0010
MAX_HELLO = 64 * 1024  # Larger first handshake messages are not legitimate ClientHellos
# Fatal no_application_protocol alert (RFC 7301), sent in the clear before the handshake.
NO_APPLICATION_PROTOCOL = b"\x15\x03\x03\x00\x02\x02\x78"


def looks_like_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] == _HANDSHAKE and data[1] == 0x03


def handshake_message(data: bytes) -> bytes | None:
    """Reassemble the first handshake message from consecutive TLS records.

    A ClientHello may be fragmented over several records and arrive in several
    reads. Returns ``None`` while the message is incomplete.
    """
    payload = bytearray()
    pos = 0
    while pos + 5 <= len(data) and data[pos] == _HANDSHAKE:
        (length,) = struct.unpack_from("!H", data, pos + 3)
        if pos + 5 + length > len(data):
            return None
        payload += data[pos + 5 : pos + 5 + length]
        pos += 5 + length
        if len(payload) >= 4:
            size = int.from_bytes(payload[1:4], "big")
            if len(payload) >= 4 + size:
                return bytes(payload[: 4 + size])
    return None


def hello_complete(data: bytes) -> bool:
    """Return True once nothing more is needed to judge the first handshake message."""
    if handshake_message(data) is not None or len(data) >= MAX_HELLO:
        return True
    # Stop waiting as soon as the stream is not a sequence of handshake records.
    pos = 0
    while pos + 5 <= len(data):
        if data[pos] != _HANDSHAKE:
            return True
        pos += 5 + struct.unpack_from("!H", data, pos + 3)[0]
    return False


class MalformedHello(ValueError):
    """The stream does not start with one complete, well-formed ClientHello."""


@dataclass(frozen=True)
class ClientHello:
    server_name: str | None  # lowercased; None when the client sends no SNI
    alpn: tuple[str, ...] | None  # None when the client offers no ALPN


class _Fields:
    """Cursor over TLS presentation-language fields; short reads are malformed."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take(self, size: int) -> bytes:
        if size > self.remaining:
            raise MalformedHello("truncated ClientHello")
        self._pos += size
        return self._data[self._pos - size : self._pos]

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, length_size: int) -> bytes:
        return self.take(self.number(length_size))

    def end(self, what: str) -> None:
        if self.remaining:
            raise MalformedHello(f"trailing data after the {what}")


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse the ClientHello at the start of a TLS stream, strictly.

    Anything a TLS server could read differently from the gateway raises
    :class:`MalformedHello`: an incomplete or oversized message, inconsistent
    lengths, duplicate extensions, or a server name list with anything but a
    single non-empty ASCII host name. The gateway refuses such connections, so
    a server name it cannot check never reaches a server that could read one.
    """
    message = handshake_message(data) if looks_like_tls(data) else None
    if message is None:
        raise MalformedHello("no complete ClientHello")
    if message[0] != _CLIENT_HELLO:
        raise MalformedHello("the first handshake message is not a ClientHello")
    fields = _Fields(message[4:])
    fields.take(2 + 32)  # legacy_version, random
    if len(fields.vector(1)) > 32:
        raise MalformedHello("session id longer than 32 bytes")
    suites = fields.vector(2)
    if not suites or len(suites) % 2:
        raise MalformedHello("malformed cipher suite list")
    if not fields.vector(1):
        raise MalformedHello("no compression method")
    extensions: dict[int, bytes] = {}
    if fields.remaining:  # Extensions are optional before TLS 1.3
        block = _Fields(fields.vector(2))
        fields.end("extensions")
        while block.remaining:
            kind, body = block.number(2), block.vector(2)
            if kind in extensions:
                raise MalformedHello(f"duplicate extension {kind}")
            extensions[kind] = body
    return ClientHello(_host_name(extensions.get(_SERVER_NAME)), _protocols(extensions.get(_ALPN)))


def _host_name(extension: bytes | None) -> str | None:
    if extension is None:
        return None
    fields = _Fields(extension)
    names = _Fields(fields.vector(2))
    fields.end("server name list")
    if not names.remaining:
        raise MalformedHello("empty server name list")
    if names.number(1) != 0:  # host_name, the only name type (RFC 6066)
        raise MalformedHello("unknown server name type")
    name = names.vector(2)
    names.end("host name")  # One name only: servers disagree on which one counts
    if not name or not name.isascii() or b"\0" in name:
        raise MalformedHello("invalid server name")
    return name.decode("ascii").lower()


def _protocols(extension: bytes | None) -> tuple[str, ...] | None:
    if extension is None:
        return None
    fields = _Fields(extension)
    names = _Fields(fields.vector(2))
    fields.end("ALPN protocol list")
    protocols = []
    while names.remaining:
        name = names.vector(1)
        if not name:
            raise MalformedHello("empty ALPN protocol name")
        protocols.append(name.decode("ascii", "replace"))
    if not protocols:
        raise MalformedHello("empty ALPN protocol list")
    return tuple(protocols)


def server_name(data: bytes) -> str | None:
    """Return the SNI host name of a ClientHello, or ``None`` if absent or unparsable."""
    try:
        return parse_client_hello(data).server_name
    except MalformedHello:
        return None


def alpn_protocols(data: bytes) -> list[str] | None:
    """Return the ALPN protocols a ClientHello offers, or ``None`` if none or unparsable."""
    try:
        protocols = parse_client_hello(data).alpn
    except MalformedHello:
        return None
    return None if protocols is None else list(protocols)


class TLSServerSession:
    """Server side of a TLS connection driven over an existing asyncio stream.

    ``asyncio``'s ``start_tls`` cannot be used here: the proxy has already read
    the ClientHello from the stream to check its server name, so those bytes
    are fed to an ``SSLObject`` through memory BIOs instead. Reads are pulled
    on demand, so a slow upstream back-pressures the client.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        context: ssl.SSLContext,
        received: bytes = b"",
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl = context.wrap_bio(self._incoming, self._outgoing, server_side=True)
        self._incoming.write(received)
        self._closed = False

    def _flush(self) -> None:
        data = self._outgoing.read()
        if data:
            self._writer.write(data)

    async def _receive_raw(self) -> bool:
        await self._writer.drain()
        data = await self._reader.read(_READ_SIZE)
        if not data:
            self._incoming.write_eof()
            return False
        self._incoming.write(data)
        return True

    async def handshake(self) -> None:
        while True:
            try:
                self._ssl.do_handshake()
                break
            except ssl.SSLWantReadError:
                self._flush()
            if not await self._receive_raw():
                raise ConnectionError("client closed the connection during the handshake")
        self._flush()
        await self._writer.drain()

    @property
    def alpn_protocol(self) -> str | None:
        return self._ssl.selected_alpn_protocol()

    async def receive(self) -> bytes:
        """Return the next decrypted bytes, or ``b""`` once the client is done."""
        while True:
            try:
                data = self._ssl.read(_READ_SIZE)
            except ssl.SSLWantReadError:
                self._flush()  # e.g. replies to key updates
                if not await self._receive_raw():
                    return b""
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""
            self._flush()
            return data

    def write(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("TLS session is closed")
        self._ssl.write(data)
        self._flush()

    async def drain(self) -> None:
        await self._writer.drain()

    def can_write_eof(self) -> bool:
        return False

    def write_eof(self) -> None:
        raise NotImplementedError("TLS has no half-close")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(ssl.SSLError, ValueError):
            self._ssl.unwrap()  # Queues close_notify; the peer's reply is not awaited
        with contextlib.suppress(Exception):
            self._flush()
            self._writer.close()
