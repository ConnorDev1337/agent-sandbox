"""TLS helpers: ClientHello parsing (SNI) and server-side TLS over memory BIOs."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import struct

_HANDSHAKE = 0x16
_READ_SIZE = 64 * 1024
_CLIENT_HELLO = 0x01
_SERVER_NAME = 0x0000
MAX_HELLO = 64 * 1024  # Larger first handshake messages are not legitimate ClientHellos


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


def server_name(data: bytes) -> str | None:
    """Return the SNI host name of a ClientHello, or ``None`` if absent or unparsable."""
    message = handshake_message(data) if looks_like_tls(data) else None
    try:
        if message is None or message[0] != _CLIENT_HELLO:
            return None
        pos = 4  # handshake header
        pos += 2 + 32  # client_version, random
        pos += 1 + message[pos]  # session_id
        (suites_len,) = struct.unpack_from("!H", message, pos)
        pos += 2 + suites_len
        pos += 1 + message[pos]  # compression_methods
        (extensions_len,) = struct.unpack_from("!H", message, pos)
        pos += 2
        end = min(pos + extensions_len, len(message))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", message, pos)
            pos += 4
            if ext_type == _SERVER_NAME:
                (list_len,) = struct.unpack_from("!H", message, pos)
                cursor, list_end = pos + 2, pos + 2 + list_len
                while cursor + 3 <= list_end:
                    name_type, name_len = struct.unpack_from("!BH", message, cursor)
                    cursor += 3
                    if name_type == 0:
                        return message[cursor : cursor + name_len].decode("ascii").lower()
                    cursor += name_len
                return None
            pos += ext_len
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


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
