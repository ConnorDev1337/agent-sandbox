"""Minimal TLS ClientHello parsing to read the SNI server name."""

from __future__ import annotations

import struct

_HANDSHAKE = 0x16
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
