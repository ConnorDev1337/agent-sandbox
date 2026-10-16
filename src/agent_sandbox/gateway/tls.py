"""Minimal TLS ClientHello parsing to read the SNI server name."""

from __future__ import annotations

import struct

_HANDSHAKE = 0x16
_CLIENT_HELLO = 0x01
_SERVER_NAME = 0x0000


def looks_like_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] == _HANDSHAKE and data[1] == 0x03


def server_name(data: bytes) -> str | None:
    """Return the SNI host name of a ClientHello, or ``None`` if absent or unparsable."""
    try:
        if not looks_like_tls(data) or data[5] != _CLIENT_HELLO:
            return None
        pos = 5 + 4  # record header, handshake header
        pos += 2 + 32  # client_version, random
        pos += 1 + data[pos]  # session_id
        (suites_len,) = struct.unpack_from("!H", data, pos)
        pos += 2 + suites_len
        pos += 1 + data[pos]  # compression_methods
        (extensions_len,) = struct.unpack_from("!H", data, pos)
        pos += 2
        end = min(pos + extensions_len, len(data))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", data, pos)
            pos += 4
            if ext_type == _SERVER_NAME:
                (list_len,) = struct.unpack_from("!H", data, pos)
                cursor, list_end = pos + 2, pos + 2 + list_len
                while cursor + 3 <= list_end:
                    name_type, name_len = struct.unpack_from("!BH", data, cursor)
                    cursor += 3
                    if name_type == 0:
                        return data[cursor : cursor + name_len].decode("ascii").lower()
                    cursor += name_len
                return None
            pos += ext_len
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None
