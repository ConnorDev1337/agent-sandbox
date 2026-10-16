"""DNS sinkhole for the agent network.

The agent reaches the internet only through the HTTP proxy, so it never needs
to resolve external names itself. Every query is answered NXDOMAIN and logged;
names that carry canary data (DNS tunnelling) raise a critical alert.
"""

from __future__ import annotations

import asyncio
import struct

from ..canary import CanaryMatcher
from .alerts import EventLog

NXDOMAIN = 3
FORMERR = 1
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


def parse_query(packet: bytes) -> tuple[int, int, str, int, int]:
    """Return ``(id, flags, qname, qtype, end_of_question)`` of a DNS query."""
    if len(packet) < 12:
        raise ValueError("short packet")
    query_id, flags, qdcount = struct.unpack_from("!HHH", packet, 0)
    if qdcount < 1:
        raise ValueError("no question")
    labels, pos = [], 12
    while True:
        length = packet[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:
            raise ValueError("compressed name in question")
        labels.append(packet[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
        if pos >= len(packet):
            raise ValueError("truncated name")
    qtype, _qclass = struct.unpack_from("!HH", packet, pos)
    return query_id, flags, ".".join(labels), qtype, pos + 4


def build_response(packet: bytes, rcode: int) -> bytes:
    """Answer ``packet`` with ``rcode``, echoing the question when it is parsable."""
    try:
        query_id, flags, _name, _qtype, end = parse_query(packet)
        question, qdcount = packet[12:end], 1
    except (ValueError, IndexError, struct.error):
        query_id = struct.unpack_from("!H", packet, 0)[0] if len(packet) >= 2 else 0
        flags, question, qdcount, rcode = 0, b"", 0, FORMERR
    reply_flags = 0x8000 | (flags & 0x7900) | rcode  # QR, opcode and RD copied, RA=0
    return struct.pack("!HHHHHH", query_id, reply_flags, qdcount, 0, 0, 0) + question


class SinkholeProtocol(asyncio.DatagramProtocol):
    def __init__(self, matcher: CanaryMatcher, log: EventLog) -> None:
        self.matcher = matcher
        self.log = log
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            _, _, name, qtype, _ = parse_query(data)
        except (ValueError, IndexError, struct.error):
            name, qtype = "", 0
        if name:
            self.log.event(
                "dns.query", name=name[:253], qtype=QTYPES.get(qtype, qtype), client=addr[0]
            )
            for hit in self.matcher.scan_hostname(name):
                self.log.alert(
                    "canary.dns",
                    "critical",
                    f"canary {hit.kind} ({hit.encoding}) found in DNS query",
                    canary_id=hit.canary_id,
                    canary_kind=hit.kind,
                    encoding=hit.encoding,
                    client=addr[0],
                )
        if self.transport is not None:
            self.transport.sendto(build_response(data, NXDOMAIN), addr)


async def serve(
    matcher: CanaryMatcher, log: EventLog, host: str, port: int
) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SinkholeProtocol(matcher, log), local_addr=(host, port)
    )
    return transport  # type: ignore[return-value]
