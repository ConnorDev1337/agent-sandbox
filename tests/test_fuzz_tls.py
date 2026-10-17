"""Property-based tests of ClientHello reassembly and SNI/ALPN extraction."""

import itertools
import ssl
import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agent_sandbox.gateway.tls import (
    MAX_HELLO,
    ClientHello,
    MalformedHello,
    alpn_protocols,
    handshake_message,
    hello_complete,
    parse_client_hello,
    server_name,
)

labels = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", fullmatch=True)
hostnames = st.builds(
    lambda names, top: ".".join([*names, top]),
    st.lists(labels, min_size=1, max_size=3),
    st.from_regex(r"[a-z]{2,6}", fullmatch=True),
)
protocols = st.lists(
    st.binary(min_size=1, max_size=12).map(lambda b: b.hex()[:12]), min_size=1, max_size=4
)


def records(handshake: bytes, cuts: list[int]) -> bytes:
    """Split a handshake message into TLS records at ``cuts``."""
    points = sorted({min(c, len(handshake)) for c in cuts} | {0, len(handshake)})
    return b"".join(
        b"\x16\x03\x01" + struct.pack("!H", end - start) + handshake[start:end]
        for start, end in itertools.pairwise(points)
        if end > start
    )


def openssl_hello(name: str | None, alpn: list[str] | None) -> bytes:
    """The ClientHello Python's ssl module (OpenSSL) sends."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if alpn:
        context.set_alpn_protocols(alpn)
    client = context.wrap_bio(ssl.MemoryBIO(), outgoing := ssl.MemoryBIO(), server_hostname=name)
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    return outgoing.read()


def payload(stream: bytes) -> bytes:
    """The handshake bytes carried by a stream of handshake records."""
    out, pos = b"", 0
    while pos < len(stream):
        (length,) = struct.unpack_from("!H", stream, pos + 3)
        out += stream[pos + 5 : pos + 5 + length]
        pos += 5 + length
    return out


@st.composite
def extensions(draw):
    """Random extensions with distinct types, optionally with SNI and ALPN."""
    name = draw(st.none() | hostnames)
    alpn = draw(st.none() | protocols)
    items = {
        kind: draw(st.binary(max_size=40))
        for kind in draw(st.sets(st.integers(1, 0xFFFF).filter(lambda k: k != 16), max_size=5))
    }
    if name is not None:
        entry = struct.pack("!BH", 0, len(name)) + name.encode()
        items[0] = struct.pack("!H", len(entry)) + entry
    if alpn is not None:
        names = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        items[16] = struct.pack("!H", len(names)) + names
    order = draw(st.permutations(sorted(items)))
    block = b"".join(struct.pack("!HH", k, len(items[k])) + items[k] for k in order)
    return ClientHello(name, None if alpn is None else tuple(alpn)), block


def handshake_of(block: bytes, session: bytes = b"", suites: int = 1) -> bytes:
    body = b"\x03\x03" + b"\x07" * 32 + bytes([len(session)]) + session
    body += struct.pack("!H", 2 * suites) + b"\x13\x01" * suites + b"\x01\x00"
    body += struct.pack("!H", len(block)) + block
    return b"\x01" + len(body).to_bytes(3, "big") + body


@given(st.none() | hostnames, st.none() | protocols, st.lists(st.integers(0, 2000)))
def test_openssl_hellos_parse_whatever_the_records(name, alpn, cuts):
    stream = openssl_hello(name, alpn)
    expected = ClientHello(name, None if alpn is None else tuple(alpn))
    assert parse_client_hello(stream) == expected
    assert parse_client_hello(records(payload(stream), cuts)) == expected


@given(extensions(), st.binary(max_size=32), st.integers(1, 30), st.lists(st.integers(0, 600)))
def test_hellos_round_trip_whatever_the_records(item, session, suites, cuts):
    expected, block = item
    stream = records(handshake_of(block, session, suites), cuts)
    assert parse_client_hello(stream) == expected
    assert server_name(stream) == expected.server_name
    assert alpn_protocols(stream) == (None if expected.alpn is None else list(expected.alpn))
    # Bytes after the message (another record, early data) do not matter.
    assert parse_client_hello(stream + b"\x17\x03\x03\x00\x01x") == expected


@given(extensions(), st.lists(st.integers(0, 600), max_size=8))
def test_a_hello_is_complete_once_its_last_record_is_in(item, cuts):
    handshake = handshake_of(item[1])
    stream = records(handshake, cuts)
    # The record holding the last byte of the message ends the hello.
    end, pos, carried = 0, 0, 0
    while carried < len(handshake):
        (length,) = struct.unpack_from("!H", stream, pos + 3)
        pos, carried = pos + 5 + length, carried + length
        end = pos
    for size in range(len(stream) + 1):
        assert hello_complete(stream[:size]) == (size >= end)
        if size < end:
            assert handshake_message(stream[:size]) is None
            with pytest.raises(MalformedHello):
                parse_client_hello(stream[:size])


@given(st.binary(max_size=300))
def test_arbitrary_data_is_parsed_or_refused(data):
    for stream in (data, b"\x16\x03\x01" + data, records(b"\x01" + data, [7, 50])):
        hello_complete(stream)
        handshake_message(stream)
        try:
            hello = parse_client_hello(stream)
        except MalformedHello:
            assert server_name(stream) is None and alpn_protocols(stream) is None
            continue
        assert server_name(stream) == hello.server_name


@given(extensions(), st.data())
def test_mutated_hellos_are_parsed_consistently_or_refused(item, data):
    handshake = handshake_of(item[1])
    position = data.draw(st.integers(0, len(handshake) - 1), label="position")
    value = data.draw(st.integers(0, 255), label="value")
    mutated = handshake[:position] + bytes([value]) + handshake[position + 1 :]
    cuts = data.draw(st.lists(st.integers(0, len(handshake)), max_size=6), label="cuts")
    try:
        whole = parse_client_hello(records(mutated, []))
    except MalformedHello:
        with pytest.raises(MalformedHello):
            parse_client_hello(records(mutated, cuts))
        return
    # Fragmentation never changes what the gateway reads.
    assert parse_client_hello(records(mutated, cuts)) == whole


@given(extensions(), hostnames, st.data())
def test_a_second_server_name_is_refused(item, other, data):
    expected, block = item
    entry = struct.pack("!BH", 0, len(other)) + other.encode()
    if expected.server_name is None:
        # One extension, two names.
        names = entry * 2
        extra = struct.pack("!HHH", 0, len(names) + 2, len(names)) + names
    else:
        extra = struct.pack("!HHH", 0, len(entry) + 2, len(entry)) + entry
    split = data.draw(st.integers(0, len(block)), label="split")
    # Insert at an extension boundary: walk the block to the first one past split.
    pos = 0
    while pos < split:
        (length,) = struct.unpack_from("!H", block, pos + 2)
        pos += 4 + length
    with pytest.raises(MalformedHello):
        parse_client_hello(records(handshake_of(block[:pos] + extra + block[pos:]), []))


def test_oversized_hellos_are_complete_but_refused():
    padding = struct.pack("!HH", 21, 60000) + b"\0" * 60000
    stream = records(handshake_of(padding, suites=5000), list(range(0, 80000, 16384)))
    assert len(stream) > MAX_HELLO
    assert hello_complete(stream[:MAX_HELLO])
    with pytest.raises(MalformedHello):
        parse_client_hello(stream[:MAX_HELLO])
