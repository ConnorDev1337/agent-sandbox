import asyncio

import pytest

from agent_sandbox.gateway.http1 import (
    BufferedReader,
    ProxyError,
    body_length,
    chunk,
    chunk_size,
    parse_head,
    request_start,
    serialize_head,
)


def head(*lines: str) -> bytes:
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def test_parse_head_accepts_well_formed_requests():
    request = parse_head(head("post /x?y=1 HTTP/1.1", "Host: a.example", "X-Empty:", "A:  b \t"))
    assert (request.method, request.target, request.version) == ("POST", "/x?y=1", "HTTP/1.1")
    assert request.header("host") == "a.example" and request.header("a") == "b"
    assert request.header_values("x-empty") == [""]


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nA: b\nContent-Length: 5\r\n\r\n",
        b"GET / HTTP/1.1\r\nA: b\rC: d\r\n\r\n",
        b"GET / HTTP/1.1\r\nA: b\0\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
        b"GET / HTTP/1.1\r\n folded: x\r\n\r\n",
        b"GET / HTTP/2.0\r\n\r\n",
        b"GET  / HTTP/1.1\r\n\r\n",
        b"G(T / HTTP/1.1\r\n\r\n",
        b"GET /\r\n\r\n",
        # Found by tests/test_fuzz_http1.py: targets servers may read differently,
        # control characters in values, and a second request after the empty line.
        b"GET #/ HTTP/1.0\r\n\r\n",
        b"GET /a\tb HTTP/1.1\r\n\r\n",
        b"GET /a\x0bb HTTP/1.1\r\n\r\n",
        b"GET /..\xc0\xafx HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\x0b\r\n\r\n",
        b"GET / HTTP/1.1\r\nA: \x7f\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\nHost: evil.example\r\n\r\n",
    ],
)
def test_parse_head_refuses_ambiguous_heads(raw):
    with pytest.raises(ProxyError) as info:
        parse_head(raw)
    assert info.value.status == 400


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ((), 0),
        (("Content-Length: 12",), 12),
        (("Content-Length: 12", "content-length: 12"), 12),
        (("Transfer-Encoding: Chunked",), None),
    ],
)
def test_body_length(headers, expected):
    assert body_length(parse_head(head("POST / HTTP/1.1", *headers))) == expected


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        (("Content-Length: 1", "Transfer-Encoding: chunked"), 400),
        (("Transfer-Encoding: gzip, chunked",), 501),
        (("Transfer-Encoding: chunked", "Transfer-Encoding: chunked"), 501),
        (("Content-Length: 1", "Content-Length: 2"), 400),
        (("Content-Length: 1, 1",), 400),
        (("Content-Length: -1",), 400),
        (("Content-Length: 1234567890123456789",), 400),
        # Found by tests/test_fuzz_http1.py: str.isdigit() accepts superscripts,
        # which int() refuses, and str.strip() removes more than SP and HTAB, so
        # a coding a server may not take for chunked was forwarded as is.
        (("Content-Length: \xb2",), 400),
        (("Content-Length: 5\xa0",), 400),
        (("Transfer-Encoding: \xa0chunked",), 501),
        (("Transfer-Encoding: chunked\x85",), 501),
    ],
)
def test_body_length_refuses_ambiguous_framing(headers, status):
    with pytest.raises(ProxyError) as info:
        body_length(parse_head(head("POST / HTTP/1.1", *headers)))
    assert info.value.status == status


def test_transfer_encoding_in_http_1_0_is_refused():
    # Found by tests/test_fuzz_http1.py: such framing is faulty (RFC 9112, 6.1).
    with pytest.raises(ProxyError) as info:
        body_length(parse_head(head("POST / HTTP/1.0", "Transfer-Encoding: chunked")))
    assert info.value.status == 400


def test_chunk_helpers():
    assert chunk_size(b"1a\r\n") == 26
    assert chunk_size(b"A;name=value\r\n") == 10
    bad_lines = (b"0x10\r\n", b"1_0\r\n", b"+5\r\n", b"\r\n", b"12345678901234567\r\n")
    # Found by tests/test_fuzz_http1.py: bare CR or LF before the CRLF.
    for bad in (*bad_lines, b"0\r\r\n", b"5\n\r\n", b"5;a\nb\r\n"):
        with pytest.raises(ProxyError):
            chunk_size(bad)
    assert chunk(b"hello") == b"5\r\nhello\r\n"


def test_serialize_head_drops_proxy_headers():
    request = parse_head(
        head("GET / HTTP/1.1", "Host: a.example", "Proxy-Authorization: x", "Proxy-Connection: y")
    )
    assert serialize_head(request) == head("GET / HTTP/1.1", "Host: a.example")


def _reader(*pieces: bytes, initial: bytes = b"", limit: int = 64) -> BufferedReader:
    queue = list(pieces)

    async def source() -> bytes:
        return queue.pop(0) if queue else b""

    return BufferedReader(source, initial, limit=limit)


def test_buffered_reader_reads_across_pieces():
    async def scenario():
        reader = _reader(b"llo\r", b"\nwor", b"ld!", initial=b"he")
        assert await reader.readuntil(b"\r\n") == b"hello\r\n"
        assert await reader.readexactly(4) == b"worl"
        assert await reader.read(10) == b"d!"
        assert await reader.read(10) == b""
        with pytest.raises(asyncio.IncompleteReadError) as info:
            await reader.readexactly(1)
        assert info.value.partial == b""

    asyncio.run(scenario())


def test_buffered_reader_limits_and_partial_reads():
    async def scenario():
        with pytest.raises(asyncio.LimitOverrunError):
            await _reader(b"x" * 100, limit=64).readuntil(b"\r\n\r\n")
        with pytest.raises(asyncio.IncompleteReadError) as info:
            await _reader(b"GET / HT").readuntil(b"\r\n\r\n")
        assert info.value.partial == b"GET / HT"
        with pytest.raises(asyncio.IncompleteReadError) as info:
            await _reader(b"abc").readexactly(5)
        assert info.value.partial == b"abc"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"GET / HTTP/1.1", True),
        (b"M-SEARCH * HTTP/1.1", True),
        (b"DEL", None),
        (b"", False),
        (b"SSH-2.0-OpenSSH_9.6\r\n", False),
        (b"SSH-2.0-OpenSSH_9.6", None),
        (b"\x16\x03\x01", False),
        # Found by tests/test_fuzz_http1.py: requests lenient servers accept were
        # relayed unparsed (so undecoded), and the answer for a long method
        # depended on the reads (False for 24 bytes, True for 25 and a space).
        (b"X" * 30, None),
        (b"X" * 30 + b" / HTTP/1.1", True),
        (b"\r\nPOST / HTTP/1.1", True),
        (b" POST / HTTP/1.1", True),
        (b"POST\t/ HTTP/1.1", True),
    ],
)
def test_request_start(data, expected):
    assert request_start(data) is expected
