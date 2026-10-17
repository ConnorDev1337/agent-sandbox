"""Property-based tests of the strict HTTP/1 request parsing and relaying."""

import asyncio
import contextlib
import itertools
import re

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from agent_sandbox.allowlist import Allowlist
from agent_sandbox.canary import CanaryMatcher, generate
from agent_sandbox.gateway.alerts import EventLog
from agent_sandbox.gateway.http1 import (
    BufferedReader,
    ProxyError,
    Request,
    body_length,
    chunk,
    chunk_size,
    parse_head,
    request_start,
    serialize_head,
)
from agent_sandbox.gateway.proxy import Proxy

TCHAR = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
VCHAR = "".join(map(chr, range(0x21, 0x7F)))
OBS_TEXT = "".join(map(chr, range(0x80, 0x100)))
CTL = "".join(map(chr, [*range(0x20), 0x7F]))

tokens = st.text(TCHAR, min_size=1, max_size=12)
methods = st.one_of(st.sampled_from(["GET", "POST", "PUT", "DELETE", "OPTIONS"]), tokens)
paths = st.text(VCHAR.replace("#", "").replace("?", ""), max_size=30).map(lambda p: "/" + p)
targets = st.one_of(
    paths,
    st.builds(lambda p, q: f"{p}?{q}", paths, st.text(VCHAR.replace("#", ""), max_size=20)),
    paths.map(lambda p: "http://a.example" + p),
    st.just("*"),
)
versions = st.sampled_from(["HTTP/1.0", "HTTP/1.1"])
# Field values: no leading or trailing whitespace, inner SP and HTAB allowed.
field_values = st.one_of(
    st.just(""),
    st.builds(
        lambda first, middle, last: first + middle + last if middle else first,
        st.text(VCHAR + OBS_TEXT, min_size=1, max_size=1),
        st.text(VCHAR + OBS_TEXT + " \t", max_size=20),
        st.text(VCHAR + OBS_TEXT, min_size=1, max_size=1),
    ),
)
headers = st.lists(st.tuples(tokens, field_values), max_size=6)


@st.composite
def requests(draw):
    return Request(draw(methods).upper(), draw(targets), draw(versions), draw(headers), b"")


# ---------------------------------------------------------------------------- parse_head


def head_of(request: Request) -> bytes:
    lines = [f"{request.method} {request.target} {request.version}"]
    lines += [f"{name}: {value}" for name, value in request.headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def parsed_or_refused(raw: bytes) -> Request | None:
    """Parse ``raw``, which must either succeed or raise ProxyError."""
    try:
        return parse_head(raw)
    except ProxyError as exc:
        assert exc.status == 400
        return None


@given(requests())
def test_valid_heads_round_trip(request):
    parsed = parse_head(head_of(request))
    assert (parsed.method, parsed.target, parsed.version) == (
        request.method,
        request.target,
        request.version,
    )
    assert parsed.headers == request.headers
    assert serialize_head(parsed) == head_of(
        Request(
            parsed.method,
            parsed.target,
            parsed.version,
            [(k, v) for k, v in parsed.headers if k.lower() not in PROXY_ONLY],
            b"",
        )
    )


PROXY_ONLY = {"proxy-authorization", "proxy-connection"}


def assert_canonical(request: Request) -> None:
    """What the gateway accepts must be read the same way by any HTTP/1 parser."""
    assert re.fullmatch(f"[{re.escape(TCHAR)}]+", request.method)
    assert request.method == request.method.upper()
    assert re.fullmatch(r"[\x21-\x7e]+", request.target) and "#" not in request.target
    assert request.version in {"HTTP/1.0", "HTTP/1.1"}
    for name, value in request.headers:
        assert re.fullmatch(f"[{re.escape(TCHAR)}]+", name)
        assert not set(value) & set(CTL.replace("\t", ""))
        assert value == value.strip(" \t")


@given(st.binary(max_size=200))
def test_arbitrary_heads_parse_canonically_or_are_refused(data):
    for raw in (data, data + b"\r\n\r\n", b"GET / HTTP/1.1\r\n" + data + b"\r\n\r\n"):
        request = parsed_or_refused(raw)
        if request is not None:
            assert_canonical(request)
            # Serializing what was parsed gives a head that parses to the same request.
            again = parse_head(serialize_head(request))
            assert (again.method, again.target, again.version) == (
                request.method,
                request.target,
                request.version,
            )


@st.composite
def mutated_heads(draw):
    raw = head_of(draw(requests()))
    position = draw(st.integers(0, len(raw) - 4))
    insert = draw(st.text(CTL + OBS_TEXT + VCHAR + " ", min_size=1, max_size=3))
    return raw[:position] + insert.encode("latin-1") + raw[position:]


@given(mutated_heads())
def test_mutated_heads_parse_canonically_or_are_refused(raw):
    request = parsed_or_refused(raw)
    if request is not None:
        assert_canonical(request)


@given(requests(), st.data())
def test_bare_cr_lf_or_nul_in_a_head_is_refused(request, data):
    raw = head_of(request)
    position = data.draw(st.integers(0, len(raw) - 2), label="position")
    char = data.draw(st.sampled_from([b"\r", b"\n", b"\0"]), label="char")
    with pytest.raises(ProxyError):
        parse_head(raw[:position] + char + raw[position:])


@given(requests(), tokens, field_values, st.sampled_from([" ", "\t"]))
def test_folded_headers_are_refused(request, name, value, fold):
    lines = head_of(request)[:-2] + f"{name}: x\r\n{fold}{value}\r\n\r\n".encode("latin-1")
    with pytest.raises(ProxyError):
        parse_head(lines)


@given(requests(), tokens, st.text(" \t", min_size=1, max_size=3), field_values)
def test_whitespace_before_a_colon_is_refused(request, name, space, value):
    raw = head_of(request)[:-2] + f"{name}{space}: {value}\r\n\r\n".encode("latin-1")
    with pytest.raises(ProxyError):
        parse_head(raw)


@given(requests(), requests())
def test_a_head_holds_exactly_one_request(first, second):
    # An empty line ends the head; anything after it is not part of this request.
    with pytest.raises(ProxyError):
        parse_head(head_of(first) + head_of(second))


# ---------------------------------------------------------------------------- body framing

LENGTH_VALUES = st.one_of(
    st.integers(0, 10**18).map(str),
    st.sampled_from(["", "+5", "-1", "0x5", "5 5", "5,5", "1e3", "0" * 19 + "1", "\xb2", "1\xb9"]),
    st.text(VCHAR + OBS_TEXT + CTL.replace("\r", "").replace("\n", "").replace("\0", "")),
)
CODING_VALUES = st.one_of(
    st.sampled_from(["chunked", "Chunked", "CHUNKED", "chunked, chunked", "gzip, chunked"]),
    st.sampled_from(["identity", "x-chunked", "chunked;q=1", "\xa0chunked", "chunked\x0b"]),
    st.text("chunkedCHUNKED ,;\t\x0b\x0c\x1c\x85\xa0", max_size=12),
)


@st.composite
def framed_heads(draw):
    request = draw(requests())
    framing = draw(
        st.lists(
            st.one_of(
                st.tuples(st.sampled_from(["Content-Length", "content-length"]), LENGTH_VALUES),
                st.tuples(
                    st.sampled_from(["Transfer-Encoding", "transfer-encoding"]), CODING_VALUES
                ),
            ),
            max_size=3,
        )
    )
    request.headers += [(name, value.strip(" \t")) for name, value in framing]
    return head_of(request)


@given(framed_heads())
def test_body_framing_is_unambiguous(raw):
    request = parsed_or_refused(raw)
    if request is None:
        return
    try:
        length = body_length(request)
    except ProxyError as exc:
        assert exc.status in {400, 501}
        return
    lengths = request.header_values("content-length")
    codings = request.header_values("transfer-encoding")
    if length is None:
        # Chunked: exactly one Transfer-Encoding naming only chunked, in HTTP/1.1.
        assert not lengths and len(codings) == 1
        assert codings[0].lower() == "chunked"
        assert request.version == "HTTP/1.1"
    else:
        assert not codings
        assert all(re.fullmatch(r"[0-9]{1,18}", value) for value in lengths)
        assert {int(value) for value in lengths} <= {length}


@given(st.integers(0, 2**64 - 1), st.sampled_from(["%x", "%X", "%016x"]), st.data())
def test_chunk_sizes_round_trip(size, form, data):
    extension = data.draw(st.sampled_from(["", ";a=b", ' ;name="v"', "\t;x"]), label="ext")
    line = (form % size + extension + "\r\n").encode()
    assert chunk_size(line) == size


@given(st.binary(max_size=24))
def test_chunk_size_lines_parse_or_are_refused(line):
    try:
        size = chunk_size(line + b"\r\n")
    except ProxyError as exc:
        assert exc.status == 400
        return
    digits = line.split(b";", 1)[0].strip(b" \t")
    assert re.fullmatch(rb"[0-9a-fA-F]{1,16}", digits) and size == int(digits, 16)
    assert b"\r" not in line and b"\n" not in line


@given(st.binary(max_size=8), st.sampled_from([b"\r", b"\n"]), st.binary(max_size=8))
def test_bare_cr_or_lf_in_a_chunk_size_line_is_refused(before, char, after):
    with pytest.raises(ProxyError):
        chunk_size(b"5" + before + char + after + b"\r\n")


@given(st.binary(max_size=100))
def test_chunks_round_trip(data):
    line, _, rest = chunk(data).partition(b"\r\n")
    assert chunk_size(line + b"\r\n") == len(data) and rest == data + b"\r\n"


# ---------------------------------------------------------------------------- request start


@given(methods, targets)
def test_request_start_never_refuses_a_request_line_prefix(method, target):
    line = f"{method} {target} HTTP/1.1\r\n".encode()
    for end in range(1, len(line) + 1):
        assert request_start(line[:end]) is not False
    assert request_start(line) is True


@given(st.one_of(st.binary(min_size=1, max_size=40), st.text(TCHAR + " \t\r\n").map(str.encode)))
def test_request_start_answers_do_not_depend_on_reads(data):
    assume(data)
    answers = [request_start(data[:end]) for end in range(1, len(data) + 1)]
    decided = next((n for n, answer in enumerate(answers) if answer is not None), len(answers))
    assert all(answer is None for answer in answers[:decided])
    assert all(answer is answers[decided] for answer in answers[decided:])


@given(
    st.text(TCHAR, min_size=1, max_size=40),
    st.sampled_from([" ", "\t", "\x0b", "\x0c"]),
    st.text(" \t\r\n", max_size=3),
)
def test_requests_a_lenient_server_could_read_are_parsed(method, space, leading):
    # Whatever is taken for a request is parsed, and refused if not canonical,
    # rather than relayed unread (body decoding would then be skipped).
    line = f"{leading}{method}{space}/ HTTP/1.1\r\n".encode()
    assert request_start(line) is True


# ---------------------------------------------------------------------------- BufferedReader


def pieces_of(data: bytes, cuts: list[int]) -> list[bytes]:
    points = sorted({min(cut, len(data)) for cut in cuts} | {0, len(data)})
    return [data[a:b] for a, b in itertools.pairwise(points) if b > a]


def source_of(pieces: list[bytes]):
    queue = list(pieces)

    async def read() -> bytes:
        return queue.pop(0) if queue else b""

    return read


@given(st.lists(st.binary(max_size=20), max_size=8), st.lists(st.integers(0, 200)))
def test_readuntil_is_independent_of_read_boundaries(records, cuts):
    stream = b"".join(record.replace(b"\r\n", b"") + b"\r\n" for record in records)

    async def main():
        reader = BufferedReader(source_of(pieces_of(stream, cuts)))
        lines = []
        with pytest.raises(asyncio.IncompleteReadError) as info:
            while True:
                lines.append(await reader.readuntil(b"\r\n"))
        assert info.value.partial == b""
        return lines

    lines = asyncio.run(main())
    assert b"".join(lines) == stream
    assert all(line.endswith(b"\r\n") and line.count(b"\r\n") == 1 for line in lines)


@given(st.integers(1, 64), st.lists(st.integers(1, 50), min_size=1, max_size=20))
def test_readuntil_memory_is_bounded(limit, sizes):
    pieces = [b"x" * size for size in sizes]

    async def main():
        reader = BufferedReader(source_of(pieces), limit=limit)
        with pytest.raises((asyncio.LimitOverrunError, asyncio.IncompleteReadError)):
            await reader.readuntil(b"\r\n\r\n")
        return len(reader._buffer)

    # The buffer never grows past the limit by more than one read.
    assert asyncio.run(main()) <= limit + max(sizes)


@given(st.binary(max_size=200), st.lists(st.integers(0, 200)), st.lists(st.integers(0, 50)))
def test_readexactly_and_read_return_the_stream_in_order(data, cuts, sizes):
    async def main():
        reader = BufferedReader(source_of(pieces_of(data, cuts)))
        out = b""
        for size in sizes:
            part = await reader.read(size)
            assert len(part) <= size
            out += part
            more = await reader.readexactly(min(size, len(data) - len(out)))
            out += more
        return out

    out = asyncio.run(main())
    assert data.startswith(out)


# ---------------------------------------------------------------------------- relaying

HOST, PORT = "relay.example", 80
ALLOW = Allowlist(
    [{"host": HOST, "methods": ["GET", "POST", "PUT"], "paths": ["/ok/*", "/*/upload"]}]
)
MATCHER = CanaryMatcher(generate())


class Recorder(EventLog):
    def __init__(self) -> None:
        super().__init__(None, stream=None)
        self.events: list[dict] = []

    def event(self, kind, **fields):
        self.events.append({"kind": kind, **fields})
        return fields

    def alert(self, kind, severity, message, **fields):
        return self.event(kind, **fields)


class Sink:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        pass

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        pass

    def close(self) -> None:
        pass


def strict_requests(stream: bytes) -> list[tuple[str, str, bytes]]:
    """Parse what the gateway sent upstream with a minimal, strict HTTP/1.1 parser.

    Every framing decision must be one that no HTTP/1 implementation makes
    differently: canonical request lines and fields, a single all-digit
    ``Content-Length`` or exactly ``Transfer-Encoding: chunked``.
    """
    found = []
    pos = 0
    while pos < len(stream):
        end = stream.index(b"\r\n\r\n", pos)
        lines = stream[pos:end].decode("latin-1").split("\r\n")
        pos = end + 4
        method, target, version = lines[0].split(" ")
        assert re.fullmatch(r"[\x21-\x7e]+", target) and version in {"HTTP/1.0", "HTTP/1.1"}
        fields: dict[str, list[str]] = {}
        for line in lines[1:]:
            name, value = line.split(": ", 1) if ": " in line else line.split(":", 1)
            assert re.fullmatch(f"[{re.escape(TCHAR)}]+", name)
            assert not set(value) & set(CTL.replace("\t", "")) and value == value.strip(" \t")
            fields.setdefault(name.lower(), []).append(value)
        lengths, codings = fields.get("content-length", []), fields.get("transfer-encoding", [])
        assert not (lengths and codings)
        if codings:
            assert len(codings) == 1 and codings[0].lower() == "chunked"
            body = b""
            while True:
                line_end = stream.index(b"\r\n", pos)
                size_line = stream[pos:line_end]
                assert re.fullmatch(rb"[0-9a-f]+", size_line)
                size = int(size_line, 16)
                pos = line_end + 2
                if size == 0:
                    assert stream[pos : pos + 2] == b"\r\n"
                    pos += 2
                    break
                body += stream[pos : pos + size]
                assert stream[pos + size : pos + size + 2] == b"\r\n"
                pos += size + 2
        else:
            assert len(set(lengths)) <= 1 and all(re.fullmatch(r"[0-9]+", v) for v in lengths)
            size = int(lengths[0]) if lengths else 0
            body = stream[pos : pos + size]
            assert len(body) == size
            pos += size
        found.append((method, target, body))
    return found


def relay(stream: bytes, cuts: list[int]) -> tuple[list[tuple[str, str, bytes]], list[dict]]:
    """Relay a client byte stream like a plaintext tunnel; return what reached upstream."""
    log = Recorder()
    proxy = Proxy(ALLOW, MATCHER, log)
    upstream, client = Sink(), Sink()

    async def main():
        source = BufferedReader(source_of(pieces_of(stream, cuts)))
        with contextlib.suppress(
            ProxyError, asyncio.IncompleteReadError, asyncio.LimitOverrunError
        ):
            await proxy._relay_requests(source, client, upstream, HOST, PORT, "c", tls=False)

    asyncio.run(main())
    sent = strict_requests(bytes(upstream.data))
    return sent, [e for e in log.events if e["kind"] == "egress.request"]


ALLOWED_PATHS = st.sampled_from(["/ok/a", "/ok/b?q=1", "/x/upload", "/ok/"])
ANY_PATHS = st.one_of(ALLOWED_PATHS, st.sampled_from(["/no", "/ok", "/a/b/upload/x", "/"]))


@st.composite
def bodies(draw, chunked: bool):
    body = draw(st.binary(max_size=40))
    if not chunked:
        return body, body
    sizes = draw(st.lists(st.integers(1, 10), max_size=6))
    chunks, rest = [], body
    for size in sizes:
        chunks.append(rest[:size])
        rest = rest[size:]
    chunks.append(rest)
    return body, b"".join(chunk(part) for part in chunks if part) + b"0\r\n\r\n"


@st.composite
def valid_requests(draw):
    method = draw(st.sampled_from(["GET", "POST", "PUT"]))
    path = draw(ALLOWED_PATHS)
    chunked = draw(st.booleans())
    body, wire = draw(bodies(chunked))
    framing = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {len(wire)}"
    head = f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n{framing}\r\n\r\n".encode()
    return (method, path, body), head + wire


@given(st.lists(valid_requests(), min_size=1, max_size=4), st.lists(st.integers(0, 600)))
def test_valid_requests_are_relayed_whatever_the_reads(items, cuts):
    stream = b"".join(wire for _, wire in items)
    sent, events = relay(stream, cuts)
    assert [(m, t, b) for m, t, b in sent] == [request for request, _ in items]
    assert [(e["method"], e["path"]) for e in events] == [
        (m, p.split("?")[0]) for (m, p, _), _ in items
    ]


FRAMINGS = st.one_of(
    st.tuples(st.just("Content-Length"), LENGTH_VALUES),
    st.tuples(st.just("Transfer-Encoding"), CODING_VALUES),
)
CHUNK_LINES = st.one_of(
    st.sampled_from(["5", "05", "5;x=y", "5 ", " 5", "0x5", "+5", "5\n", "5\r", "-0"]),
    st.text("0123456789abcdefABCDEF ;=\t\r\n", max_size=6),
)


@st.composite
def hostile_requests(draw):
    method = draw(st.sampled_from(["GET", "POST", "PUT", "DELETE"]))
    path = draw(ANY_PATHS)
    framing = draw(st.lists(FRAMINGS, max_size=3))
    lines = [f"{method} {path} {draw(versions)}", f"Host: {HOST}"]
    lines += [f"{name}: {value}" for name, value in framing]
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    body = b""
    for _ in range(draw(st.integers(0, 3))):
        size_line = draw(CHUNK_LINES).encode("latin-1")
        body += size_line + b"\r\n" + draw(st.binary(max_size=8)) + b"\r\n"
    body += draw(st.sampled_from([b"", b"0\r\n\r\n", b"0\r\nX: 1\r\n\r\n"]))
    return head + body


@st.composite
def hostile_streams(draw):
    parts = draw(
        st.lists(
            st.one_of(valid_requests().map(lambda item: item[1]), hostile_requests()),
            min_size=1,
            max_size=4,
        )
    )
    stream = b"".join(parts)
    if draw(st.booleans()):
        position = draw(st.integers(0, len(stream)))
        stream = stream[:position] + draw(st.binary(min_size=1, max_size=4)) + stream[position:]
    return stream


@given(hostile_streams(), st.lists(st.integers(0, 600), max_size=6))
def test_upstream_only_sees_requests_the_gateway_checked(stream, cuts):
    sent, events = relay(stream, cuts)
    # Each request upstream was checked, in order, and is framed unambiguously
    # (checked by strict_requests); nothing else reached the server.
    assert [(m, t.split("?")[0]) for m, t, _ in sent] == [(e["method"], e["path"]) for e in events]
    assert all(ALLOW.permits(HOST, PORT, m, t.split("?")[0]) for m, t, _ in sent)


@given(hostile_streams())
def test_relaying_does_not_depend_on_read_boundaries(stream):
    whole = relay(stream, [])
    assume(whole[0])
    assert relay(stream, list(range(0, len(stream), 3))) == whole
