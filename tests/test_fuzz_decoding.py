"""Property-based tests of streamed Content-Encoding decoding and scanning."""

import base64
import gzip
import itertools
import zlib
from urllib.parse import quote

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_sandbox.canary import CanaryMatcher, encodings, generate
from agent_sandbox.gateway.decoding import STEP, BodyScanner, DecodeError, _Layer

CANARIES = generate()
MATCHER = CanaryMatcher(CANARIES)
SECRETS = [(canary, value) for canary in CANARIES for value in canary.secrets]
# Encodings an agent might apply before compressing; whitespace-free, so the
# position of the value in the decoded body is known.
FORMS = {
    "plain": lambda data: data,
    "url": lambda data: quote(data.decode("latin-1"), safe="").encode(),
    "hex": lambda data: data.hex().encode(),
    "base64": base64.b64encode,
    "base32": base64.b32encode,
}
TEXT = st.binary(max_size=300).map(lambda b: b.hex().encode())  # No whitespace, no "%"


def gzip_encode(data: bytes, level: int) -> bytes:
    return gzip.compress(data, compresslevel=level, mtime=0)


def zlib_encode(data: bytes, level: int) -> bytes:
    return zlib.compress(data, level)


def raw_encode(data: bytes, level: int) -> bytes:
    compressor = zlib.compressobj(level, wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


# Content coding name, encoder, and the window bits to read it back leniently.
LAYERS = {
    "gzip": ("gzip", gzip_encode, 16 + zlib.MAX_WBITS),
    "x-gzip": ("x-gzip", gzip_encode, 16 + zlib.MAX_WBITS),
    "deflate": ("deflate", zlib_encode, zlib.MAX_WBITS),
    "raw deflate": ("deflate", raw_encode, -zlib.MAX_WBITS),
}
stacks = st.lists(st.sampled_from(sorted(LAYERS)), min_size=1, max_size=3)
levels = st.integers(0, 9)


def encode(data: bytes, stack: list[str], level: int) -> tuple[bytes, list[str]]:
    """Apply ``stack`` in order; return the body and its Content-Encoding codings."""
    for layer in stack:
        data = LAYERS[layer][1](data, level)
    return data, [LAYERS[layer][0] for layer in stack]


def lenient_decode(data: bytes, stack: list[str]) -> bytes:
    """What a server decodes from a (possibly truncated) body, ignoring errors."""
    for layer in reversed(stack):
        decoder = zlib.decompressobj(LAYERS[layer][2])
        try:
            data = decoder.decompress(data)
        except zlib.error:
            data = b""
    return data


def pieces(data: bytes, cuts: list[int]) -> list[bytes]:
    points = sorted({min(c, len(data)) for c in cuts} | {0, len(data)})
    return [data[a:b] for a, b in itertools.pairwise(points)]


def scan(body: bytes, codings: list[str], cuts: list[int], **limits):
    """Feed ``body`` cut at ``cuts``; return (bytes released before any hit, hits)."""
    scanner = BodyScanner(MATCHER, codings, **limits)
    released = b""
    for piece in pieces(body, cuts):
        safe, hits = scanner.feed(piece)
        if hits:
            return released, hits
        released += safe
    tail, hits = scanner.finish()
    return (released if hits else released + tail), hits


@given(st.binary(max_size=3000), st.sampled_from(sorted(LAYERS)), levels, st.data())
def test_layers_round_trip_whatever_the_pieces(data, layer, level, draw):
    body = LAYERS[layer][1](data, level)
    if layer in {"gzip", "x-gzip"} and draw.draw(st.booleans(), label="members"):
        body += gzip_encode(data[::-1], level)  # Concatenated members decode as one body
        data += data[::-1]
    decoder = _Layer(LAYERS[layer][0].replace("x-", ""))
    cuts = draw.draw(st.lists(st.integers(0, len(body))), label="cuts")
    out = [piece for p in pieces(body, cuts) for piece in decoder.feed(p)]
    out += decoder.finish()
    assert b"".join(out) == data
    assert all(len(piece) <= STEP for piece in out)


@given(TEXT, stacks, levels, st.lists(st.integers(0, 3000)))
def test_clean_bodies_are_released_unchanged(text, stack, level, cuts):
    body, codings = encode(text, stack, level)
    assert scan(body, codings, cuts) == (body, [])


@given(
    st.sampled_from(SECRETS),
    st.sampled_from(sorted(FORMS)),
    TEXT,
    TEXT,
    stacks,
    levels,
    st.lists(st.integers(0, 3000)),
)
def test_compressed_canaries_are_never_released(secret, form, before, after, stack, level, cuts):
    canary, value = secret
    plain = before + b"=" + FORMS[form](value.encode()) + b"&" + after
    body, codings = encode(plain, stack, level)
    released, hits = scan(body, codings, cuts)
    assert canary.id in {hit.canary_id for hit in hits}
    # A server given the released bytes decodes nothing past the start of the
    # first encoded occurrence of the value.
    needles = {n.encode() for found in encodings(value).values() for n in found}
    start = min(plain.lower().find(n) for n in needles if n in plain.lower())
    assert len(lenient_decode(released, stack)) <= start


@given(TEXT, stacks, levels, st.lists(st.integers(0, 3000)), st.lists(st.integers(0, 3000)))
def test_results_do_not_depend_on_the_pieces(text, stack, level, cuts, other):
    body, codings = encode(text + CANARIES[2].secrets[0].encode() + text, stack, level)
    first, second = scan(body, codings, cuts)[1], scan(body, codings, other)[1]
    assert {h.canary_id for h in first} == {h.canary_id for h in second} != set()


@given(st.binary(min_size=1, max_size=400), stacks, st.lists(st.integers(0, 400)))
def test_malformed_bodies_are_refused_cleanly(data, stack, cuts):
    codings = [LAYERS[layer][0] for layer in stack]
    try:
        scan(data, codings, cuts)
    except DecodeError as exc:
        assert exc.status == 400


@given(st.binary(min_size=1, max_size=2000), stacks, levels, st.data())
def test_truncated_bodies_are_refused(text, stack, level, data):
    body, codings = encode(text, stack, level)
    end = data.draw(st.integers(0, len(body) - 1), label="end")
    try:
        released, hits = scan(body[:end], codings, [7, 300])
    except DecodeError as exc:
        assert exc.status == 400
    else:
        # Only possible when the cut body is itself complete (stored blocks...).
        assert hits == [] and lenient_decode(released, stack) == lenient_decode(body[:end], stack)


@given(st.integers(1, 5000), st.integers(0, 5000), stacks, st.lists(st.integers(0, 6000)))
def test_decoded_size_limit_is_enforced(limit, size, stack, cuts):
    body, codings = encode(b"a" * size, stack, 6)
    try:
        scan(body, codings, cuts, max_decoded=limit)
    except DecodeError as exc:
        assert exc.status == 413 and (size > limit or len(stack) > 1)
    else:
        assert size <= limit


# Each example decodes megabytes: a few are enough, the pieces barely matter.
@settings(max_examples=max(3, settings.default.max_examples // 400))
@pytest.mark.parametrize("stack", [["gzip"], ["raw deflate"], ["gzip", "deflate"]])
@given(cuts=st.lists(st.integers(0, 50_000), max_size=4))
def test_bombs_are_refused_by_ratio(stack, cuts):
    body, codings = encode(b"\0" * (3 * 1024 * 1024), stack, 9)
    with pytest.raises(DecodeError, match="ratio"):
        scan(body, codings, cuts)


@given(st.integers(0, 255), st.binary(min_size=3, max_size=40))
def test_deflate_is_read_one_way_only(flags, rest):
    # A body with a zlib header is read zlib-wrapped; one that a raw-deflate
    # reader could also decode output from is refused as ambiguous.
    body = bytes([0x78, flags]) + rest
    raw = zlib.decompressobj(-zlib.MAX_WBITS)
    try:
        raw_output = raw.decompress(body)
    except zlib.error:
        raw_output = b""
    try:
        scan(body, ["deflate"], [])
    except DecodeError as exc:
        if raw_output and (0x7800 | flags) % 31 == 0:
            assert "ambiguous" in exc.reason
        return
    assert not raw_output or (0x7800 | flags) % 31
