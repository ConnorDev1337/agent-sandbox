import gzip
import zlib

import pytest

from agent_sandbox.canary import CanaryMatcher, generate
from agent_sandbox.gateway.decoding import (
    MAX_LAYERS,
    RATIO_FLOOR,
    BodyScanner,
    DecodeError,
    content_codings,
)


@pytest.fixture(scope="module")
def canaries():
    return generate()


@pytest.fixture(scope="module")
def matcher(canaries):
    return CanaryMatcher(canaries)


@pytest.fixture(scope="module")
def secret(canaries):
    return next(c for c in canaries if c.kind == "aws").secrets[1].encode()


def raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


ENCODERS = {
    "gzip": gzip.compress,
    "x-gzip": gzip.compress,
    "deflate": zlib.compress,
}


def encode(data: bytes, codings: list[str]) -> bytes:
    for coding in codings:
        data = ENCODERS[coding](data)
    return data


def run(matcher, body: bytes, codings, size: int = 7, **limits):
    """Feed ``body`` in pieces of ``size`` bytes; return (released bytes, hits)."""
    scanner = BodyScanner(matcher, codings, **limits)
    released = b""
    for start in range(0, len(body), size):
        safe, hits = scanner.feed(body[start : start + size])
        if hits:
            return released, hits
        released += safe
    tail, hits = scanner.finish()
    return released + tail, hits


def test_content_codings_parsing():
    assert content_codings(["gzip"]) == ["gzip"]
    assert content_codings(["Deflate , GZIP", "identity", " br"]) == ["deflate", "gzip", "br"]
    assert content_codings(["", " , identity"]) == []


@pytest.mark.parametrize(
    "codings", [["gzip"], ["x-gzip"], ["deflate"], ["deflate", "gzip"], ["gzip", "gzip", "gzip"]]
)
def test_clean_bodies_pass_through_unchanged(matcher, codings):
    body = encode(b"hello world, nothing to see here " * 200, codings)
    released, hits = run(matcher, body, codings, size=33)
    assert hits == [] and released == body


@pytest.mark.parametrize("codings", [["gzip"], ["deflate"], ["deflate", "gzip"]])
def test_canary_inside_an_encoded_body_is_found(matcher, secret, codings):
    body = encode(b"x" * 5000 + b"key=" + secret + b"&" + b"y" * 5000, codings)
    assert secret not in body
    _, hits = run(matcher, body, codings)
    (hit,) = hits
    assert hit.kind == "aws" and hit.encoding == f"plain in {', '.join(codings)}"


def test_raw_deflate_and_concatenated_gzip_members(matcher, secret):
    body = raw_deflate(b"value=" + secret)
    assert run(matcher, body, ["deflate"])[1][0].encoding == "plain in deflate"
    members = gzip.compress(b"harmless ") + gzip.compress(secret)
    assert run(matcher, members, ["gzip"])[1]
    clean = gzip.compress(b"one") + gzip.compress(b"two")
    assert run(matcher, clean, ["gzip"]) == (clean, [])


def test_released_prefix_never_decodes_to_part_of_a_canary(matcher, secret):
    """A server given only what was released must not be able to decode the canary's start."""
    body = gzip.compress(b"a" * 3000 + bytes(range(256)) * 40 + secret + b"z" * 3000)
    scanner = BodyScanner(matcher, ["gzip"])
    released = b""
    for start in range(0, len(body), 64):
        safe, hits = scanner.feed(body[start : start + 64])
        released += safe
        if hits:
            break
    assert hits
    decoded = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(released)
    assert secret[:12] not in decoded and len(decoded) > 1000


@pytest.mark.parametrize(
    ("body", "codings", "status", "reason"),
    [
        (b"not gzip at all", ["gzip"], 400, "malformed gzip"),
        (gzip.compress(b"data")[:-6], ["gzip"], 400, "truncated gzip"),
        (gzip.compress(b"data") + b"trailing", ["gzip"], 400, "malformed gzip"),
        (zlib.compress(b"data") + b"x", ["deflate"], 400, "after the end"),
        (b"x", ["deflate"], 400, "deflate"),
        (b"\x78\x01\x00\xfe\xff", ["deflate"], 400, "ambiguous"),
        (b"data", ["br"], 415, "unsupported content coding br"),
        (b"data", ["gzip"] * (MAX_LAYERS + 1), 415, "more than"),
    ],
)
def test_undecodable_bodies(matcher, body, codings, status, reason):
    with pytest.raises(DecodeError) as info:
        run(matcher, body, codings)
    assert info.value.status == status and reason in info.value.reason


def test_decompression_bomb_limits(matcher):
    bomb = gzip.compress(b"\0" * (4 * RATIO_FLOOR))
    with pytest.raises(DecodeError, match="ratio"):
        run(matcher, bomb, ["gzip"], size=1024)
    with pytest.raises(DecodeError, match="larger than 1000"):
        run(matcher, gzip.compress(b"a" * 5000), ["gzip"], max_decoded=1000)
    # A layer that expands then shrinks again is bounded too.
    nested = gzip.compress(gzip.compress(b"") * 100_000)
    with pytest.raises(DecodeError, match="ratio"):
        run(matcher, nested, ["gzip", "gzip"], size=4096)


def test_empty_body_and_no_codings(matcher, secret):
    assert BodyScanner(matcher, ["gzip"]).finish() == (b"", [])
    scanner = BodyScanner(matcher)
    assert not scanner.decoding
    assert scanner.feed(b"plain " + secret)[1]


def test_abandon_releases_held_bytes_and_scans_as_sent(matcher, secret):
    body = gzip.compress(b"payload " * 1000)
    scanner = BodyScanner(matcher, ["gzip"])
    released, _ = scanner.feed(body[:100])
    released += scanner.abandon()
    assert not scanner.decoding
    rest, hits = scanner.feed(body[100:])
    tail, _ = scanner.finish()
    assert hits == [] and released + rest + tail == body
    assert scanner.feed(secret)[1]
