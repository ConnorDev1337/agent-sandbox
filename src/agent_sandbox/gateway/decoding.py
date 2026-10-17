"""Content-Encoding decoding of request bodies for canary scanning.

A canary inside a gzip or deflate body does not appear in the bytes as sent,
so a body with a ``Content-Encoding`` is also decoded, as a stream, and the
decoded bytes are scanned too. Decoding is bounded: output is produced in
small pieces and stops at an absolute size and at a compression ratio, so a
decompression bomb costs the gateway little memory and CPU.

Only codings the standard library can decode are supported (``gzip``,
``x-gzip`` and ``deflate``, stacked up to three times). Anything else, and any
body that cannot be decoded completely, raises :class:`DecodeError`; the
proxy then refuses the request or forwards it scanned as sent, by policy.
"""

from __future__ import annotations

import zlib
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import replace

from ..canary import CanaryHit, CanaryMatcher, StreamScanner

GZIP, DEFLATE = "gzip", "deflate"
CODINGS = {"gzip": GZIP, "x-gzip": GZIP, "deflate": DEFLATE}
MAX_LAYERS = 3
MAX_DECODED = 64 * 1024 * 1024  # decoded bytes per body, at every layer
MAX_RATIO = 100  # decoded bytes per byte sent, enforced past RATIO_FLOOR
RATIO_FLOOR = 1024 * 1024
STEP = 64 * 1024  # largest piece of output produced at once
_GZIP_WBITS = 16 + zlib.MAX_WBITS
_DEFLATE_PROBE = 5  # bytes needed to tell zlib-wrapped from raw deflate


class DecodeError(Exception):
    """A body cannot be decoded completely; ``status`` is the HTTP status to refuse it with."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def content_codings(values: Iterable[str]) -> list[str]:
    """Return the codings named by ``Content-Encoding`` field values, in the order applied."""
    codings = []
    for value in values:
        for item in value.split(","):
            name = item.strip().lower()
            if name and name != "identity":
                codings.append(name)
    return codings


def _zlib_header(head: bytes) -> bool:
    """Return True if ``head`` starts with a valid zlib header (RFC 1950)."""
    cmf, flg = head[0], head[1]
    return cmf & 0x0F == 8 and cmf >> 4 <= 7 and ((cmf << 8) | flg) % 31 == 0


class _Layer:
    """One gzip or deflate layer, decoded incrementally with bounded output."""

    def __init__(self, coding: str) -> None:
        self.coding = coding
        self._head = b""
        self._decoder = zlib.decompressobj(_GZIP_WBITS) if coding == GZIP else None

    def _deflate_decoder(self, head: bytes) -> zlib._Decompress:
        """Choose between zlib-wrapped and raw deflate, as servers disagree on ``deflate``.

        Read as raw deflate, a valid zlib header always starts a stored block,
        whose length check fails at once unless the stream was crafted to be
        valid both ways. Such a stream is refused, so at most one reading can
        produce any output, and that is the one scanned.
        """
        if len(head) >= 2 and _zlib_header(head):
            length, check = head[1:3], head[3:5]
            if (
                len(check) == 2
                and int.from_bytes(length, "little") ^ int.from_bytes(check, "little") == 0xFFFF
            ):
                raise DecodeError(400, "ambiguous deflate body (valid with and without zlib)")
            return zlib.decompressobj(zlib.MAX_WBITS)
        return zlib.decompressobj(-zlib.MAX_WBITS)

    def feed(self, data: bytes) -> Iterator[bytes]:
        if self._decoder is None:
            self._head += data
            if len(self._head) < _DEFLATE_PROBE:
                return
            data, self._head = self._head, b""
            self._decoder = self._deflate_decoder(data)
        yield from self._inflate(data)

    def finish(self) -> Iterator[bytes]:
        if self._decoder is None:
            data, self._head = self._head, b""
            self._decoder = self._deflate_decoder(data)
            yield from self._inflate(data)
        yield from self._inflate(b"")  # Output still pending inside the decoder
        if not self._decoder.eof:
            raise DecodeError(400, f"truncated {self.coding} body")

    def _inflate(self, data: bytes) -> Iterator[bytes]:
        decoder = self._decoder  # Always set before data is inflated
        while True:
            try:
                out = decoder.decompress(data, STEP)
            except zlib.error:
                raise DecodeError(400, f"malformed {self.coding} body") from None
            if out:
                yield out
            if decoder.eof:
                data = decoder.unused_data
                if not data:
                    return
                if self.coding != GZIP:
                    raise DecodeError(400, "data after the end of the deflate body")
                # Concatenated gzip members decode as one body (RFC 1952).
                decoder = self._decoder = zlib.decompressobj(_GZIP_WBITS)
                continue
            data = decoder.unconsumed_tail
            if not data and len(out) < STEP:
                return


class BodyScanner:
    """Scan a request body as sent and, when it is content-encoded, as decoded.

    ``feed`` returns the part of the body proven canary-free. For an encoded
    body a byte is released only once everything a server could decode from
    the body up to that byte has been scanned too, so a body cut short (a large
    streamed upload refused half-way) never hands the server part of a canary.
    """

    def __init__(
        self,
        matcher: CanaryMatcher,
        codings: Iterable[str] = (),
        *,
        max_decoded: int = MAX_DECODED,
        max_ratio: int = MAX_RATIO,
    ) -> None:
        codings = list(codings)
        if len(codings) > MAX_LAYERS:
            raise DecodeError(415, f"more than {MAX_LAYERS} content codings")
        unsupported = [c for c in codings if c not in CODINGS]
        if unsupported:
            raise DecodeError(415, f"unsupported content coding {unsupported[0]}")
        self.encoding = ", ".join(codings)
        self.max_decoded = max_decoded
        self.max_ratio = max_ratio
        self._raw = StreamScanner(matcher)
        self._decoded = StreamScanner(matcher)
        # Decoding undoes the last coding applied first.
        self._layers = [_Layer(CODINGS[c]) for c in reversed(codings)]
        self._produced = [0] * len(self._layers)
        self._held = bytearray()  # clean as sent, waiting for the decoded scan
        self._held_end = 0  # body offset just past the held bytes
        self._fed = 0
        self._released = 0  # decoded bytes proven clean
        self._clean_end = 0  # body offset up to which every decodable byte is clean
        self._checkpoints: deque[tuple[int, int]] = deque()  # (body offset, decoded size)

    @property
    def decoding(self) -> bool:
        return bool(self._layers)

    def feed(self, data: bytes) -> tuple[bytes, list[CanaryHit]]:
        """Return the bytes that are safe to forward, or the canaries found."""
        safe, hits = self._raw.feed(data)
        if hits or not self._layers:
            return safe, hits
        self._held += safe
        self._held_end += len(safe)
        self._fed += len(data)
        hits = self._scan(self._pipeline(0, [data], final=False))
        if hits:
            return b"", hits
        self._checkpoints.append((self._fed, self._produced[-1]))
        return self._release(), []

    def finish(self) -> tuple[bytes, list[CanaryHit]]:
        """Scan the end of the body; return the rest of it, or the canaries found."""
        tail = self._raw.flush()
        if not self._layers:
            return tail, []
        self._held += tail  # Kept for abandon() if decoding fails below
        self._held_end += len(tail)
        if self._fed:  # An empty body has nothing to decode.
            hits = self._scan(self._pipeline(0, [], final=True))
            if hits:
                return b"", hits
        self._decoded.flush()
        data, self._held = bytes(self._held), bytearray()
        return data, []

    def abandon(self) -> bytes:
        """Stop decoding (the body is then only scanned as sent); return the held bytes."""
        self._layers = []
        data, self._held = bytes(self._held), bytearray()
        return data

    def _scan(self, pieces: Iterator[bytes]) -> list[CanaryHit]:
        for piece in pieces:
            safe, hits = self._decoded.feed(piece)
            if hits:
                return [replace(h, encoding=f"{h.encoding} in {self.encoding}") for h in hits]
            self._released += len(safe)
        return []

    def _pipeline(self, index: int, pieces: Iterable[bytes], *, final: bool) -> Iterator[bytes]:
        """Pass ``pieces`` through the layers from ``index`` on; yield the decoded output."""
        if index == len(self._layers):
            yield from pieces
            return
        layer = self._layers[index]

        def output() -> Iterator[bytes]:
            for piece in pieces:
                yield from layer.feed(piece)
            if final:
                yield from layer.finish()

        yield from self._pipeline(index + 1, self._bounded(index, output()), final=final)

    def _bounded(self, index: int, pieces: Iterator[bytes]) -> Iterator[bytes]:
        for piece in pieces:
            self._produced[index] += len(piece)
            produced = self._produced[index]
            if produced > self.max_decoded:
                raise DecodeError(413, f"decoded body larger than {self.max_decoded} bytes")
            if produced > RATIO_FLOOR and produced > self.max_ratio * self._fed:
                raise DecodeError(413, f"compression ratio above {self.max_ratio}:1")
            yield piece

    def _release(self) -> bytes:
        while self._checkpoints and self._checkpoints[0][1] <= self._released:
            self._clean_end = self._checkpoints.popleft()[0]
        count = min(self._clean_end, self._held_end) - (self._held_end - len(self._held))
        if count <= 0:
            return b""
        data = bytes(self._held[:count])
        del self._held[:count]
        return data
