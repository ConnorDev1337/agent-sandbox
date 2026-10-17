"""Property-based tests of canary matching and of the stream scanner."""

import base64
import itertools
from urllib.parse import quote

from hypothesis import given, settings
from hypothesis import strategies as st

from agent_sandbox.canary import CanaryMatcher, StreamScanner, generate

CANARIES = generate()
MATCHER = CanaryMatcher(CANARIES)
SECRETS = [(canary, value) for canary in CANARIES for value in canary.secrets]
HOSTS = [(canary, host) for canary in CANARIES for host in canary.hosts]
MORE = settings(max_examples=3 * settings.default.max_examples)


def wrap(text: str, width: int, breaks: list[str]) -> str:
    lines = [text[i : i + width] for i in range(0, len(text), width)]
    return "".join(line + breaks[n % len(breaks)] for n, line in enumerate(lines))


# How an agent might send a value: encoded at any byte alignment (among other
# bytes), then wrapped, padded with whitespace, partially or fully
# percent-encoded or with its case changed, possibly several of these.
ENCODERS = {
    "plain": lambda raw: raw.decode("latin-1"),
    "url": lambda raw: quote(raw.decode("latin-1"), safe=""),
    "hex": lambda raw: raw.hex(),
    "base64": lambda raw: base64.b64encode(raw).decode(),
    "base64url": lambda raw: base64.urlsafe_b64encode(raw).decode(),
    "base32": lambda raw: base64.b32encode(raw).decode(),
}
BREAKS = ["\n", "\r\n", " ", "\t", "=\r\n", "=\n"]
filler = st.binary(max_size=300).map(lambda b: b.hex()[: len(b)])


@st.composite
def restyled(draw, text: str, style: str) -> str:
    flags = draw(st.lists(st.booleans(), min_size=len(text), max_size=len(text)))
    if style == "wrapped":
        breaks = draw(st.lists(st.sampled_from(BREAKS), min_size=1, max_size=3))
        return wrap(text, draw(st.integers(4, 80)), breaks)
    if style == "padded":  # Whitespace between some characters
        gaps = draw(st.lists(st.sampled_from(BREAKS[:4]), min_size=1, max_size=4))
        return "".join(
            c + (gaps[n % len(gaps)] if f else "")
            for n, (c, f) in enumerate(zip(text, flags, strict=True))
        )
    if style in {"percent", "all percent"}:
        return "".join(
            f"%{ord(c):02X}" if f or style == "all percent" else c
            for c, f in zip(text, flags, strict=True)
        )
    return "".join(c.upper() if f else c.lower() for c, f in zip(text, flags, strict=True))


@st.composite
def sent_values(draw):
    """A canary value as an agent could send it, and the canary it belongs to."""
    canary, value = draw(st.sampled_from(SECRETS))
    encoder = draw(st.sampled_from(sorted(ENCODERS)))
    before = draw(st.binary(max_size=8)) if encoder != "plain" else b""
    text = ENCODERS[encoder](before + value.encode() + draw(st.binary(max_size=8)))
    styles = ["wrapped", "padded", "percent", "all percent", "case"]
    percent = encoder == "url"
    for style in draw(st.lists(st.sampled_from(styles), max_size=2, unique=True)):
        if style == "case" and encoder == "plain":
            continue  # Plain values are matched case-insensitively, but stay as they are
        if "percent" in style:
            if percent:
                continue  # Percent-encoding twice is another encoding, not supported
            percent = True
        text = draw(restyled(text, style))
    return canary, text.encode("latin-1")


def stream_hits(data: bytes, cuts: list[int]):
    """Feed ``data`` cut at ``cuts``; return (bytes released before a hit, hits)."""
    scanner = StreamScanner(MATCHER)
    points = sorted({min(c, len(data)) for c in cuts} | {0, len(data)})
    released = b""
    for start, end in itertools.pairwise(points):
        safe, hits = scanner.feed(data[start:end])
        if hits:
            return released, hits
        released += safe
    return released + scanner.flush(), []


@MORE
@given(sent_values(), filler, filler, st.lists(st.integers(0, 2000)))
def test_sent_values_are_found_whatever_the_pieces(sent, before, after, cuts):
    canary, text = sent
    data = before.encode() + b"&k=" + text + b"&" + after.encode()
    assert canary.id in {hit.canary_id for hit in MATCHER.scan(data)}
    released, hits = stream_hits(data, cuts)
    assert canary.id in {hit.canary_id for hit in hits}
    # What was released before the hit is clean on its own.
    assert MATCHER.scan(released) == []


@given(st.binary(min_size=1, max_size=2000), st.lists(st.integers(0, 2000)))
def test_streams_are_released_whole_and_in_order(data, cuts):
    scanner = StreamScanner(MATCHER)
    points = sorted({min(c, len(data)) for c in cuts} | {0, len(data)})
    released, fed = b"", 0
    for start, end in itertools.pairwise(points):
        safe, hits = scanner.feed(data[start:end])
        assert hits == []
        released += safe
        fed = end
        # Everything but the hold-back is released, and the hold-back is bounded.
        assert len(released) >= fed - (MATCHER.span - 1) * 2 - 64 * 1024
        assert data.startswith(released)
    assert released + scanner.flush() == data


@settings(max_examples=max(10, settings.default.max_examples // 4))
@given(
    st.one_of(
        st.binary(min_size=1000, max_size=20000),
        st.text("0123456789abcdef", min_size=1000, max_size=20000).map(str.encode),
        st.text("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", min_size=1000, max_size=20000).map(str.encode),
        st.text(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            min_size=1000,
            max_size=20000,
        ).map(str.encode),
    )
)
def test_random_data_has_no_false_positives(data):
    # With needles of at least MIN_NEEDLE characters from alphabets of 16
    # symbols or more, a chance match in 20 KB is below 1e-9.
    assert MATCHER.scan(data) == []


@given(
    st.sampled_from(HOSTS), st.lists(st.sampled_from(["", "api", "x-1"]), max_size=2), st.data()
)
def test_canary_hostnames_and_their_subdomains_are_found(item, prefix, data):
    canary, host = item
    name = ".".join([*filter(None, prefix), host])
    name = "".join(c.upper() if data.draw(st.booleans()) else c for c in name)
    name += data.draw(st.sampled_from(["", "."]))
    assert canary.id in {hit.canary_id for hit in MATCHER.scan_hostname(name)}


@given(
    st.sampled_from(SECRETS),
    st.sampled_from(["hex", "base32"]),
    st.lists(st.integers(1, 63), min_size=1, max_size=8),
    st.sampled_from(["exfil.example", "a.b.example."]),
)
def test_values_split_across_dns_labels_are_found(secret, encoder, sizes, zone):
    canary, value = secret
    text = ENCODERS[encoder](value.encode()).rstrip("=").lower()
    labels, rest = [], text
    for size in itertools.cycle(sizes):
        if not rest:
            break
        labels.append(rest[:size])
        rest = rest[size:]
    name = ".".join([*labels, zone])
    assert canary.id in {hit.canary_id for hit in MATCHER.scan_hostname(name)}
