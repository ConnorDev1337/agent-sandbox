"""Property-based tests of allowlist host, port, wildcard and path matching."""

import ipaddress
import itertools
import re
from fnmatch import fnmatchcase
from urllib.parse import unquote_to_bytes

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from agent_sandbox.allowlist import Allowlist, AllowRule, normalize_host, parse_rule
from agent_sandbox.gateway.proxy import split_host_port

# Cheap properties over large input spaces run more examples, in every profile.
MORE = settings(max_examples=5 * settings.default.max_examples)
labels = st.from_regex(r"[a-z0-9]([a-z0-9_-]{0,8}[a-z0-9])?", fullmatch=True)
top_labels = st.from_regex(r"[a-z][a-z0-9-]{0,5}[a-z0-9]", fullmatch=True)
domains = st.builds(
    lambda names, top: ".".join([*names, top]),
    st.lists(labels, min_size=1, max_size=3),
    top_labels,
)
ports = st.integers(1, 65535)
# Characters outside ASCII whose lowercase form is ASCII (the Kelvin sign...).
ASCII_LOOKALIKES = [c for c in map(chr, range(0x80, 0x3000)) if c.lower().isascii()]


def variants(host: str) -> st.SearchStrategy[str]:
    """Spellings of ``host`` that name the same destination."""
    return st.builds(
        lambda flips, dot: (
            "".join(c.upper() if f else c for c, f in zip(host, flips, strict=False)) + dot
        ),
        st.lists(st.booleans(), min_size=len(host), max_size=len(host)),
        st.sampled_from(["", "."]),
    )


# ---------------------------------------------------------------------------- hosts


@given(st.one_of(st.text(max_size=40), domains, st.ip_addresses().map(str)))
def test_normalized_hosts_are_canonical(text):
    host = normalize_host(text)
    if host is None:
        return
    assert host.isascii() and host == host.lower() and not host.endswith(".")
    assert len(host) <= 253 and normalize_host(host) == host
    assert text.isascii()


@given(domains, st.data())
def test_hosts_are_case_and_trailing_dot_insensitive(domain, data):
    assert normalize_host(data.draw(variants(domain))) == domain


@given(domains, st.data())
def test_non_ascii_names_are_refused(domain, data):
    # IDNA names must be listed and sent as punycode; Unicode lookalikes of
    # ASCII letters never normalize to an ASCII name.
    position = data.draw(st.integers(0, len(domain) - 1))
    char = data.draw(
        st.one_of(st.sampled_from(ASCII_LOOKALIKES), st.characters(min_codepoint=128))
    )
    assert normalize_host(domain[:position] + char + domain[position + 1 :]) is None


@given(st.text(st.characters(min_codepoint=0xA1, max_codepoint=0x24F), min_size=1, max_size=8))
def test_punycode_names_match_their_ascii_form(name):
    try:
        ascii_name = f"{name}.example".encode("idna").decode()
    except UnicodeError:
        ascii_name = ""
    assert normalize_host(f"{name}.example") is None
    assume(normalize_host(ascii_name) is not None)
    assert Allowlist([ascii_name]).allows(ascii_name.upper(), 443)


@given(domains, labels, domains, st.data())
def test_wildcards_match_strict_subdomains_only(suffix, label, other, data):
    allow = Allowlist([f"*.{suffix}"])
    assert allow.allows(data.draw(variants(f"{label}.{suffix}")), 443)
    assert not allow.allows(suffix, 443)
    for host in (f"{label}{suffix}", f"{suffix}.{other}", other, f"{other}{suffix}"):
        # Only names with a label boundary before the suffix match.
        assert allow.allows(host, 443) == host.endswith(f".{suffix}")


@given(domains, domains, st.data())
def test_exact_entries_match_one_name(domain, other, data):
    allow = Allowlist([domain])
    assert allow.allows(data.draw(variants(domain)), 443)
    assert allow.allows(other, 443) == (other == domain)


@given(domains, ports, ports)
def test_ports(domain, port, other):
    assert Allowlist([f"{domain}:{port}"]).allows(domain, other) == (other == port)
    assert Allowlist([domain]).allows(domain, other) == (other in {80, 443})


@given(st.text(max_size=30))
def test_entries_parse_or_raise_value_error(text):
    try:
        rule = parse_rule(text)
    except ValueError:
        return
    assert normalize_host(rule.host.removeprefix("*.")) == rule.host.removeprefix("*.")
    assert all(0 < port < 65536 for port in rule.ports)


ODD_PORTS = ["\xb2", "+80", " 80", "8_0", "0x50", chr(0x661), "", "080000"]


@given(domains, st.sampled_from(ODD_PORTS))
def test_ports_are_ascii_digits(domain, port):
    with pytest.raises(ValueError):
        parse_rule(f"{domain}:{port}")
    with pytest.raises(ValueError):
        split_host_port(f"{domain}:{port}", 443)


@given(st.one_of(domains, st.ip_addresses(v=4).map(str)), ports)
def test_authorities_round_trip(host, port):
    assert split_host_port(f"{host}:{port}", 443) == (host, port)
    assert split_host_port(host, 8080) == (host, 8080)


@given(st.ip_addresses(v=6), ports)
def test_ipv6_authorities_round_trip(address, port):
    assert split_host_port(f"[{address}]:{port}", 443) == (str(address), port)
    assert split_host_port(f"[{address}]", 443) == (str(address), 443)


@MORE
@given(st.text(max_size=30))
def test_authorities_split_or_raise_value_error(text):
    try:
        host, port = split_host_port(text, 443)
    except ValueError:
        return
    assert normalize_host(host) == host and 0 < port < 65536


@given(
    st.lists(st.from_regex(r"[0-9]{1,3}|0x[0-9a-f]{1,2}", fullmatch=True), min_size=2, max_size=4)
)
def test_numeric_names_are_not_host_names(parts):
    # Resolvers read "127.1" or "0x7f.1" as IPv4 addresses; no TLD is numeric.
    name = ".".join(parts)
    if normalize_host(name) is not None:
        assert normalize_host(name) == str(ipaddress.ip_address(name))
    with pytest.raises(ValueError):
        parse_rule(f"*.{name}")


@given(domains, st.ip_addresses())
def test_wildcards_never_match_ip_addresses(domain, address):
    assert not Allowlist([f"*.{domain}"]).allows(str(address), 443)


# ---------------------------------------------------------------------------- overlaps

UNIVERSE = ["a.example", "b.a.example", "c.b.a.example", "d.example", "a.other"]
patterns = st.one_of(st.sampled_from(UNIVERSE), st.sampled_from(UNIVERSE).map(lambda h: f"*.{h}"))
rule_ports = st.sampled_from([(443,), (80, 443), (8443,)])


def witness(first: AllowRule, second: AllowRule) -> str:
    """A host both rules match, if they overlap."""
    hosts = sorted([first.host, second.host], key=lambda h: (h.startswith("*."), -len(h)))
    return hosts[0].replace("*.", "w.") if hosts[0].startswith("*.") else hosts[0]


@given(patterns, patterns, rule_ports, rule_ports, st.sampled_from(UNIVERSE), st.data())
def test_overlaps_is_exact(first, second, first_ports, second_ports, host, data):
    a, b = AllowRule(first, first_ports), AllowRule(second, second_ports)
    assert a.overlaps(b) == b.overlaps(a)
    host = data.draw(st.sampled_from([host, f"w.{host}", f"w.x.{host}"]))
    for port in {*first_ports, *second_ports}:
        if a.matches(host, port) and b.matches(host, port):
            assert a.overlaps(b)
    if a.overlaps(b):
        common = set(first_ports) & set(second_ports)
        assert common
        name = witness(a, b)
        assert all(a.matches(name, p) and b.matches(name, p) for p in common)


@given(
    st.lists(
        st.tuples(
            patterns, st.sampled_from(["", ":443", ":8443"]), st.sampled_from(["", "p", "r"])
        ),
        min_size=1,
        max_size=5,
    )
)
def test_no_destination_is_both_passed_through_and_restricted(specs):
    entries = []
    for pattern, port, kind in specs:
        host = pattern + port
        entries.append(
            {"host": host, "inspect": False}
            if kind == "p"
            else {"host": host, "methods": ["GET"]}
            if kind == "r"
            else host
        )
    try:
        allow = Allowlist(entries)
    except ValueError as exc:
        assert "inspect = false" in str(exc)
        return
    for host, port in itertools.product(UNIVERSE + [f"w.{h}" for h in UNIVERSE], (80, 443, 8443)):
        assert not (allow.passthrough(host, port) and allow.restricted(host, port))


# ---------------------------------------------------------------------------- paths

PATTERNS = ["/ok/*", "/*/upload", "/a/*/b", "/exact/path", "/v1/*.json"]
# Path pieces that servers are known to normalize: dot segments, path
# parameters (Tomcat), escaped and overlong delimiters, %u escapes (IIS),
# double encoding, NUL truncation, Windows trailing dots and spaces... There
# is no raw "?": rules are matched against the path without the query.
PIECES = [
    "/", "ok", "a", "b", "x", "upload", "exact", "path", "v1", "f.json", ".", "..", "...",
    ";", ";p", "%2e", "%2E", "%2f", "%5c", "%25", "%252e", "%252f", "%00", "%20", "%3b",
    "%23", "%3f", "%u002e", "%c0%ae", "%c0%af", "%e0%80%ae", "%61", "\\", "#", "~",
    "\xc0\xae", "..;", "..%00", "..%20", ". .", "%252e%252e", "%c0%ae%c0%ae", "%u002e%u002e",
]  # fmt: skip
segments = st.lists(st.sampled_from(PIECES), min_size=1, max_size=3).map("".join)
# Mostly paths that start and end like a pattern, with tricky segments between.
paths = st.builds(
    lambda prefix, middle, suffix: prefix + "/".join(middle) + suffix,
    st.sampled_from(["/", "/ok/", "/x/", "/a/", "/v1/", "/exact/path"]),
    st.lists(segments, max_size=4),
    st.sampled_from(["", "/upload", "/b", "/f.json", "/x"]),
)


def remove_dot_segments(path: str) -> str:
    """RFC 3986, section 5.2.4."""
    segments = path.split("/")[1:]
    output: list[str] = []
    for index, segment in enumerate(segments, 1):
        if segment == ".." and output:
            output.pop()
        if segment not in {".", ".."}:
            output.append(segment)
        elif index == len(segments):
            output.append("")
    return "/" + "/".join(output)


OVERLONG = {b"\xc0\xae": b".", b"\xc0\xaf": b"/", b"\xc1\x9c": b"\\", b"\xe0\x80\xae": b"."}


def lenient_decode(path: str) -> str:
    data = unquote_to_bytes(re.sub(r"%u00([0-9a-fA-F]{2})", r"%\1", path))
    for overlong, plain in OVERLONG.items():
        data = data.replace(overlong, plain)
    return data.decode("latin-1")


def overlong_raw(path: str) -> str:
    data = path.encode("latin-1", "replace")
    for overlong, plain in OVERLONG.items():
        data = data.replace(overlong, plain)
    return data.decode("latin-1")


SERVER_STEPS = [
    lambda p: p.split("#", 1)[0],
    lambda p: p.split("?", 1)[0],
    lenient_decode,
    overlong_raw,
    lambda p: p.split("\0", 1)[0],
    lambda p: p.replace("\\", "/"),
    lambda p: re.sub(r";[^/]*", "", p),
    lambda p: re.sub(r"/{2,}", "/", p),
    lambda p: "/".join(s.rstrip(". ") if s.rstrip(". ") else s for s in p.split("/")),
    remove_dot_segments,
]


def server_views(path: str) -> set[str]:
    """Paths that some server could route ``path`` to, up to three steps deep."""
    views = {path}
    for _ in range(3):
        views |= {step(view) for view in views for step in SERVER_STEPS}
    return views


@MORE
@given(paths, st.sampled_from(PATTERNS))
def test_permitted_paths_match_however_servers_normalize_them(path, pattern):
    rule = AllowRule("x.example", (443,), paths=(pattern,))
    if rule.permits("GET", path):
        assert all(fnmatchcase(view, pattern) for view in server_views(path)), path


@given(paths, st.sampled_from(PATTERNS))
def test_unambiguous_paths_match_like_a_glob(path, pattern):
    rule = AllowRule("x.example", (443,), paths=(pattern,))
    if rule.permits("GET", path):
        assert fnmatchcase(path, pattern)


@given(st.sampled_from(["GET", "get", "Post", "DELETE"]), paths)
def test_methods_are_case_insensitive(method, path):
    rule = AllowRule("x.example", (443,), methods=frozenset({"GET", "POST"}))
    assert rule.permits(method, path) == (method.upper() in {"GET", "POST"})
