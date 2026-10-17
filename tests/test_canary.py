import base64
import json
from urllib.parse import quote

import pytest

from agent_sandbox.canary import (
    KINDS,
    Canary,
    CanaryMatcher,
    StreamScanner,
    encodings,
    generate,
    load_registry,
    save_registry,
)


@pytest.fixture(scope="module")
def canaries():
    return generate()


@pytest.fixture(scope="module")
def matcher(canaries):
    return CanaryMatcher(canaries)


def test_generate_all_kinds(canaries):
    assert [c.kind for c in canaries] == list(KINDS)
    assert len({c.id for c in canaries}) == len(KINDS)
    for canary in canaries:
        assert canary.secrets and all(s in canary.content for s in canary.secrets)
        assert not canary.path.startswith("/") and ".." not in canary.path
    with pytest.raises(ValueError, match="unknown canary kind"):
        generate(["vault"])


def test_values_are_unique_per_generation():
    first, second = generate(["aws"]), generate(["aws"])
    assert first[0].secrets != second[0].secrets


def test_formats_look_realistic(canaries):
    by_kind = {c.kind: c for c in canaries}
    assert by_kind["aws"].secrets[0].startswith("AKIA") and len(by_kind["aws"].secrets[0]) == 20
    assert by_kind["github"].secrets[0].startswith("ghp_")
    assert by_kind["ssh"].content.startswith(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE"
    )
    assert by_kind["url"].hosts[0].endswith(".metrics.corp-internal.example")


def test_registry_roundtrip(tmp_path, canaries):
    path = tmp_path / "state" / "canaries.json"
    save_registry(canaries, path)
    assert load_registry(path) == canaries
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = 99
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        load_registry(path)


def _secret(canaries, kind, index=0):
    return next(c for c in canaries if c.kind == kind).secrets[index]


@pytest.mark.parametrize(
    "encode",
    [
        lambda s: s,
        lambda s: s.upper(),
        lambda s: quote(s, safe=""),
        lambda s: s.encode().hex(),
        lambda s: base64.b64encode(b"prefix:" + s.encode()).decode(),
        lambda s: base64.b64encode(b"xy" + s.encode() + b"tail").decode(),
        lambda s: base64.urlsafe_b64encode(b"z" + s.encode()).decode(),
        lambda s: base64.b32encode(b"abc" + s.encode()).decode().lower(),
    ],
    ids=["plain", "upper", "url", "hex", "b64-0", "b64-2", "b64url-1", "b32-3"],
)
def test_detects_encoded_secrets(canaries, matcher, encode):
    secret = _secret(canaries, "aws", 1)
    payload = f"POST /collect HTTP/1.1\r\n\r\ndata={encode(secret)}&x=1"
    (hit,) = matcher.scan(payload)
    assert hit.kind == "aws"


def _wrap(text: str, width: int, sep: str = "\r\n") -> str:
    return sep.join(text[i : i + width] for i in range(0, len(text), width))


@pytest.mark.parametrize(
    ("encode", "label"),
    [
        # base64(1) and MIME wrap at 76 columns; prefixes move the line breaks around.
        (lambda s, p: _wrap(base64.b64encode(p + s.encode()).decode(), 76, "\n"), "base64"),
        (lambda s, p: _wrap(base64.b64encode(p + s.encode()).decode(), 76), "base64"),
        (lambda s, p: " ".join(f"{b:02x}" for b in p + s.encode()), "hex"),
        (lambda s, p: _wrap(p.decode() + s, 9, "=\r\n"), "plain"),  # quoted-printable
        (lambda s, p: p.decode() + quote(s, safe="/"), "plain|url|plain (percent-decoded)"),
        (
            lambda s, p: p.decode() + "".join(f"%{b:02X}" for b in s.encode()),
            "plain (percent-decoded)",
        ),
        (
            lambda s, p: p.decode() + "".join(f"%{b:02x}" for b in s.encode()[:20]) + s[20:],
            "plain (percent-decoded)",
        ),
    ],
    ids=[
        "b64-lf",
        "b64-crlf",
        "hex-spaced",
        "quoted-printable",
        "url-keep-slash",
        "url-all",
        "url-mixed",
    ],
)
def test_detects_wrapped_and_partially_encoded_secrets(canaries, matcher, encode, label):
    secret = _secret(canaries, "aws", 1)
    for prefix in (b"", b"k", b"key=", b"aws_secret_access_key = "):
        (hit,) = matcher.scan(f"part\r\n\r\n{encode(secret, prefix)}\r\n--boundary--")
        assert hit.kind == "aws" and hit.encoding in label.split("|")


def test_percent_decoding_only_around_escapes(canaries, matcher):
    secret = _secret(canaries, "github")
    mixed = "".join(f"%{ord(c):02x}" for c in secret[:6]) + secret[6:]
    noise = "%zz %41" + "x" * 2000
    (hit,) = matcher.scan(f"{noise}{mixed}{noise}")
    assert hit.encoding == "plain (percent-decoded)"
    assert matcher.scan(noise + "%2f" + "y" * 2000 + "%25") == []


def test_multipart_upload_of_a_canary_file_is_detected(canaries, matcher):
    aws = next(c for c in canaries if c.kind == "aws")
    for transfer, body in (
        ("binary", aws.content),
        ("base64", _wrap(base64.b64encode(aws.content.encode()).decode(), 76)),
    ):
        payload = (
            "--b\r\nContent-Disposition: form-data; name=file; filename=credentials\r\n"
            f"Content-Transfer-Encoding: {transfer}\r\n\r\n{body}\r\n--b--\r\n"
        )
        assert matcher.scan(payload)[0].canary_id == aws.id


def test_whole_file_exfiltration_is_detected(canaries, matcher):
    ssh = next(c for c in canaries if c.kind == "ssh")
    assert matcher.scan(ssh.content)[0].canary_id == ssh.id
    encoded = base64.b64encode(ssh.content.encode())
    assert matcher.scan(encoded)[0].kind == "ssh"


def test_no_false_positives_on_ordinary_traffic(matcher):
    payload = (
        "GET /simple/requests/ HTTP/1.1\r\nHost: pypi.org\r\nUser-Agent: pip/24.0\r\n"
        "Accept: text/html\r\n\r\n" + "x" * 10_000
    )
    assert matcher.scan(payload) == []
    assert matcher.scan(b"\x00\x01binary\xff" * 1000) == []


def test_hostname_and_dns_label_exfiltration(canaries, matcher):
    url = next(c for c in canaries if c.kind == "url")
    assert matcher.scan_hostname(url.hosts[0] + ".")[0].encoding == "hostname"
    assert matcher.scan_hostname("api." + url.hosts[0])[0].canary_id == url.id
    secret = _secret(canaries, "netrc")
    hexed = secret.encode().hex()
    labels = ".".join(hexed[i : i + 30] for i in range(0, len(hexed), 30))
    (hit,) = matcher.scan_hostname(f"{labels}.attacker.example")
    assert hit.kind == "netrc" and hit.encoding == "hex"
    assert matcher.scan_hostname("pypi.org") == []


def test_encodings_skip_short_needles():
    forms = encodings("abc")
    assert all(not needles for needles in forms.values())
    canary = Canary("id1", "custom", "x", "x", ("short",))
    assert CanaryMatcher([canary]).scan("short") == []


def test_netrc_is_not_a_tripwire(canaries, tmp_path):
    by_kind = {c.kind: c for c in canaries}
    assert by_kind["netrc"].tripwire is False and by_kind["aws"].tripwire is True
    save_registry(canaries, tmp_path / "r.json")
    assert {c.kind: c.tripwire for c in load_registry(tmp_path / "r.json")}["netrc"] is False


def test_stream_scanner_holds_back_split_canaries(canaries, matcher):
    secret = next(c for c in canaries if c.kind == "aws").secrets[1].encode()
    scanner = StreamScanner(matcher)
    clean = b"a" * 1000
    released, hits = scanner.feed(clean + secret[:15])
    assert hits == [] and released == clean[: len(released)]
    assert secret[:15] not in released and len(released) <= 1000
    released, hits = scanner.feed(secret[15:])
    assert released == b"" and hits[0].kind == "aws"


def test_stream_scanner_finds_a_wrapped_canary_split_across_pieces(canaries, matcher):
    secret = next(c for c in canaries if c.kind == "dotenv").secrets[1].encode()
    wrapped = _wrap(base64.b64encode(b"x" + secret).decode(), 8, "\r\n").encode()
    scanner = StreamScanner(matcher)
    released, hits = scanner.feed(b"a" * 500 + wrapped[:30])
    assert hits == [] and wrapped[:12] not in released
    assert scanner.feed(wrapped[30:])[1][0].kind == "dotenv"


def test_stream_scanner_releases_everything_eventually(matcher):
    scanner = StreamScanner(matcher)
    pieces = [bytes([65 + i % 26]) * 700 for i in range(20)]
    released = b"".join(scanner.feed(piece)[0] for piece in pieces) + scanner.flush()
    assert released == b"".join(pieces) and scanner.flush() == b""
    empty = StreamScanner(CanaryMatcher([]))
    assert empty.feed(b"abc") == (b"abc", [])
