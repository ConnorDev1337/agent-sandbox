import base64
import json
from urllib.parse import quote

import pytest

from agent_sandbox.canary import (
    KINDS,
    Canary,
    CanaryMatcher,
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
