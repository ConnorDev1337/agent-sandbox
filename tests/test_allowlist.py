import pytest

from agent_sandbox.allowlist import Allowlist, normalize_host, parse_rule


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("PyPI.org.", "pypi.org"),
        ("files.pythonhosted.org", "files.pythonhosted.org"),
        ("[::1]", "::1"),
        ("10.0.0.1", "10.0.0.1"),
        ("localhost", None),
        ("bad host.com", None),
        ("-x.example", None),
        ("", None),
        ("a" * 300 + ".com", None),
    ],
)
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


def test_rules_and_matching():
    allow = Allowlist(["pypi.org", "*.githubusercontent.com", "registry.example:8443"])
    assert allow.allows("pypi.org", 443)
    assert allow.allows("PYPI.ORG.", 80)
    assert not allow.allows("pypi.org", 22)
    assert not allow.allows("evil-pypi.org", 443)
    assert not allow.allows("pypi.org.evil.example", 443)
    assert allow.allows("objects.githubusercontent.com", 443)
    assert not allow.allows("githubusercontent.com", 443)  # wildcard means subdomains only
    assert allow.allows("registry.example", 8443)
    assert not allow.allows("registry.example", 443)
    assert not allow.allows("not a host", 443)


def test_ip_literals_must_be_listed_explicitly():
    assert not Allowlist(["*.example.com"]).allows("93.184.216.34", 443)
    assert Allowlist(["93.184.216.34"]).allows("93.184.216.34", 443)


@pytest.mark.parametrize(
    "entry", ["pypi.org:0", "pypi.org:http", "*.", "under_score..com", "x:1:2"]
)
def test_invalid_entries(entry):
    with pytest.raises(ValueError):
        parse_rule(entry)
