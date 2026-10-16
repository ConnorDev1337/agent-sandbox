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


GITHUB_READ_ONLY = [
    "github.com",
    {"host": "github.com", "methods": ["get", "HEAD"]},
    {"host": "github.com", "methods": ["POST"], "paths": ["/*/git-upload-pack"]},
]


def test_method_and_path_rules():
    allow = Allowlist(
        [*GITHUB_READ_ONLY, "pypi.org", {"host": "*.example.com", "paths": ["/v1/*"]}]
    )
    assert allow.allows("github.com", 443) and allow.restricted("github.com", 443)
    assert allow.permits("github.com", 443, "GET", "/owner/repo")
    assert allow.permits("github.com", 443, "head", "/")
    assert allow.permits("github.com", 443, "POST", "/owner/repo.git/git-upload-pack")
    assert not allow.permits("github.com", 443, "POST", "/owner/repo.git/git-receive-pack")
    assert not allow.permits("github.com", 443, "DELETE", "/owner/repo")
    # Plain entries do not widen a host covered by restricting rules.
    assert not allow.permits("github.com", 443, "PUT", "/x")
    assert not allow.restricted("pypi.org", 443) and allow.permits("pypi.org", 443, "PUT", "/")
    assert allow.permits("api.example.com", 443, "DELETE", "/v1/items")
    assert not allow.permits("api.example.com", 443, "GET", "/v2/items")
    assert not allow.permits("evil.example", 443, "GET", "/")


@pytest.mark.parametrize(
    "path",
    ["/a/%2e%2e/git-upload-pack", "/a%2Fb/git-upload-pack", "/a/../git-upload-pack",
     "//x/git-upload-pack", "/a\\b/git-upload-pack", "/a/./git-upload-pack"],
)  # fmt: skip
def test_ambiguous_paths_never_match_path_rules(path):
    assert not Allowlist(GITHUB_READ_ONLY).permits("github.com", 443, "POST", path)


def test_rule_description():
    rules = Allowlist([*GITHUB_READ_ONLY, "registry.example:8443"]).rules
    assert [r.describe() for r in rules] == [
        "github.com",
        "github.com [GET,HEAD]",
        "github.com [POST] /*/git-upload-pack",
        "registry.example:8443",
    ]


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"host": "x.example", "verbs": ["GET"]}, "unknown key"),
        ({"methods": ["GET"]}, "need a host"),
        ({"host": "x.example", "methods": []}, "non-empty list"),
        ({"host": "x.example", "methods": "GET"}, "non-empty list"),
        ({"host": "x.example", "methods": ["GET /x"]}, "invalid HTTP method"),
        ({"host": "x.example", "methods": ["CONNECT"]}, "invalid HTTP method"),
        ({"host": "x.example", "paths": ["v1/*"]}, "must start with '/'"),
        ({"host": "bad host", "methods": ["GET"]}, "invalid host"),
        (42, "string or a table"),
    ],
)
def test_invalid_tables(entry, message):
    with pytest.raises(ValueError, match=message):
        parse_rule(entry)
