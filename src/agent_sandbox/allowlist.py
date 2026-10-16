"""Egress allowlist: which host:port pairs the gateway may connect to.

An entry is either a string (``"pypi.org"``, ``"*.example.com"``,
``"registry.example:8443"``) that allows every request, or a table that also
limits the HTTP methods and request paths::

    {host = "github.com", methods = ["GET", "HEAD"]}
    {host = "github.com", methods = ["POST"], paths = ["/*/git-upload-pack"]}

Rules with ``methods`` or ``paths`` only ever narrow access: once such a rule
matches a destination, a request to it must be permitted by at least one of
the restricting rules, regardless of plain entries for the same host.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

DEFAULT_PORTS = (80, 443)
RULE_KEYS = frozenset({"host", "methods", "paths"})
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_METHOD = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")
# Paths that servers may normalize differently from a plain glob match.
_AMBIGUOUS_PATH = re.compile(r"%2[ef]|%5c|\\|//|/\.\.?(/|$)", re.IGNORECASE)

AllowEntry = str | Mapping[str, Any]


def normalize_host(host: str) -> str | None:
    """Lowercase hostname without trailing dot, or ``None`` if it is not a valid name."""
    host = host.strip().lower().rstrip(".")
    if not host or len(host) > 253:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    return host


@dataclass(frozen=True)
class AllowRule:
    host: str  # exact name, IP literal, or "*.suffix" for strict subdomains
    ports: tuple[int, ...]
    methods: frozenset[str] | None = None  # None: any method
    paths: tuple[str, ...] | None = None  # None: any path

    @property
    def restricted(self) -> bool:
        return self.methods is not None or self.paths is not None

    def matches(self, host: str, port: int) -> bool:
        if port not in self.ports:
            return False
        if self.host.startswith("*."):
            return host.endswith(self.host[1:])
        return host == self.host

    def permits(self, method: str, path: str) -> bool:
        """Return True if this rule lets ``method`` reach ``path`` (without query)."""
        if self.methods is not None and method.upper() not in self.methods:
            return False
        if self.paths is None:
            return True
        if _AMBIGUOUS_PATH.search(path):
            return False
        return any(fnmatchcase(path, pattern) for pattern in self.paths)

    def describe(self) -> str:
        text = self.host if len(self.ports) > 1 else f"{self.host}:{self.ports[0]}"
        if self.methods is not None:
            text += f" [{','.join(sorted(self.methods))}]"
        if self.paths is not None:
            text += f" {' '.join(self.paths)}"
        return text


def _parse_host(entry: str, default_ports: tuple[int, ...]) -> tuple[str, tuple[int, ...]]:
    text = entry.strip().lower()
    ports = default_ports
    if text.count(":") == 1 and not text.startswith("["):
        text, _, port_text = text.partition(":")
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise ValueError(f"invalid port in allowlist entry {entry!r}")
        ports = (int(port_text),)
    wildcard = text.startswith("*.")
    host = normalize_host(text[2:] if wildcard else text)
    if host is None:
        raise ValueError(f"invalid host in allowlist entry {entry!r}")
    return (f"*.{host}" if wildcard else host), ports


def _string_list(value: Any, name: str, host: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{name} of allowlist entry {host!r} must be a non-empty list of strings")
    return value


def parse_rule(entry: AllowEntry, default_ports: Iterable[int] = DEFAULT_PORTS) -> AllowRule:
    """Parse a string entry or a ``{host, methods, paths}`` table."""
    ports = tuple(default_ports)
    if isinstance(entry, str):
        host, ports = _parse_host(entry, ports)
        return AllowRule(host, ports)
    if not isinstance(entry, Mapping):
        raise ValueError(f"allowlist entry {entry!r} must be a string or a table")
    unknown = set(entry) - RULE_KEYS
    if unknown:
        raise ValueError(f"allowlist entry has unknown key(s) {', '.join(sorted(unknown))}")
    raw_host = entry.get("host")
    if not isinstance(raw_host, str):
        raise ValueError("allowlist table entries need a host string")
    host, ports = _parse_host(raw_host, ports)

    methods = None
    if "methods" in entry:
        names = _string_list(entry["methods"], "methods", raw_host)
        methods = frozenset(name.strip().upper() for name in names)
        bad = sorted(m for m in methods if not _METHOD.match(m) or m == "CONNECT")
        if bad:
            raise ValueError(f"invalid HTTP method(s) {', '.join(bad)} for {raw_host!r}")
    paths = None
    if "paths" in entry:
        paths = tuple(_string_list(entry["paths"], "paths", raw_host))
        bad = [p for p in paths if not p.startswith("/") or len(p) > 1024 or p != p.strip()]
        if bad:
            raise ValueError(f"paths for {raw_host!r} must start with '/': {', '.join(bad)}")
    return AllowRule(host, ports, methods, paths)


class Allowlist:
    def __init__(
        self, entries: Iterable[AllowEntry], default_ports: Iterable[int] = DEFAULT_PORTS
    ):
        ports = tuple(default_ports)
        self.rules = tuple(parse_rule(entry, ports) for entry in entries)

    def _matching(self, host: str, port: int) -> list[AllowRule]:
        normalized = normalize_host(host)
        if normalized is None:
            return []
        return [rule for rule in self.rules if rule.matches(normalized, port)]

    def allows(self, host: str, port: int) -> bool:
        return bool(self._matching(host, port))

    def restricted(self, host: str, port: int) -> bool:
        """Return True if requests to ``host:port`` are limited by method or path rules."""
        return any(rule.restricted for rule in self._matching(host, port))

    def permits(self, host: str, port: int, method: str, path: str) -> bool:
        """Return True if an HTTP ``method`` request for ``path`` may reach ``host:port``."""
        rules = self._matching(host, port)
        restricting = [rule for rule in rules if rule.restricted]
        if not restricting:
            return bool(rules)
        return any(rule.permits(method, path) for rule in restricting)
