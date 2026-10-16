"""Egress allowlist: which host:port pairs the gateway may connect to."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

DEFAULT_PORTS = (80, 443)
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


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

    def matches(self, host: str, port: int) -> bool:
        if port not in self.ports:
            return False
        if self.host.startswith("*."):
            return host.endswith(self.host[1:])
        return host == self.host


def parse_rule(entry: str, default_ports: Iterable[int] = DEFAULT_PORTS) -> AllowRule:
    """Parse ``example.com``, ``*.example.com`` or ``example.com:8443``."""
    text = entry.strip().lower()
    ports = tuple(default_ports)
    if text.count(":") == 1 and not text.startswith("["):
        text, _, port_text = text.partition(":")
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise ValueError(f"invalid port in allowlist entry {entry!r}")
        ports = (int(port_text),)
    wildcard = text.startswith("*.")
    host = normalize_host(text[2:] if wildcard else text)
    if host is None:
        raise ValueError(f"invalid host in allowlist entry {entry!r}")
    return AllowRule(f"*.{host}" if wildcard else host, ports)


class Allowlist:
    def __init__(self, entries: Iterable[str], default_ports: Iterable[int] = DEFAULT_PORTS):
        ports = tuple(default_ports)
        self.rules = tuple(parse_rule(entry, ports) for entry in entries)

    def allows(self, host: str, port: int) -> bool:
        normalized = normalize_host(host)
        if normalized is None:
            return False
        return any(rule.matches(normalized, port) for rule in self.rules)
