"""Sandbox configuration (``.agent-sandbox.toml``) and per-project state paths.

State (canary registry, logs, generated Compose file) lives outside the
workspace so the agent, which can read the whole workspace, never sees which
credentials are canaries.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .allowlist import AllowEntry, AllowRule, parse_rule
from .canary import KINDS

CONFIG_FILE = ".agent-sandbox.toml"
ENV_HOME = "AGENT_SANDBOX_HOME"
DEFAULT_ALLOW = (
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
)
_SECTIONS = {
    "sandbox": {"name", "agent_image", "runtime"},
    "network": {
        "allow",
        "extend_default_allow",
        "default_ports",
        "subnet",
        "tls_inspect",
        "undecodable_bodies",
    },
    "resources": {"cpus", "memory", "pids"},
    "env": {"pass", "set"},
    "canaries": {"kinds"},
    "alerts": {"webhook"},
}
# What the gateway does with a request body it cannot decode for scanning.
UNDECODABLE_POLICIES = ("block", "allow")
# OCI runtimes the agent container can use: runc shares the host kernel, runsc
# (gVisor) gives it a user-space kernel of its own.
RUNTIMES = ("runc", "runsc")
_MEMORY = re.compile(r"^\d+(\.\d+)?[kmg]?$", re.IGNORECASE)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ConfigError(ValueError):
    pass


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "workspace"


@dataclass(frozen=True)
class SandboxConfig:
    workspace: Path
    name: str
    allow: tuple[AllowEntry, ...] = DEFAULT_ALLOW
    default_ports: tuple[int, ...] = (80, 443)
    subnet: str = "172.31.250.0/24"
    tls_inspect: bool = False
    undecodable_bodies: str = "allow"  # load() defaults to "block" with tls_inspect
    cpus: float = 2.0
    memory: str = "4g"
    pids: int = 512
    env_pass: tuple[str, ...] = ()
    env_set: dict[str, str] = field(default_factory=dict)
    canary_kinds: tuple[str, ...] = KINDS
    webhook: str | None = None
    agent_image: str = f"agent-sandbox/agent:{__version__}"
    runtime: str = "runc"
    gateway_image: str = f"agent-sandbox/gateway:{__version__}"

    @property
    def project(self) -> str:
        """Docker Compose project name, unique per workspace path."""
        digest = hashlib.sha256(str(self.workspace).encode()).hexdigest()[:8]
        return f"agent-sandbox-{self.name}-{digest}"

    @property
    def bridge_ip(self) -> str:
        """Address Docker would give the host on the sandbox bridge."""
        return str(ipaddress.ip_network(self.subnet).network_address + 1)

    @property
    def gateway_ip(self) -> str:
        return str(ipaddress.ip_network(self.subnet).network_address + 2)

    @property
    def agent_ip(self) -> str:
        return str(ipaddress.ip_network(self.subnet).network_address + 3)

    @property
    def state_dir(self) -> Path:
        root = Path(os.environ.get(ENV_HOME) or Path.home() / ".agent-sandbox")
        return root / "projects" / self.project

    @property
    def canary_file(self) -> Path:
        return self.state_dir / "canaries.json"

    @property
    def gateway_file(self) -> Path:
        return self.state_dir / "gateway.json"

    @property
    def compose_file(self) -> Path:
        return self.state_dir / "compose.json"

    @property
    def log_dir(self) -> Path:
        return self.state_dir / "logs"

    def rules(self) -> list[AllowRule]:
        return [parse_rule(entry, self.default_ports) for entry in self.allow]

    def warnings(self) -> list[str]:
        """Describe settings that are valid but weaker than they look."""
        if self.tls_inspect:
            return []
        return [
            f"network.allow: the method/path rule for {rule.describe()} is enforced on plain "
            "HTTP only; HTTPS requests are not visible without [network] tls_inspect = true"
            for rule in self.rules()
            if rule.restricted
        ]

    def gateway_settings(self) -> dict[str, Any]:
        return {
            "allow": [dict(e) if isinstance(e, dict) else e for e in self.allow],
            "default_ports": list(self.default_ports),
            "tls_inspect": self.tls_inspect,
            "undecodable_bodies": self.undecodable_bodies,
            "webhook": self.webhook,
            "uid": 1000,
            "gid": 1000,
        }


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a table")
    unknown = set(value) - _SECTIONS[name]
    if unknown:
        raise ConfigError(f"[{name}]: unknown key(s) {', '.join(sorted(unknown))}")
    return value


def _strings(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return tuple(value)


def load(workspace: str | Path, path: Path | None = None) -> SandboxConfig:
    """Load the configuration of ``workspace`` (defaults if no config file exists)."""
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise ConfigError(f"workspace {root} is not a directory")
    file = path or root / CONFIG_FILE
    data: dict[str, Any] = {}
    if file.exists():
        try:
            data = tomllib.loads(file.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot read {file}: {exc}") from None
    unknown = set(data) - set(_SECTIONS)
    if unknown:
        raise ConfigError(f"unknown section(s): {', '.join(sorted(unknown))}")

    sandbox = _section(data, "sandbox")
    network = _section(data, "network")
    resources = _section(data, "resources")
    env = _section(data, "env")
    canaries = _section(data, "canaries")
    alerts = _section(data, "alerts")

    extra = network.get("allow", [])
    if not isinstance(extra, list) or not all(isinstance(e, str | dict) for e in extra):
        raise ConfigError("network.allow must be a list of strings or tables")
    allow = (DEFAULT_ALLOW if network.get("extend_default_allow", True) else ()) + tuple(extra)
    ports = network.get("default_ports", [80, 443])
    if not isinstance(ports, list) or not all(isinstance(p, int) and 0 < p < 65536 for p in ports):
        raise ConfigError("network.default_ports must be a list of TCP ports")
    for entry in allow:
        try:
            parse_rule(entry, ports)
        except ValueError as exc:
            raise ConfigError(f"network.allow: {exc}") from None

    runtime = sandbox.get("runtime", "runc")
    if runtime not in RUNTIMES:
        raise ConfigError(f"sandbox.runtime must be one of: {', '.join(RUNTIMES)}")

    tls_inspect = network.get("tls_inspect", False)
    if not isinstance(tls_inspect, bool):
        raise ConfigError("network.tls_inspect must be true or false")
    # Inspection is the opt-in to content scanning, so a body it cannot read is
    # refused by default; without it HTTPS is not scanned at all anyway.
    undecodable = network.get("undecodable_bodies", "block" if tls_inspect else "allow")
    if undecodable not in UNDECODABLE_POLICIES:
        raise ConfigError('network.undecodable_bodies must be "block" or "allow"')

    subnet = str(network.get("subnet", "172.31.250.0/24"))
    try:
        net = ipaddress.ip_network(subnet)
    except ValueError:
        raise ConfigError(f"network.subnet {subnet!r} is not a network") from None
    if net.version != 4 or not net.is_private or net.prefixlen > 28:
        raise ConfigError("network.subnet must be a private IPv4 network of /28 or larger")

    cpus = resources.get("cpus", 2.0)
    memory = str(resources.get("memory", "4g"))
    pids = resources.get("pids", 512)
    if not isinstance(cpus, int | float) or cpus <= 0:
        raise ConfigError("resources.cpus must be a positive number")
    if not _MEMORY.match(memory):
        raise ConfigError("resources.memory must look like 512m or 4g")
    if not isinstance(pids, int) or pids < 32:
        raise ConfigError("resources.pids must be an integer >= 32")

    env_pass = _strings(env.get("pass", []), "env.pass")
    env_set = env.get("set", {})
    if not isinstance(env_set, dict) or not all(isinstance(v, str) for v in env_set.values()):
        raise ConfigError("env.set must be a table of strings")
    for name in (*env_pass, *env_set):
        if not _ENV_NAME.match(name):
            raise ConfigError(f"invalid environment variable name {name!r}")

    kinds = _strings(canaries.get("kinds", list(KINDS)), "canaries.kinds")
    unknown_kinds = set(kinds) - set(KINDS)
    if unknown_kinds:
        raise ConfigError(f"canaries.kinds: unknown kind(s) {', '.join(sorted(unknown_kinds))}")

    webhook = alerts.get("webhook") or None
    if webhook is not None and not str(webhook).startswith(("https://", "http://")):
        raise ConfigError("alerts.webhook must be an http(s) URL")

    return SandboxConfig(
        workspace=root,
        name=_slug(str(sandbox.get("name") or root.name)),
        allow=allow,
        default_ports=tuple(ports),
        subnet=str(net),
        tls_inspect=tls_inspect,
        undecodable_bodies=undecodable,
        cpus=float(cpus),
        memory=memory,
        pids=pids,
        env_pass=env_pass,
        env_set=dict(env_set),
        canary_kinds=kinds,
        webhook=webhook,
        agent_image=str(sandbox.get("agent_image") or f"agent-sandbox/agent:{__version__}"),
        runtime=runtime,
    )
