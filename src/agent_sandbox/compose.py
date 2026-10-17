"""Generate the Docker Compose project for one sandbox.

Compose accepts JSON (a subset of YAML), so no YAML library is needed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import SandboxConfig

PACKAGE_DIR = Path(__file__).parent
SECCOMP_PROFILE = PACKAGE_DIR / "docker" / "seccomp" / "agent.json"
PROXY_PORT = 3128
AGENT_HOME = "/home/agent"
GATEWAY_RUNTIME = "runc"
GATEWAY_CA_DIR = "/var/lib/agent-sandbox/ca"
GATEWAY_TLS_DIR = "/sandbox-tls"
AGENT_TLS_DIR = "/etc/agent-sandbox/tls"
# Variables that point the usual clients at the bundle with the sandbox CA.
# NODE_EXTRA_CA_CERTS adds to Node's built-in roots, so it gets the CA alone.
CA_BUNDLE_VARIABLES = (
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
)

# Host-executed files inside the workspace. The agent must not be able to plant
# code that runs on the host later (git hooks, core.hooksPath/core.fsmonitor).
READ_ONLY_PATHS = (".git/hooks", ".git/config")


def _bind(source: Path, target: str, *, read_only: bool = False) -> dict[str, Any]:
    return {"type": "bind", "source": str(source), "target": target, "read_only": read_only}


def build(config: SandboxConfig) -> dict[str, Any]:
    proxy = f"http://{config.gateway_ip}:{PROXY_PORT}"
    no_proxy = "localhost,127.0.0.1,::1"
    environment: dict[str, str | None] = {
        "HOME": AGENT_HOME,
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "http_proxy": proxy,
        "https_proxy": proxy,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
        "NODE_USE_ENV_PROXY": "1",
        **config.env_set,
    }
    if config.tls_inspect:
        for name in CA_BUNDLE_VARIABLES:
            environment[name] = f"{AGENT_TLS_DIR}/ca-bundle.crt"
        environment["NODE_EXTRA_CA_CERTS"] = f"{AGENT_TLS_DIR}/ca.crt"
    for name in config.env_pass:
        environment[name] = None  # Compose takes the value from the invoking shell

    workspace_mounts = [_bind(config.workspace, "/workspace")]
    for relative in READ_ONLY_PATHS:
        path = config.workspace / relative
        if path.exists():
            workspace_mounts.append(_bind(path, f"/workspace/{relative}", read_only=True))

    hardening = {
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "restart": "unless-stopped",
    }
    gateway = {
        **hardening,
        "image": config.gateway_image,
        "build": {"context": str(PACKAGE_DIR), "dockerfile": "docker/gateway.Dockerfile"},
        # Always runc, whatever the daemon's default: under gVisor, inotify does not
        # see the agent opening the canary files, so the tripwire would go blind.
        "runtime": GATEWAY_RUNTIME,
        # Seeding the agent's home needs CHOWN/FOWNER/DAC_OVERRIDE; port 53 needs
        # NET_BIND_SERVICE. Nothing else.
        "cap_add": ["CHOWN", "DAC_OVERRIDE", "FOWNER", "NET_BIND_SERVICE"],
        "tmpfs": ["/tmp:size=16m"],  # noqa: S108 - container tmpfs mount
        "mem_limit": "256m",
        "pids_limit": 128,
        "volumes": [
            _bind(config.gateway_file, "/etc/agent-sandbox/gateway.json", read_only=True),
            _bind(config.canary_file, "/etc/agent-sandbox/canaries.json", read_only=True),
            _bind(config.log_dir, "/var/log/agent-sandbox"),
            {"type": "volume", "source": "home", "target": "/sandbox-home"},
        ],
        "networks": {"sandbox": {"ipv4_address": config.gateway_ip}, "egress": {}},
        "healthcheck": {
            "test": [
                "CMD",
                "python",
                "-c",
                f"import socket; socket.create_connection(('127.0.0.1', {PROXY_PORT}), 2)",
            ],
            "interval": "2s",
            "timeout": "3s",
            "retries": 30,
        },
    }
    agent = {
        **hardening,
        "image": config.agent_image,
        "build": {"context": str(PACKAGE_DIR), "dockerfile": "docker/agent.Dockerfile"},
        # Under runsc the seccomp profile below is enforced by gVisor's kernel
        # (the runtime must run with --oci-seccomp; see runtime.py).
        "runtime": config.runtime,
        "depends_on": {"gateway": {"condition": "service_healthy"}},
        "user": "1000:1000",
        "init": True,
        "working_dir": "/workspace",
        "command": ["sleep", "infinity"],
        "security_opt": ["no-new-privileges:true", f"seccomp={SECCOMP_PROFILE}"],
        "tmpfs": [
            "/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777",  # noqa: S108 - container tmpfs
            "/run:rw,noexec,nosuid,nodev,size=16m",
        ],
        "cpus": config.cpus,
        "mem_limit": config.memory,
        "pids_limit": config.pids,
        "ulimits": {"nofile": {"soft": 4096, "hard": 8192}},
        "dns": [config.gateway_ip],
        "environment": environment,
        "volumes": [
            *workspace_mounts,
            {"type": "volume", "source": "home", "target": AGENT_HOME},
        ],
        "networks": {"sandbox": {"ipv4_address": config.agent_ip}},
    }
    volumes: dict[str, Any] = {"home": {}}
    if config.tls_inspect:
        # The CA key never leaves the gateway; the agent mounts only the
        # published certificates, read-only, so its root filesystem stays read-only.
        gateway["volumes"] += [
            {"type": "volume", "source": "ca", "target": GATEWAY_CA_DIR},
            {"type": "volume", "source": "tls", "target": GATEWAY_TLS_DIR},
        ]
        agent["volumes"].append(
            {"type": "volume", "source": "tls", "target": AGENT_TLS_DIR, "read_only": True}
        )
        volumes.update({"ca": {}, "tls": {}})
    return {
        "name": config.project,
        "services": {"gateway": gateway, "agent": agent},
        "networks": {
            "sandbox": {
                "internal": True,
                "ipam": {"config": [{"subnet": config.subnet}]},
                # Without this the host owns an address on the bridge and every host
                # service listening on 0.0.0.0 is reachable from the agent.
                "driver_opts": {"com.docker.network.bridge.inhibit_ipv4": "true"},
            },
            "egress": {},
        },
        "volumes": volumes,
    }


def write(config: SandboxConfig) -> Path:
    """Write the Compose file and gateway settings into the state directory."""
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.log_dir.mkdir(parents=True, exist_ok=True)
    config.gateway_file.write_text(
        json.dumps(config.gateway_settings(), indent=2) + "\n", encoding="utf-8"
    )
    config.compose_file.write_text(json.dumps(build(config), indent=2) + "\n", encoding="utf-8")
    return config.compose_file
