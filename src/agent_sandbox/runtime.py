"""Check that the Docker daemon can run the agent under the configured runtime.

The input is the JSON printed by ``docker info --format '{{json .}}'``. The
sandbox never falls back to another runtime: when gVisor is requested and the
daemon cannot provide it as required, starting the sandbox fails.
"""

from __future__ import annotations

import re
from typing import Any

GVISOR = "runsc"
GVISOR_INSTALL_URL = "https://gvisor.dev/docs/user_guide/install/"
_OCI_SECCOMP = re.compile(r"--?oci-seccomp(?:=(?P<value>.*))?")
# Values Go's strconv.ParseBool accepts, which is how runsc reads its flags.
_GO_TRUE = frozenset({"1", "t", "T", "true", "TRUE", "True"})
_REGISTER = (
    f"Install gVisor ({GVISOR_INSTALL_URL}), register it with "
    "`sudo runsc install -- --oci-seccomp` and reload Docker "
    "(`sudo systemctl reload docker`)"
)


class RuntimeCheckError(ValueError):
    pass


def oci_seccomp_enabled(args: list[str]) -> bool:
    """Return True if runsc arguments ``args`` enable ``--oci-seccomp`` (the last one wins)."""
    enabled = False
    for arg in args:
        match = _OCI_SECCOMP.fullmatch(arg)
        if match:
            value = match.group("value")
            enabled = value is None or value in _GO_TRUE
    return enabled


def check(info: dict[str, Any], runtime: str) -> list[str]:
    """Check the daemon described by ``info`` for ``runtime``; return warnings.

    Raises :class:`RuntimeCheckError` when the agent must not be started.
    """
    runtimes = info.get("Runtimes") or {}
    if runtime != GVISOR:
        if info.get("DefaultRuntime") == GVISOR:
            return [
                "the Docker daemon runs containers under runsc by default, but "
                f'[sandbox] runtime = "{runtime}" starts the agent under {runtime}; '
                'set runtime = "runsc" to keep gVisor'
            ]
        return []
    entry = runtimes.get(GVISOR)
    if not isinstance(entry, dict):
        available = ", ".join(sorted(runtimes)) or "none"
        raise RuntimeCheckError(
            f'[sandbox] runtime = "runsc" but the Docker daemon has no runsc runtime '
            f'(available: {available}). {_REGISTER}, or set runtime = "runc".'
        )
    if not entry.get("path"):
        # Registered as a containerd shim: its flags live in a TOML file Docker does
        # not report, so the self-test is the only way to tell.
        return [
            "cannot confirm that runsc runs with --oci-seccomp (it is configured as a "
            "containerd shim); `agent-sandbox verify` checks that the seccomp profile "
            "is enforced"
        ]
    if not oci_seccomp_enabled(entry.get("runtimeArgs") or []):
        raise RuntimeCheckError(
            "the runsc runtime is registered without --oci-seccomp, so gVisor would ignore "
            "the sandbox's seccomp profile. Re-register it with "
            '`sudo runsc install -- --oci-seccomp` (or add "--oci-seccomp" to its '
            '"runtimeArgs" in /etc/docker/daemon.json) and reload Docker.'
        )
    return []
