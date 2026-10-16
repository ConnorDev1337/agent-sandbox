"""Derive the agent's seccomp profile from Docker's default profile.

The upstream profile is vendored (``docker/seccomp/moby-default.json``) and
tightened here instead of being written by hand, so it stays an allowlist and
can be refreshed from upstream. Run ``python -m agent_sandbox.seccomp`` to
regenerate ``docker/seccomp/agent.json``; a test fails if it is stale.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SECCOMP_DIR = Path(__file__).parent / "docker" / "seccomp"
UPSTREAM = SECCOMP_DIR / "moby-default.json"
OUTPUT = SECCOMP_DIR / "agent.json"
UPSTREAM_URL = "https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json"
UPSTREAM_SHA256 = "6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6"

# Never allowed, whatever capabilities a future configuration grants.
DENIED = frozenset(
    {
        # Process inspection and injection.
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "kcmp",
        "pidfd_getfd",
        # Namespaces, mounts and filesystem handles (container escape primitives).
        "unshare",
        "setns",
        "mount",
        "umount",
        "umount2",
        "pivot_root",
        "chroot",
        "move_mount",
        "open_tree",
        "fsopen",
        "fsconfig",
        "fsmount",
        "fspick",
        "mount_setattr",
        "name_to_handle_at",
        "open_by_handle_at",
        # Kernel attack surface rarely needed by build tools.
        "bpf",
        "perf_event_open",
        "userfaultfd",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "keyctl",
        "add_key",
        "request_key",
        "fanotify_init",
        "lookup_dcookie",
        # Host administration.
        "init_module",
        "finit_module",
        "delete_module",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "swapon",
        "swapoff",
        "acct",
        "syslog",
        "quotactl",
        "quotactl_fd",
        "iopl",
        "ioperm",
        "vhangup",
    }
)

# socket(2) address families the agent may use: AF_UNIX, AF_INET, AF_INET6 and
# AF_NETLINK (glibc's getaddrinfo/getifaddrs need it; without CAP_NET_ADMIN it
# is read-only). Raw packet sockets and exotic families stay blocked.
SOCKET_FAMILIES = (1, 2, 10, 16)


def load_upstream(path: Path = UPSTREAM) -> dict[str, Any]:
    """Load the vendored upstream profile, refusing unexpected content."""
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != UPSTREAM_SHA256:
        raise ValueError(f"{path} sha256 {digest} does not match {UPSTREAM_SHA256}")
    return json.loads(data)


def harden(profile: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``profile`` with denied syscalls and socket families removed."""
    result = copy.deepcopy(profile)
    rules = []
    for rule in result["syscalls"]:
        if rule.get("action") == "SCMP_ACT_ALLOW":
            names = [n for n in rule["names"] if n not in DENIED]
            if "socket" in names:
                # Replaced below by an explicit family allowlist.
                names.remove("socket")
            if not names:
                continue
            rule["names"] = names
        rules.append(rule)
    for family in SOCKET_FAMILIES:
        rules.append(
            {
                "names": ["socket"],
                "action": "SCMP_ACT_ALLOW",
                "args": [{"index": 0, "value": family, "op": "SCMP_CMP_EQ"}],
            }
        )
    result["syscalls"] = rules
    return result


def allowed_names(profile: dict[str, Any]) -> set[str]:
    """Syscalls allowed by at least one rule (ignoring argument filters)."""
    return {
        name
        for rule in profile["syscalls"]
        if rule.get("action") == "SCMP_ACT_ALLOW"
        for name in rule["names"]
    }


def render(profile: dict[str, Any]) -> str:
    return json.dumps(profile, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    check = "--check" in (argv if argv is not None else sys.argv[1:])
    content = render(harden(load_upstream()))
    if check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != content:
            print(f"{OUTPUT} is stale; run: python -m agent_sandbox.seccomp", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(content, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
