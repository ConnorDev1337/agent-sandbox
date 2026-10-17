"""``agent-sandbox`` command line (runs on the host)."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__, compose, runtime
from .allowlist import Allowlist
from .canary import generate, load_registry, save_registry
from .config import CONFIG_FILE, ConfigError, SandboxConfig, load

EXPECTED_ALERTS = ("canary.exfiltration", "canary.dns", "canary.file_access")
# Methods the self-test tries against a host with method rules, in order.
FORBIDDEN_CANDIDATES = ("DELETE", "PUT", "PATCH", "POST")
SAMPLE_CONFIG = """\
# agent-sandbox configuration (safe to commit: it contains no secrets).

[sandbox]
# Run the agent under gVisor's user-space kernel instead of the host kernel
# (needs runsc registered with --oci-seccomp; check with: agent-sandbox doctor).
# runtime = "runsc"

[network]
# Hosts the agent may reach through the gateway, in addition to the defaults
# (PyPI, npm, GitHub). Use "*.example.com" for subdomains, "host:port" for ports,
# and tables to limit methods and paths, e.g.
# { host = "github.com", methods = ["GET", "HEAD"] }
allow = []
# Decrypt HTTPS with a per-sandbox CA so canaries in request bodies are caught
# and method rules apply to HTTPS too (breaks clients that pin certificates).
# tls_inspect = true

[resources]
cpus = 2
memory = "4g"
pids = 512

[env]
# Host environment variables forwarded into the sandbox, e.g. an API key the
# agent needs. Anything forwarded can be exfiltrated to an allowlisted host.
pass = []
"""


class CommandError(Exception):
    pass


def _docker() -> str:
    path = shutil.which("docker")
    if path is None:
        raise CommandError("docker was not found on PATH")
    return path


def compose_command(config: SandboxConfig, *args: str) -> list[str]:
    return [_docker(), "compose", "-p", config.project, "-f", str(config.compose_file), *args]


def run(command: list[str], *, capture: bool = False, check: bool = True, **kwargs: Any):
    try:
        return subprocess.run(  # noqa: S603 - fixed docker argv built by this module
            command, check=check, text=True, capture_output=capture, **kwargs
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        raise CommandError(f"{' '.join(command[:4])} ... failed: {detail}") from None


def _ensure_canaries(config: SandboxConfig, *, rotate: bool = False) -> int:
    if config.canary_file.exists() and not rotate:
        return len(load_registry(config.canary_file))
    canaries = generate(config.canary_kinds)
    save_registry(canaries, config.canary_file)
    if os.name != "nt":
        config.canary_file.chmod(0o600)
    return len(canaries)


def _warn(config: SandboxConfig) -> None:
    for message in config.warnings():
        print(f"warning: {message}", file=sys.stderr)


def _prepare(config: SandboxConfig) -> None:
    _warn(config)
    _ensure_canaries(config)
    compose.write(config)


def _docker_info() -> dict[str, Any]:
    result = run([_docker(), "info", "--format", "{{json .}}"], capture=True)
    try:
        info = json.loads(result.stdout)
    except ValueError:
        info = None
    if not isinstance(info, dict):
        raise CommandError("docker info did not return a JSON object")
    return info


def _preflight(config: SandboxConfig) -> dict[str, Any] | None:
    """Check that the Docker daemon provides the configured runtime; return its info."""
    try:
        info = _docker_info()
    except CommandError:
        if config.runtime == runtime.GVISOR:
            raise
        return None  # Compose reports an unreachable daemon itself
    for message in runtime.check(info, config.runtime):
        print(f"warning: {message}", file=sys.stderr)
    return info


def _start(config: SandboxConfig, *, build: bool) -> None:
    _prepare(config)
    command = compose_command(config, "up", "-d", "--wait")
    if build:
        command.insert(command.index("up") + 1, "--build")
    run(command)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    return records


# ---------------------------------------------------------------------------- commands


def cmd_init(config: SandboxConfig, args: argparse.Namespace) -> int:
    _warn(config)
    count = _ensure_canaries(config, rotate=args.rotate)
    compose.write(config)
    sample = config.workspace / CONFIG_FILE
    if args.write_config and not sample.exists():
        sample.write_text(SAMPLE_CONFIG, encoding="utf-8")
        print(f"wrote {sample}")
    print(f"sandbox {config.project}")
    print(f"  state      {config.state_dir}")
    print(f"  canaries   {count} ({'rotated' if args.rotate else 'kept'})")
    print(f"  allowlist  {', '.join(rule.describe() for rule in config.rules())}")
    print(f"  tls        {'inspected' if config.tls_inspect else 'not inspected (SNI only)'}")
    print(f"  runtime    {config.runtime}")
    return 0


def cmd_up(config: SandboxConfig, args: argparse.Namespace) -> int:
    _preflight(config)
    _start(config, build=args.build)
    print(f"sandbox {config.project} is running; open a shell with: agent-sandbox shell")
    return 0


def cmd_down(config: SandboxConfig, args: argparse.Namespace) -> int:
    if not config.compose_file.exists():
        print("sandbox is not initialized")
        return 0
    command = compose_command(config, "down")
    if args.volumes:
        command.append("--volumes")
    run(command)
    return 0


def _exec(config: SandboxConfig, command: list[str], interactive: bool) -> int:
    flags = [] if interactive and sys.stdin.isatty() else ["-T"]
    result = run(compose_command(config, "exec", *flags, "agent", *command), check=False)
    return result.returncode


def cmd_shell(config: SandboxConfig, _args: argparse.Namespace) -> int:
    return _exec(config, ["bash", "-l"], interactive=True)


def cmd_run(config: SandboxConfig, args: argparse.Namespace) -> int:
    command = list(args.agent_command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise CommandError("missing command after --")
    return _exec(config, command, interactive=True)


def cmd_status(config: SandboxConfig, _args: argparse.Namespace) -> int:
    if not config.compose_file.exists():
        print("sandbox is not initialized (run: agent-sandbox up)")
        return 0
    run(compose_command(config, "ps"))
    alerts = _read_jsonl(config.log_dir / "alerts.jsonl")
    critical = sum(1 for a in alerts if a.get("severity") == "critical")
    print(f"alerts: {len(alerts)} ({critical} critical) in {config.log_dir / 'alerts.jsonl'}")
    return 0


def _print_records(records: list[dict[str, Any]], as_json: bool) -> None:
    for record in records:
        if as_json:
            print(json.dumps(record, sort_keys=True))
            continue
        extra = record.get("message") or " ".join(
            f"{k}={record[k]}" for k in ("host", "port", "method", "name") if k in record
        )
        level = record.get("severity", "info")
        print(f"{record.get('ts', '?')}  {level:<8} {record.get('kind', '?'):<22} {extra}")


def cmd_alerts(config: SandboxConfig, args: argparse.Namespace) -> int:
    name = "events.jsonl" if args.events else "alerts.jsonl"
    records = _read_jsonl(config.log_dir / name)[-args.n :]
    if not records:
        print("no alerts" if not args.events else "no events")
    _print_records(records, args.json)
    return 1 if args.fail and any(r.get("severity") == "critical" for r in records) else 0


def _allowed_host(config: SandboxConfig) -> str:
    """Return the first allowlisted name that accepts any request on ports 80 and 443."""
    allowlist = Allowlist(config.allow, config.default_ports)
    for rule in allowlist.rules:
        if rule.host.startswith("*.") or not {80, 443} <= set(rule.ports):
            continue
        if not (allowlist.restricted(rule.host, 80) or allowlist.restricted(rule.host, 443)):
            return rule.host
    return "pypi.org"


def _restricted_target(config: SandboxConfig) -> tuple[str, str] | None:
    """Return a host with method rules and a method they refuse, for the self-test."""
    allowlist = Allowlist(config.allow, config.default_ports)
    port = 443 if config.tls_inspect else 80
    for rule in allowlist.rules:
        if not rule.restricted or rule.host.startswith("*.") or port not in rule.ports:
            continue
        for method in FORBIDDEN_CANDIDATES:
            if not allowlist.permits(rule.host, port, method, "/"):
                return rule.host, method
    return None


def cmd_verify(config: SandboxConfig, args: argparse.Namespace) -> int:
    started = _dt.datetime.now(_dt.UTC).isoformat(timespec="milliseconds")
    info = _preflight(config)
    if not args.no_up:
        _start(config, build=args.build)
    command = [
        "python3",
        "/opt/agent-sandbox/selftest.py",
        "--allowed-host",
        _allowed_host(config),
        "--host-ip",
        config.bridge_ip,
        "--runtime",
        config.runtime,
    ]
    if info and info.get("KernelVersion"):
        command += ["--host-kernel", str(info["KernelVersion"])]
    if config.tls_inspect:
        command.append("--tls-inspect")
    target = _restricted_target(config)
    if target is not None:
        command += ["--restricted-host", target[0], "--forbidden-method", target[1]]
    result = run(
        compose_command(config, "exec", "-T", "agent", *command), capture=True, check=False
    )
    rows = []
    for line in result.stdout.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    if not rows:
        raise CommandError(f"self-test produced no results: {result.stderr.strip()}")

    time.sleep(1.0)  # Let the gateway flush alerts raised by the last checks
    alerts = [
        a for a in _read_jsonl(config.log_dir / "alerts.jsonl") if a.get("ts", "") >= started
    ]
    seen = {a.get("kind") for a in alerts}
    expected = {f"gateway raised a {kind} alert": kind in seen for kind in EXPECTED_ALERTS}
    if config.tls_inspect:
        expected["gateway raised a canary.exfiltration alert for decrypted TLS"] = any(
            a.get("kind") == "canary.exfiltration" and a.get("tls") is True for a in alerts
        )
    for name, found in expected.items():
        rows.append({"check": name, "ok": found, "detail": "found" if found else "missing"})
    width = max(len(r["check"]) for r in rows)
    for row in rows:
        mark = "SKIP" if row.get("skipped") else "PASS" if row["ok"] else "FAIL"
        print(f"{mark}  {row['check']:<{width}}  {row['detail']}")
    ran = [r for r in rows if not r.get("skipped")]
    failed = sum(1 for r in ran if not r["ok"])
    skipped = len(rows) - len(ran)
    print(
        f"\n{len(ran) - failed}/{len(ran)} checks passed"
        + (f", {skipped} skipped (not enabled in this configuration)" if skipped else "")
    )
    return 1 if failed else 0


def cmd_config(config: SandboxConfig, _args: argparse.Namespace) -> int:
    payload = {
        "project": config.project,
        "workspace": str(config.workspace),
        "state_dir": str(config.state_dir),
        "allow": list(config.allow),
        "default_ports": list(config.default_ports),
        "tls_inspect": config.tls_inspect,
        "undecodable_bodies": config.undecodable_bodies,
        "runtime": config.runtime,
        "subnet": config.subnet,
        "gateway_ip": config.gateway_ip,
        "agent_ip": config.agent_ip,
        "resources": {"cpus": config.cpus, "memory": config.memory, "pids": config.pids},
        "env_pass": list(config.env_pass),
        "canary_kinds": list(config.canary_kinds),
        "webhook": bool(config.webhook),
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_doctor(config: SandboxConfig, _args: argparse.Namespace) -> int:
    info = _docker_info()
    runtimes = info.get("Runtimes") or {}
    print(f"docker     {info.get('ServerVersion', '?')} ({info.get('OperatingSystem', '?')})")
    print(f"kernel     {info.get('KernelVersion', '?')}")
    default = info.get("DefaultRuntime", "?")
    print(f"runtimes   {', '.join(sorted(runtimes)) or 'none'} (default: {default})")
    entry = runtimes.get(runtime.GVISOR)
    if isinstance(entry, dict):
        binary = entry.get("path") or entry.get("runtimeType", "?")
        print(f"runsc      {' '.join([binary, *entry.get('runtimeArgs', [])])}")
    for message in runtime.check(info, config.runtime):
        print(f"warning: {message}", file=sys.stderr)
    print(f"agent      {config.runtime}: ok")
    return 0


# ---------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox",
        description="Hardened Docker sandbox for coding agents.",
    )
    parser.add_argument("--version", action="version", version=f"agent-sandbox {__version__}")
    parser.add_argument("-w", "--workspace", default=".", help="project directory (default: .)")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("init", help="create sandbox state and canaries for the workspace")
    p.add_argument("--rotate", action="store_true", help="generate new canary values")
    p.add_argument("--write-config", action="store_true", help=f"write a sample {CONFIG_FILE}")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("up", help="start the sandbox (gateway + agent)")
    p.add_argument("--build", action="store_true", help="rebuild the images")
    p.set_defaults(func=cmd_up)

    p = sub.add_parser("down", help="stop the sandbox")
    p.add_argument("--volumes", action="store_true", help="also delete the agent's home volume")
    p.set_defaults(func=cmd_down)

    sub.add_parser("shell", help="open a shell in the agent container").set_defaults(
        func=cmd_shell
    )

    p = sub.add_parser("run", help="run a command in the agent container")
    p.add_argument("agent_command", nargs=argparse.REMAINDER, help="-- command [args...]")
    p.set_defaults(func=cmd_run)

    sub.add_parser("status", help="show containers and alert counts").set_defaults(func=cmd_status)

    p = sub.add_parser("alerts", help="show alerts (or all events)")
    p.add_argument("-n", type=int, default=50)
    p.add_argument("--events", action="store_true", help="show every gateway decision")
    p.add_argument("--json", action="store_true")
    p.add_argument("--fail", action="store_true", help="exit 1 if a critical alert is shown")
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("verify", help="run the isolation self-test inside the sandbox")
    p.add_argument("--build", action="store_true", help="rebuild the images first")
    p.add_argument("--no-up", action="store_true", help="assume the sandbox is running")
    p.set_defaults(func=cmd_verify)

    sub.add_parser("config", help="print the effective configuration").set_defaults(
        func=cmd_config
    )

    sub.add_parser(
        "doctor", help="check that the Docker daemon can run the configured runtime"
    ).set_defaults(func=cmd_doctor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        config = load(args.workspace)
        return int(args.func(config, args))
    except (ConfigError, CommandError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
