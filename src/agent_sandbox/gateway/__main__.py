"""Gateway entry point: ``python -m agent_sandbox.gateway``."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from ..allowlist import Allowlist
from ..canary import CanaryMatcher, load_registry
from . import dns, proxy
from .alerts import EventLog
from .tripwire import Tripwire, seed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-sandbox-gateway")
    parser.add_argument("--config", type=Path, default=Path("/etc/agent-sandbox/gateway.json"))
    parser.add_argument("--canaries", type=Path, default=Path("/etc/agent-sandbox/canaries.json"))
    parser.add_argument("--home", type=Path, default=Path("/sandbox-home"))
    parser.add_argument("--log-dir", type=Path, default=Path("/var/log/agent-sandbox"))
    parser.add_argument("--listen", default="0.0.0.0")  # noqa: S104 - internal network only
    parser.add_argument("--proxy-port", type=int, default=3128)
    parser.add_argument("--dns-port", type=int, default=53)
    return parser


async def _run(args: argparse.Namespace) -> None:
    config = json.loads(args.config.read_text(encoding="utf-8"))
    log = EventLog(args.log_dir, webhook=config.get("webhook") or None)
    canaries = load_registry(args.canaries) if args.canaries.exists() else []
    matcher = CanaryMatcher(canaries)

    if canaries and config.get("seed_canaries", True):
        paths = seed(args.home, canaries, config.get("uid", 1000), config.get("gid", 1000))
        watched = {p: c for p, c in zip(paths, canaries, strict=True) if c.tripwire}
        Tripwire(watched, log).start()

    allowlist = Allowlist(config.get("allow", []), config.get("default_ports", (80, 443)))
    server = await proxy.serve(
        proxy.Proxy(allowlist, matcher, log, max_body=config.get("max_body", 10 * 1024 * 1024)),
        args.listen,
        args.proxy_port,
    )
    await dns.serve(matcher, log, args.listen, args.dns_port)
    log.event(
        "gateway.started",
        allow=len(allowlist.rules),
        canaries=len(canaries),
        proxy_port=args.proxy_port,
        dns_port=args.dns_port,
    )
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    asyncio.run(_run(_parser().parse_args(argv)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
