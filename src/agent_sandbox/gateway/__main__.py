"""Gateway entry point: ``python -m agent_sandbox.gateway``."""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from pathlib import Path

from ..allowlist import Allowlist
from ..canary import CanaryMatcher, load_registry
from . import certs, dns, proxy
from .alerts import EventLog
from .decoding import MAX_DECODED
from .tripwire import Tripwire, seed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-sandbox-gateway")
    parser.add_argument("--config", type=Path, default=Path("/etc/agent-sandbox/gateway.json"))
    parser.add_argument("--canaries", type=Path, default=Path("/etc/agent-sandbox/canaries.json"))
    parser.add_argument("--home", type=Path, default=Path("/sandbox-home"))
    parser.add_argument("--log-dir", type=Path, default=Path("/var/log/agent-sandbox"))
    # TLS inspection: the CA key lives in a gateway-only volume, the published
    # certificates in a volume the agent mounts read-only.
    parser.add_argument("--ca-dir", type=Path, default=Path("/var/lib/agent-sandbox/ca"))
    parser.add_argument("--tls-dir", type=Path, default=Path("/sandbox-tls"))
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
        tripwire = Tripwire(watched, log)
        tripwire.arm()  # Watches exist before the proxy accepts connections
        tripwire.start()

    allowlist = Allowlist(config.get("allow", []), config.get("default_ports", (80, 443)))
    issuer = None
    if config.get("tls_inspect"):
        # Ready before the proxy listens, so the agent never starts without its bundle.
        workdir = Path(tempfile.mkdtemp(prefix="agent-sandbox-tls-"))
        issuer = certs.prepare(args.ca_dir, args.tls_dir, workdir)
        log.event(
            "tls.inspection_enabled",
            ca_fingerprint=issuer.ca.fingerprint(),
            passthrough=[rule.target for rule in allowlist.rules if not rule.inspect],
        )

    server = await proxy.serve(
        proxy.Proxy(
            allowlist,
            matcher,
            log,
            max_body=config.get("max_body", 10 * 1024 * 1024),
            tls_issuer=issuer,
            upstream_tls=certs.upstream_context() if issuer else None,
            undecodable_bodies=config.get(
                "undecodable_bodies", "block" if config.get("tls_inspect") else "allow"
            ),
            max_decoded_body=config.get("max_decoded_body", MAX_DECODED),
        ),
        args.listen,
        args.proxy_port,
    )
    await dns.serve(matcher, log, args.listen, args.dns_port)
    log.event(
        "gateway.started",
        allow=len(allowlist.rules),
        canaries=len(canaries),
        tls_inspect=issuer is not None,
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
