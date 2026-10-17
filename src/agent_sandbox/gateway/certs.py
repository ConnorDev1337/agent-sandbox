"""Per-sandbox certificate authority and leaf certificates for TLS inspection.

The standard library cannot create X.509 certificates, so the gateway calls
the ``openssl`` command line tool. The CA private key stays in a volume that
only the gateway mounts; the agent receives the CA certificate alone, in a
read-only bundle. Leaf certificates share one key, are minted per server name
on first use and cached in memory.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import secrets
import shutil
import ssl
import subprocess
import time
from collections import OrderedDict
from pathlib import Path

CA_KEY = "ca.key"
CA_CERT = "ca.crt"
BUNDLE = "ca-bundle.crt"
SYSTEM_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
CA_DAYS = 3650
LEAF_DAYS = 397  # The longest validity clients accept for server certificates
LEAF_REFRESH = 30 * 24 * 3600.0  # Re-mint cached leaves well before they expire
OPENSSL_TIMEOUT = 30.0

_CA_CONFIG = """\
[req]
prompt = no
distinguished_name = dn
x509_extensions = ca_ext
[dn]
CN = {name}
O = agent-sandbox
[ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
"""
_LEAF_REQUEST = """\
[req]
prompt = no
distinguished_name = dn
[dn]
CN = agent-sandbox inspection
O = agent-sandbox
"""
_LEAF_EXTENSIONS = """\
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = {san}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


class CertificateError(RuntimeError):
    pass


def find_openssl() -> str:
    path = shutil.which("openssl")
    if path is None:
        raise CertificateError("the openssl command is required for TLS inspection")
    return path


def openssl_version(openssl: str) -> str:
    """Return the version line of ``openssl``: ``OpenSSL 3.0.15 ...``, ``LibreSSL 3.3.6``..."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv
            [openssl, "version"], check=True, capture_output=True, timeout=OPENSSL_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot run {openssl}: {exc}") from None
    return result.stdout.decode(errors="replace").strip()


def _ec_key_args(path: Path) -> list[str]:
    return ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-param_enc",
            "named_curve", "-out", str(path)]  # fmt: skip


def _run(openssl: str, args: list[str]) -> None:
    try:
        subprocess.run(  # noqa: S603 - fixed openssl argv built by this module
            [openssl, *args], check=True, capture_output=True, timeout=OPENSSL_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        message = detail.decode(errors="replace").strip() or str(exc)
        raise CertificateError(f"openssl {args[0]} failed: {message}") from None


def _private(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o600)


def subject_alt_name(host: str) -> str:
    try:
        return f"IP:{ipaddress.ip_address(host)}"
    except ValueError:
        return f"DNS:{host}"


class CertificateAuthority:
    """A CA whose key and certificate live in ``directory``."""

    def __init__(self, directory: Path, openssl: str) -> None:
        self.directory = directory
        self.openssl = openssl
        self.key = directory / CA_KEY
        self.cert = directory / CA_CERT

    @classmethod
    def load_or_create(cls, directory: Path, openssl: str | None = None) -> CertificateAuthority:
        """Reuse the CA in ``directory`` or create one (kept across gateway restarts)."""
        ca = cls(directory, openssl or find_openssl())
        if ca.key.exists() and ca.cert.exists():
            return ca
        directory.mkdir(parents=True, exist_ok=True)
        config = directory / "ca.cnf"
        config.write_text(
            _CA_CONFIG.format(name=f"agent-sandbox CA {secrets.token_hex(4)}"), encoding="ascii"
        )
        try:
            _run(ca.openssl, _ec_key_args(ca.key))
            _private(ca.key)
            _run(
                ca.openssl,
                ["req", "-x509", "-new", "-sha256", "-key", str(ca.key), "-config", str(config),
                 "-days", str(CA_DAYS), "-set_serial", f"0x{secrets.token_hex(16)}",
                 "-out", str(ca.cert)],
            )  # fmt: skip
        except CertificateError:
            for path in (ca.key, ca.cert):
                path.unlink(missing_ok=True)
            raise
        finally:
            config.unlink(missing_ok=True)
        return ca

    def pem(self) -> str:
        return self.cert.read_text(encoding="ascii")

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the CA certificate, as shown by most tools."""
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.pem())).hexdigest().upper()
        return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))

    def write_bundle(self, directory: Path, system_bundle: Path | None = SYSTEM_BUNDLE) -> Path:
        """Publish the CA certificate and a system-plus-sandbox bundle for the agent.

        Files are replaced atomically so a client never reads half a bundle.
        """
        directory.mkdir(parents=True, exist_ok=True)
        pem = self.pem()
        system = ""
        if system_bundle is not None and system_bundle.is_file():
            system = system_bundle.read_text(encoding="utf-8", errors="replace").rstrip() + "\n"
        for name, content in ((CA_CERT, pem), (BUNDLE, system + pem)):
            temporary = directory / f".{name}.tmp"
            temporary.write_text(content, encoding="utf-8", newline="\n")
            temporary.chmod(0o644)
            os.replace(temporary, directory / name)
        return directory / BUNDLE


class LeafIssuer:
    """Mint and cache server certificates signed by a sandbox CA."""

    def __init__(self, ca: CertificateAuthority, workdir: Path, *, max_entries: int = 512):
        self.ca = ca
        self.workdir = workdir
        self.max_entries = max_entries
        self._cache: OrderedDict[str, tuple[ssl.SSLContext, float]] = OrderedDict()
        self._pending: dict[str, asyncio.Future[ssl.SSLContext]] = {}
        workdir.mkdir(parents=True, exist_ok=True)
        self.key = workdir / "leaf.key"
        self._request = workdir / "leaf.csr"
        config = workdir / "leaf.cnf"
        config.write_text(_LEAF_REQUEST, encoding="ascii")
        _run(ca.openssl, _ec_key_args(self.key))
        _private(self.key)
        _run(
            ca.openssl,
            ["req", "-new", "-sha256", "-key", str(self.key), "-config", str(config),
             "-out", str(self._request)],
        )  # fmt: skip

    async def context_for(self, host: str) -> ssl.SSLContext:
        """Return a server context presenting a certificate for ``host``."""
        cached = self._cache.get(host)
        if cached is not None and time.monotonic() - cached[1] < LEAF_REFRESH:
            self._cache.move_to_end(host)
            return cached[0]
        pending = self._pending.get(host)
        if pending is None:
            # Concurrent connections to a new host share one openssl run.
            pending = asyncio.ensure_future(self._mint(host))
            self._pending[host] = pending
            pending.add_done_callback(lambda _: self._pending.pop(host, None))
        context = await asyncio.shield(pending)
        self._cache[host] = (context, time.monotonic())
        self._cache.move_to_end(host)
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)
        return context

    async def _mint(self, host: str) -> ssl.SSLContext:
        serial = secrets.token_hex(16)
        extensions = self.workdir / f"{serial}.ext"
        cert = self.workdir / f"{serial}.crt"
        extensions.write_text(_LEAF_EXTENSIONS.format(san=subject_alt_name(host)), "ascii")
        try:
            process = await asyncio.create_subprocess_exec(
                self.ca.openssl, "x509", "-req", "-sha256", "-in", str(self._request),
                "-CA", str(self.ca.cert), "-CAkey", str(self.ca.key),
                "-set_serial", f"0x{serial}", "-days", str(LEAF_DAYS),
                "-extfile", str(extensions), "-out", str(cert),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )  # fmt: skip
            _, stderr = await asyncio.wait_for(process.communicate(), OPENSSL_TIMEOUT)
            if process.returncode != 0:
                raise CertificateError(
                    f"cannot mint a certificate for {host}: {stderr.decode(errors='replace')}"
                )
            cert.write_text(
                cert.read_text(encoding="ascii") + self.ca.pem(), encoding="ascii", newline="\n"
            )
            return server_context(cert, self.key, host)
        finally:
            extensions.unlink(missing_ok=True)
            cert.unlink(missing_ok=True)


def server_context(chain: Path, key: Path, host: str) -> ssl.SSLContext:
    """TLS server context for ``host``: HTTP/1.1 only, refusing other server names."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Only HTTP/1.1 is offered so every request can be parsed and checked.
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(chain, key)

    def check_name(_sock: object, name: str | None, _context: ssl.SSLContext) -> int | None:
        # Second line of defense behind the ClientHello check in the proxy.
        if name is not None and name.lower().rstrip(".") != host:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    context.sni_callback = check_name
    return context


def upstream_context(cafile: str | None = None) -> ssl.SSLContext:
    """Client context for the gateway's own connections: full verification, HTTP/1.1."""
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    return context


def prepare(
    ca_dir: Path,
    bundle_dir: Path,
    workdir: Path,
    *,
    openssl: str | None = None,
    system_bundle: Path | None = SYSTEM_BUNDLE,
) -> LeafIssuer:
    """Load or create the CA, publish the agent's bundle and return a leaf issuer."""
    ca = CertificateAuthority.load_or_create(ca_dir, openssl)
    ca.write_bundle(bundle_dir, system_bundle)
    return LeafIssuer(ca, workdir)
