# agent-sandbox

A hardened Docker sandbox for coding agents. The agent gets a container with no capabilities, a
tightened seccomp profile and a read-only root filesystem; its only way out is a gateway that
enforces a domain **allowlist** (optionally down to HTTP methods and paths); and its home
directory is seeded with **canary credentials** that raise an alert the moment they show up in
outbound traffic or DNS queries. With the opt-in **TLS inspection**, that includes the bodies of
HTTPS requests to allowlisted hosts. With the opt-in **gVisor** runtime, the agent's system calls
are served by a user-space kernel instead of the host's.

```text
$ agent-sandbox verify          # tls_inspect = true, github.com read-only, registry.npmjs.org passed through
PASS  runs as a non-root user                                          uid=1000
PASS  no capabilities                                                  CapEff=0000000000000000 CapBnd=0000000000000000
PASS  no_new_privs and seccomp filter active                           NoNewPrivs=1 Seccomp=2
PASS  root filesystem is read-only                                     Read-only file system
PASS  dangerous syscalls return EPERM                                  all blocked
SKIP  agent runs on gVisor's kernel, not the host's                    runtime is runc, not runsc
PASS  threads start (clone3 is refused with ENOSYS)                    clone3 failed with ENOSYS
PASS  no direct route to the internet                                  Network is unreachable
PASS  host is unreachable on the sandbox network                       no answer from 172.31.250.1
PASS  external DNS is sinkholed                                        [Errno -2] Name or service not known
PASS  allowlisted host reachable through the proxy                     status=200
PASS  other hosts are refused by the proxy                             status=None Tunnel connection failed: 403 blocked: example.com:443 is not in the allowlist
PASS  canary exfiltration is blocked                                   status=403 agent-sandbox gateway: blocked: canary credential detected in outbound data
PASS  canary in a DNS query is caught by the sinkhole                  query answered NXDOMAIN (alert expected on the host)
PASS  HTTPS is re-signed by the sandbox CA (TLS inspection)            pypi.org certificate issued by agent-sandbox
PASS  TLS passthrough host presents its own certificate                registry.npmjs.org certificate issued by Google Trust Services
PASS  CA bundle is read-only and holds no private key                  /etc/agent-sandbox/tls/ca-bundle.crt Read-only file system
PASS  canary in an HTTPS request body is blocked                       status=403 agent-sandbox gateway: blocked: canary credential detected in outbound data
PASS  forbidden HTTP method is refused                                 DELETE https://github.com/ status=403 agent-sandbox gateway: blocked: DELETE / is not allowed for github.com
PASS  canary in a gzip-encoded request body is blocked                 https status=403 agent-sandbox gateway: blocked: canary credential detected in outbound
PASS  Node.js fetch reaches an allowlisted host through the proxy      node v22.23.3 status=200
PASS  Node.js fetch to other hosts is refused by the proxy             node v22.23.3 fetch failed: Request was cancelled.: Proxy response (403) !== 200 when HTTP Tunneling
PASS  gateway raised a canary.exfiltration alert                       found
PASS  gateway raised a canary.dns alert                                found
PASS  gateway raised a canary.file_access alert                        found
PASS  gateway raised a canary.exfiltration alert for decrypted TLS     found
PASS  gateway logged the TLS passthrough tunnel to registry.npmjs.org  found

26/26 checks passed, 1 skipped (not enabled in this configuration)
```

Checks that the configuration does not enable are reported as `SKIP` (with the defaults:
19 checks pass and the six TLS inspection, TLS passthrough, method rule and gVisor checks are
skipped).

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Running a coding agent](#running-a-coding-agent)
- [Defense in depth with tool-call-guard and mcp-security-scanner](#defense-in-depth-with-tool-call-guard-and-mcp-security-scanner)
- [Configuration](#configuration)
- [Security layers](#security-layers)
- [Alerts](#alerts)
- [Threat model](#threat-model)
- [Limitations](#limitations)
- [Development](#development)

## How it works

```text
 host                                   Docker
 ----                                   ------------------------------------------------------
 agent-sandbox CLI          +--------------------------+        +-----------------------------+
 ~/.agent-sandbox/<project> |  agent (untrusted)       |        |  gateway (trusted)          |
   canaries.json  ---ro---> |  uid 1000, no caps       | :3128  |  allowlist HTTP/CONNECT     |
   logs/ <-------- alerts ---|  seccomp, read-only /    |------->|  proxy + canary scanning    |----> allowlisted
                            |  /workspace (your repo)  |  :53   |  DNS sinkhole (NXDOMAIN)    |      hosts only
 your project  ---rw------> |  /home/agent (canaries)  |------->|  canary seeding, tripwires  |
                            +--------------------------+        +-----------------------------+
                               network "sandbox": internal, no route out, no host address
```

- The agent container is attached only to an **internal** Docker network: no default route, no
  address for the host on the bridge, and DNS pointed at the gateway's sinkhole.
- `HTTP(S)_PROXY` points at the gateway, which forwards only to allowlisted `host:port` pairs and
  scans everything it can read for canary values. With `tls_inspect`, it also terminates HTTPS
  with a per-sandbox CA so it can read (and scan, and apply method rules to) HTTPS requests.
- The canary registry and the logs live under `~/.agent-sandbox/`, **outside** the workspace, so
  the agent cannot tell which credentials are canaries.

## Quick start

Requirements: Docker Engine or Docker Desktop with Compose v2, Python 3.11+.

```bash
pip install git+https://gitlab.com/connorhack/tools/agent-sandbox.git   # or: pip install -e . from a clone
cd ~/code/my-project
agent-sandbox init --write-config     # canaries + .agent-sandbox.toml (no secrets in it)
agent-sandbox up --build              # build images, start gateway + agent
agent-sandbox verify                  # isolation self-test (output above)
agent-sandbox shell                   # interactive shell inside the sandbox
agent-sandbox run -- pytest -q        # one-off command
agent-sandbox alerts                  # what the gateway caught
agent-sandbox down                    # stop (add --volumes to wipe the agent's home)
```

| Command | Purpose |
|---|---|
| `init [--rotate] [--write-config]` | Create state and canaries (`--rotate` generates new values) |
| `up [--build]` | Start the sandbox, waiting until both containers are healthy |
| `shell`, `run -- CMD...` | Work inside the agent container |
| `status` | Containers and alert counts |
| `alerts [--events] [--json] [--fail]` | Alerts (or every gateway decision); `--fail` exits 1 on critical alerts |
| `verify [--build] [--no-up]` | Run the in-container self-test and check the expected alerts |
| `config` | Effective configuration and paths |
| `doctor` | Check that the Docker daemon can run the configured runtime (`docker info`) |
| `down [--volumes]` | Stop the sandbox |

## Running a coding agent

Example with Claude Code
([`examples/claude-code.agent-sandbox.toml`](examples/claude-code.agent-sandbox.toml)):

```toml
[network]
allow = ["api.anthropic.com"]

[env]
pass = ["ANTHROPIC_API_KEY"]
```

```bash
agent-sandbox up --build
agent-sandbox run -- bash -lc 'npm config set prefix ~/.local && npm install -g @anthropic-ai/claude-code'
agent-sandbox run -- bash -lc '~/.local/bin/claude'
```

The root filesystem is read-only, so tools are installed under the home directory (a persistent
volume). `pip`, `npm` and `git` honor the proxy variables, and so does Node's built-in `fetch`:
the default image ships Node.js 22 LTS (from the official `node:22-bookworm-slim` image, pinned
by digest), and the Compose file sets `NODE_USE_ENV_PROXY=1`, which Node.js 22.21 and later need
to route `fetch` through `HTTPS_PROXY`. A custom `agent_image` with an older Node.js has `fetch`
ignore the proxy and fail to resolve names. Claude Code and other Node.js clients trust the
sandbox CA through `NODE_EXTRA_CA_CERTS` when TLS inspection is on.

## Defense in depth with tool-call-guard and mcp-security-scanner

The sandbox is the last line. [`examples/defense-in-depth/`](examples/defense-in-depth/README.md)
is a scripted, reproducible demo of one prompt-injection attack (a poisoned MCP tool
description and an attacker-written ticket that tell the agent to send `~/.aws/credentials` to
an attacker's host) and of how three layers catch it independently:
[mcp-security-scanner](https://gitlab.com/connorhack/tools/mcp-security-scanner) flags the
poisoned definitions before the server is connected;
[tool-call-guard](https://gitlab.com/connorhack/tools/tool-call-guard), driven through Claude
Code's real hook protocol, blocks the send and holds the shell command for an out-of-band
approval; and, with the guard bypassed, the sandbox raises the canary tripwire, refuses the
attacker's host and blocks the canary sent to an allowlisted host over inspected HTTPS.

```bash
examples/defense-in-depth/run.sh     # or run.ps1; needs Docker and checkouts of the two tools
```

## Configuration

`.agent-sandbox.toml` at the root of the workspace (optional; it contains no secrets):

```toml
[sandbox]
name = "my-project"                 # default: directory name
# agent_image = "my-registry/agent:1.0"  # custom image (must provide uid 1000)
runtime = "runc"                    # "runsc": run the agent under gVisor (see below)

[network]
allow = [
  "api.anthropic.com",
  "*.internal.example",
  "registry.example:8443",
  { host = "github.com", methods = ["GET", "HEAD"] },                         # read-only...
  { host = "github.com", methods = ["POST"], paths = ["/*/git-upload-pack"] }, # ...but clone/fetch
  { host = "repo.maven.apache.org", inspect = false },  # TLS passthrough under tls_inspect
]
extend_default_allow = true         # keep PyPI, npm and GitHub
default_ports = [80, 443]
subnet = "172.31.250.0/24"          # private IPv4, /28 or larger
tls_inspect = false                 # true: decrypt HTTPS to scan bodies and enforce method rules
undecodable_bodies = "allow"        # or "block"; default "block" with tls_inspect (see below)

[resources]
cpus = 2
memory = "4g"
pids = 512

[env]
pass = ["ANTHROPIC_API_KEY"]        # forwarded from the host shell
set = { TERM = "xterm-256color" }

[canaries]
kinds = ["aws", "ssh", "github", "dotenv", "netrc", "git", "url"]

[alerts]
webhook = "https://hooks.slack.com/services/..."   # optional
```

Allowlist entries are exact host names, `*.domain` for strict subdomains, or `host:port`. IP
literals are only allowed when listed explicitly. Names are ASCII (internationalized names in
punycode, `xn--...`) and matched without regard to case or a trailing dot; names ending with a
numeric label, which resolvers read as IPv4 addresses (`127.1`), are refused.

An entry can also be a table that limits what may be sent to the host, or exempts it from TLS
inspection:

| Key | Meaning |
|---|---|
| `host` | Same syntax as a string entry (`name`, `*.domain`, `name:port`) |
| `methods` | HTTP methods allowed, e.g. `["GET", "HEAD"]` (case-insensitive; `CONNECT` is not a valid value) |
| `paths` | Glob patterns matched against the request path without the query, e.g. `["/api/*"]` (`*` also matches `/`) |
| `inspect` | `false` relays HTTPS to the host as opaque TLS under `tls_inspect` (see [TLS passthrough](#tls-passthrough)); default `true` |

Rules only ever **narrow** access: once a table entry with `methods` or `paths` matches a
destination, a request to it must be permitted by at least one such entry, whatever plain string
entries (including the defaults) say. Several tables for the same host add up, which is how the
example above keeps `git clone` and `git fetch` working (they POST to `git-upload-pack`) while
`git push` (`git-receive-pack`), gists, issues and other writes are refused. A path containing
dot segments (also as `..;x`, `..%20` or `.. .`, which Tomcat and Windows servers read as `..`),
`//`, a backslash, a fragment, whitespace or control characters, non-ASCII bytes, escapes that
are not valid UTF-8 (overlong `%c0%ae`), `%u` escapes or an encoded `/`, `\`, `.`, `;`, `#`, `?`,
`%` or NUL never matches a path pattern, because servers may normalize it differently.

The gateway can only enforce these rules on requests it can read: always for plain HTTP, and for
HTTPS only with `tls_inspect = true`. Without inspection, HTTPS tunnels to a restricted host are
still allowed (the request inside is invisible), and `agent-sandbox up` prints a warning.

`inspect = false` loosens instead of narrowing: under `tls_inspect`, HTTPS to the matching
destinations is passed through uninspected. One such entry is enough, whatever other entries
for the same host say, and a wildcard covers subdomains only, as in the allowlist. Since nothing
inside a passthrough tunnel is visible, such an entry cannot have `methods` or `paths`, and it
cannot overlap an entry that has them (for example `*.github.com` passed through and
`api.github.com` limited to `GET`): both are configuration errors that name the entries.
Without `tls_inspect`, `inspect = false` has no effect and `agent-sandbox up` warns about it.
`agent-sandbox config` lists the passthrough hosts under `tls_passthrough`.

`undecodable_bodies` decides what happens to a request body the gateway cannot decode for
canary scanning (see [Content-Encoding](#content-encoding)): `"block"` refuses the request with
an `egress.undecodable_body` alert; `"allow"` forwards it, scanned as sent, and logs the same
kind as an event. The default is `"block"` with `tls_inspect = true`, since inspection is the
opt-in to content scanning, and `"allow"` without it, since HTTPS is not scanned at all then and
blocking plain HTTP alone would add friction without closing a channel.

## Security layers

### Container

| Setting | Why |
|---|---|
| `user: 1000:1000` | No root inside the container |
| `cap_drop: [ALL]` | No capabilities at all (no raw sockets, no chown, no mounts...) |
| `no-new-privileges` | setuid binaries cannot regain privileges |
| custom seccomp profile | See below |
| `read_only: true` + tmpfs `/tmp`, `/run` | The image cannot be modified; writes go to the workspace, the home volume or tmpfs |
| `pids_limit`, `mem_limit`, `cpus`, `nofile` | Fork bombs and runaway builds stay contained |
| `init: true` | Zombie reaping and signal forwarding |
| no Docker socket, no host network, no privileged mode | No path to the Docker daemon |
| `.git/hooks` and `.git/config` mounted read-only | The agent cannot plant hooks, `core.hooksPath` or `core.fsmonitor` that would later run **on the host** |

### seccomp

The profile is generated from Docker's default profile
(`src/agent_sandbox/docker/seccomp/moby-default.json`, vendored with its SHA-256) by
`python -m agent_sandbox.seccomp`, and a test fails if the committed profile drifts. On top of
the default it:

- removes `ptrace`, `process_vm_readv/writev`, `kcmp`, `pidfd_getfd`;
- removes namespace and mount primitives (`unshare`, `setns`, `mount`, `pivot_root`, `chroot`,
  the new mount API, `open_by_handle_at`...);
- removes `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_*`, keyring syscalls and host
  administration (`init_module`, `kexec_*`, `reboot`, `swapon`, `syslog`...);
- restricts `socket(2)` to `AF_UNIX`, `AF_INET`, `AF_INET6` and `AF_NETLINK`.

Debuggers such as `gdb` and `strace` do not work inside the sandbox as a result.

### gVisor (optional)

With `[sandbox] runtime = "runsc"` the agent container runs under [gVisor](https://gvisor.dev):
its system calls are served by gVisor's user-space kernel (the Sentry, written in Go) instead of
the host kernel. The Sentry runs under its own strict seccomp filter and needs far fewer host
system calls than the agent's programs would, so a kernel exploit has to break gVisor first.

```toml
[sandbox]
runtime = "runsc"     # default: "runc"
```

- **The seccomp profile still applies.** runsc ignores a container's seccomp profile unless it
  runs with `--oci-seccomp`; with that flag, the Sentry enforces the profile on the agent's
  processes. It stays on as defence in depth: system calls that gVisor implements itself
  (`ptrace`, `unshare`, `mount`, `keyctl`...) remain out of the agent's reach, so a bug in their
  implementation cannot be used against the Sentry, and the self-test means the same under both
  runtimes. `up`, `verify` and `doctor` read `docker info` and refuse to start when runsc is
  missing or registered without `--oci-seccomp`; they never fall back to runc. (When runsc is
  configured as a containerd shim, Docker does not report its flags: you get a warning, and the
  `dangerous syscalls return EPERM` check is what tells.)
- **gVisor release 20261012.0 or later.** Older releases ignore the `errnoRet` of OCI profile
  rules, so `clone3` fails with `EPERM` instead of `ENOSYS`, glibc does not fall back to `clone`,
  and no program can start a thread (Python raises `can't start new thread`, Node.js aborts).
  The `threads start` check catches it.
- **The gateway always runs under runc**, whatever the daemon's default runtime. Under runsc it
  breaks twice (tested with `verify`): gVisor's inotify only reports accesses made inside the
  same sandbox, so the tripwire never sees the agent open a canary file (no
  `canary.file_access` alert), and the gateway cannot resolve allowlisted names through
  Docker's embedded DNS server (see the next point), so every request fails with `502`. The
  gateway is trusted code that never runs anything from the agent, and it keeps its own
  hardening (no capabilities beyond the four it needs, read-only root, Docker's default seccomp
  profile).
- **DNS**: gVisor's network stack does not see the NAT rules that send `127.0.0.11` to Docker's
  embedded DNS server, so every lookup would time out and DNS tunnelling would go unnoticed.
  Under runsc the agent gets a read-only `/etc/resolv.conf` that points at the gateway's
  sinkhole instead.
- `verify` adds a check that the agent sees gVisor's kernel (`/proc/version`, release
  `4.19.0-gvisor`) and not the host's release. Like gVisor's own `dmesg` banner, it confirms
  the configuration; it is not a security boundary.

To install gVisor on a Linux host, follow the
[installation guide](https://gvisor.dev/docs/user_guide/install/) (apt repository, or the
release tarball checked against its `.sha512`), then register it with the flag and check:

```bash
sudo runsc install -- --oci-seccomp     # adds or updates the "runsc" entry in /etc/docker/daemon.json
sudo systemctl reload docker
agent-sandbox doctor                    # ends with: agent      runsc: ok
agent-sandbox verify --build
```

The apt package registers runsc on its own, without extra flags: run `runsc install` as above
afterwards. Other runsc flags (`--platform=kvm` on hosts with `/dev/kvm`, for example) go after
`--` in the same command.

**Compatibility and performance.** Under gVisor every system call costs more, and file system
and network operations go through the Sentry: builds, package installs and test suites that
start many processes are noticeably slower, while CPU-bound work runs at close to native speed. Indicative
timings from the end-to-end environment below (ptrace platform, which is slower than the
default systrap):

| Inside the agent container | runc | runsc (ptrace) |
|---|---|---|
| `python3 -c pass`, 20 times | 0.40 s | 1.80 s |
| `node -e 0`, 10 times | 1.05 s | 2.79 s |
| `find /usr -type f` | 0.06 s | 2.87 s |
| fork and exec `/bin/true`, 500 times | 0.87 s | 9.52 s |
| write 200 MiB to the `/tmp` tmpfs | 0.16 s | 0.25 s |

Most build and language tooling works: besides the self-test (Python and Node.js 22),
`git clone`, `pip install` and `npm install` through the gateway were checked under runsc. Programs that need system calls or `/proc` and `/sys` files gVisor does not
implement fail, see gVisor's [compatibility notes](https://gvisor.dev/docs/user_guide/compatibility/).
`/proc/version` and `uname` report gVisor's kernel, and a non-root write to a read-only path
fails with `EACCES` rather than `EROFS`.

**Docker Desktop.** Not supported. Docker Desktop's VM (WSL2 backend on Windows) runs every
process under a seccomp filter that already has a user-notification listener; gVisor's default
platform, systrap, needs a listener of its own, which the kernel refuses (`EBUSY`), and the
sandbox dies with `failed to create a syscall thread`. The ptrace platform works there but is
slow, the VM has no `/dev/kvm` for the KVM platform, and the runsc binary would have to live
inside a VM that Docker Desktop manages. Use Docker Engine on a Linux host
(or VM) for gVisor.

### Network

- **Internal network**: the agent has no route to the internet, and the bridge has no address for
  the host (`com.docker.network.bridge.inhibit_ipv4`), so host services listening on `0.0.0.0` are
  unreachable too.
- **Allowlist proxy**: only `CONNECT` and absolute `http://` requests to allowlisted `host:port`
  pairs are forwarded. The gateway resolves names itself and connects only to public addresses,
  so an allowlisted name that resolves to a private, loopback, link-local or cloud-metadata
  address is refused (DNS rebinding). For TLS tunnels, the server name in the ClientHello must
  match the `CONNECT` target; the whole ClientHello is reassembled first, so splitting it across
  packets or TLS records does not hide the name, and a ClientHello the gateway cannot parse
  strictly (over 64 KiB, inconsistent lengths, duplicate extensions, several server names) is
  refused, so a server never reads a name the gateway did not check. In every request the gateway can read, the
  `Host` header (and an absolute request target) must name the destination too, so a shared
  front end (CDN, load balancer) cannot be used to reach another backend (domain fronting).
- **Plaintext tunnels**: a non-TLS `CONNECT` tunnel that starts with an HTTP/1 request (Node's
  `fetch` tunnels even `http://` URLs) is relayed request by request like plain HTTP, so method
  and path rules, the `Host` check and body decoding apply. Other plaintext protocols are relayed
  as a byte stream and scanned as is.
- **Strict request parsing**: requests the gateway forwards are parsed strictly (no bare CR or LF,
  no control characters, no whitespace before a colon, no conflicting `Content-Length` and
  `Transfer-Encoding`, a `Content-Length` of ASCII digits and exactly `chunked` as
  `Transfer-Encoding`, none in HTTP/1.0, no exotic chunk sizes, a request target of visible
  ASCII without a fragment), so the gateway and the server cannot disagree about where a
  request ends. In a plaintext tunnel, anything a lenient server could take for a request
  (after empty lines, with a tab after the method) is parsed, and refused, rather than relayed
  unread.
- **DNS sinkhole**: every external lookup is answered `NXDOMAIN` and logged. The agent never needs
  DNS for the internet because the proxy resolves names; this closes DNS tunnelling.

### TLS inspection (optional)

With `[network] tls_inspect = true` the gateway becomes a TLS-terminating proxy for every HTTPS
tunnel:

1. On first start it creates a **per-sandbox CA** (EC P-256, ten years) in a volume that only the
   gateway mounts. The private key never leaves that volume; the agent receives the certificate
   alone. `agent-sandbox down --volumes` deletes it, and the next start creates a new one.
2. It publishes `ca.crt` and `ca-bundle.crt` (the gateway's system roots plus the sandbox CA) to a
   second volume, mounted **read-only** at `/etc/agent-sandbox/tls` in the agent, whose root
   filesystem stays read-only. `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
   `GIT_SSL_CAINFO` and `PIP_CERT` point at the bundle and `NODE_EXTRA_CA_CERTS` at the CA. The
   CA is trusted inside the sandbox only, never on the host.
3. For each `CONNECT`, after the allowlist and SNI checks (and unless the host is passed
   through, see [TLS passthrough](#tls-passthrough)), the gateway connects upstream with
   **full certificate verification** (system roots, host name check), then completes the
   agent's handshake with a leaf certificate for that name, minted with the `openssl` CLI on
   first use and cached in memory. A failed upstream verification is answered with a `502` and
   logged.
4. Only `http/1.1` is offered over ALPN, so every request can be parsed (see
   [HTTP/2 and WebSocket](#http2-and-websocket)). Each one gets the same treatment as plain HTTP:
   canary scanning of the request line, headers, body (decoded too, see
   [Content-Encoding](#content-encoding)) and trailers, method and path rules, and the `Host`
   check. Bodies up to 10 MiB are held until fully scanned, so a request carrying a canary never
   reaches the server; larger bodies (uploads, `git push`) are streamed with enough data held back
   that a canary is caught before any part of it leaves, and the server only sees a truncated
   request.

Verified end to end with `pip` (Debian's and a virtualenv's), `npm`, `git clone`, `curl`,
Python's `urllib` and Node's `fetch`. It is opt-in because it breaks clients that do not use the
bundle (see [Limitations](#limitations)); hosts those clients need can be passed through.

The certificates are minted with `openssl` commands that work the same with OpenSSL and LibreSSL
(no `-addext` or `-copy_extensions`; extensions come from configuration files). The gateway image
uses Debian's OpenSSL 3.0; the test suite also runs against LibreSSL, see
[Development](#development).

### TLS passthrough

Some clients cannot be pointed at the bundle: Java uses its own `cacerts` keystore, Rust
programs built with `rustls` and `webpki-roots` (and some Go binaries and CLIs) carry a
compiled-in root store, and others pin the server's certificate. Under inspection they fail with
`tls.client_rejected`. A host such a client needs can be marked `{ host = "...", inspect = false }`
in `[network] allow` (see [Configuration](#configuration)); a `CONNECT` tunnel to it is then
relayed as **opaque TLS**:

| Still enforced | Not enforced inside the tunnel |
|---|---|
| The allowlist (`host:port`), resolution to public addresses only | Canary scanning of requests: **a canary sent through a passthrough tunnel is not detected** |
| The ClientHello server name, when sent, must match the `CONNECT` target | Method and path rules (which is why they cannot be combined with `inspect = false`) |
| Canaries in the destination host name and in the `CONNECT` request | The `Host` check: domain fronting through a shared front end is possible again |
| | The HTTP/1.1-only policy: HTTP/2, gRPC and WebSocket work |

Each passthrough tunnel is logged as `egress.tls_passthrough` (host, port, server name, client)
instead of `egress.allowed`, and the passthrough hosts are listed in the `tls.inspection_enabled`
event at start-up, so uninspected traffic stays visible. Prefer making the client trust the
sandbox CA where it can: for Java, import `/etc/agent-sandbox/tls/ca.crt` with
`keytool -importcert` into a copy of `cacerts` in the home directory and point
`javax.net.ssl.trustStore` at it; Go programs and Rust programs built with `rustls-native-certs`
already read `SSL_CERT_FILE`. Keep passthrough entries to the hosts that need them and avoid
broad `*.` patterns.
`agent-sandbox verify` checks that the first passthrough host presents a certificate that chains
to the system roots, not to the sandbox CA, while the other HTTPS checks go to an inspected host.

### Content-Encoding

A canary inside a compressed request body does not appear in the bytes as sent, so every body
the gateway reads (plain HTTP, plaintext tunnels and, with `tls_inspect`, HTTPS) that carries a
`Content-Encoding` is also decoded and scanned:

- `gzip` (and `x-gzip`, including concatenated members) and `deflate` are decoded with the
  standard library, stacked up to three times (`Content-Encoding: deflate, gzip`). `deflate` is
  read zlib-wrapped when it starts with a zlib header and raw otherwise, as servers disagree; a
  body crafted to be valid both ways is refused.
- Decoding is streamed and bounded: output is produced 64 KiB at a time, and a body is refused
  once any layer decodes to more than 64 MiB, or to more than 100 times the bytes sent (past the
  first MiB). A decompression bomb costs the gateway little memory or CPU.
- For a streamed upload, a byte is only forwarded once everything a server could decode from the
  body up to that byte has been scanned, so a body refused half-way never hands the server part
  of a canary.
- Anything else is **undecodable**: `br`, `zstd`, `compress` or unknown codings, malformed or
  truncated data, and bodies over the limits. `[network] undecodable_bodies` decides whether
  such a request is refused (`415`, `413` or `400`, with an `egress.undecodable_body` alert) or
  forwarded scanned as sent. Brotli would need a third-party C extension in the gateway and
  zstd Python 3.14, for codings clients rarely use on requests.

### HTTP/2 and WebSocket

Under inspection the gateway speaks HTTP/1.1 only, and refuses the rest with an
`egress.protocol_refused` event and an answer clients understand:

| Client behavior | Gateway answer |
|---|---|
| Offers `h2` and `http/1.1` over ALPN (curl, Node, Go, Python, browsers) | `http/1.1` is selected; the client falls back without noticing |
| Offers `h2` only (gRPC and other HTTP/2-only clients) | TLS alert `no_application_protocol` |
| Sends the HTTP/2 preface without negotiation (prior knowledge, also in plaintext tunnels) | HTTP/2 `GOAWAY` with `HTTP_1_1_REQUIRED` |
| `Upgrade:` request (WebSocket, `h2c`) | `501` |

HTTP/2 was evaluated and left out on purpose. Translating it to HTTP/1.1 upstream (for example
with the pure-Python `h2` library) would only help clients that cannot fall back, and those are
mostly gRPC clients, which need HTTP/2 to the server as well (trailers carry the call status, and
gRPC servers do not speak HTTP/1.1). Proxying HTTP/2 end to end means two HTTP/2 state machines
with bridged flow control, a third-party parser (`h2`, `hpack`, `hyperframe`) in the gateway,
which is otherwise standard library only, and defenses the library does not provide against the
known HTTP/2 denial-of-service classes (rapid reset, CONTINUATION and HPACK floods, PING and
SETTINGS floods, flow-control stalls). Every request would end up in the same scanning pipeline,
so detection would not improve; only gRPC would start working. WebSocket frames are masked,
fragmented and possibly compressed per message (`permessage-deflate`), and the connection stays
open in both directions, so they cannot be held and scanned like a request body.

### Canary tokens

Generated per sandbox with realistic formats and planted in the agent's home directory:

| Kind | File | Values watched |
|---|---|---|
| `aws` | `~/.aws/credentials` | access key ID and secret key |
| `ssh` | `~/.ssh/id_ed25519` | fragments of the key body |
| `github` | `~/.config/gh/hosts.yml` | `ghp_` token |
| `dotenv` | `~/projects/billing-api/.env` | database password and API secret |
| `netrc` | `~/.netrc` | password |
| `git` | `~/.git-credentials` | `ghp_` token |
| `url` | `~/.config/internal/handbook.md` | internal hostname and API key |

They are detected:

- in request lines, headers and bodies of plain HTTP (including chunked bodies), in non-TLS
  `CONNECT` tunnels, in destination host names and in DNS query names;
- with `tls_inspect`, in request lines, headers, bodies and trailers of HTTPS requests to
  allowlisted hosts, after decryption (not to hosts passed through with `inspect = false`);
- in request bodies compressed with `gzip` or `deflate`, after decoding;
- plain or **encoded**: URL encoding, hex, base64 and base64url at every byte alignment, and
  base32/hex split across DNS labels;
- **wrapped**: whitespace and quoted-printable soft line breaks are ignored (the output of
  `base64`, MIME parts with `Content-Transfer-Encoding`, hex dumps), and data around percent
  escapes is also searched percent-decoded (partial or excessive URL encoding), however the
  data is split into reads, as long as a value spans at most 64 KiB once wrapped or padded;
- with an inotify **tripwire** on the files themselves: opening a canary file raises a warning
  (except `~/.netrc`, which curl and git read on their own).

A request carrying a canary is refused before it reaches the network.

## Alerts

```text
$ agent-sandbox alerts
2026-10-16T21:20:05.932+00:00  warning  canary.file_access     canary file ~/.aws/credentials (aws) was opened
2026-10-16T21:20:05.938+00:00  critical canary.exfiltration    canary aws (plain) found in request body to pypi.org
2026-10-16T21:20:05.983+00:00  critical canary.dns             canary aws (hex) found in DNS query
```

- `alerts.jsonl` (security-relevant) and `events.jsonl` (every allow/deny decision and DNS query)
  are written under `~/.agent-sandbox/projects/<project>/logs/`.
- Records include the canary id, kind and encoding, never the canary value or request bodies.
  Canary alerts carry `"tls": true` when the canary was found in decrypted HTTPS.
- `events.jsonl` also records each request relayed by an inspecting connection
  (`egress.request`: method, path without query, host), refusals by method or path rules
  (`egress.denied` with a `path`), failed upstream TLS verification (`egress.tls_error`),
  agent clients that rejected the sandbox CA (`tls.client_rejected`) and tunnels relayed
  without inspection to `inspect = false` hosts (`egress.tls_passthrough`, with the `sni`).
  The SHA-256 fingerprint of the sandbox CA, the `openssl` version and the passthrough hosts
  are logged at start-up (`tls.inspection_enabled`).
- Refused protocols (HTTP/2, WebSocket and other upgrades) are logged as
  `egress.protocol_refused` with the `protocol`, and bodies that could not be decoded as
  `egress.undecodable_body` with the `encoding`, the `reason` and the `action` taken. A canary
  found after decoding has an `encoding` such as `plain in gzip`.
- With `[alerts] webhook`, each alert is also POSTed as JSON (`{"text": ..., "alert": {...}}`,
  compatible with Slack incoming webhooks).
- `agent-sandbox alerts --fail` exits 1 if there is a critical alert, for use in scripts.

| Kind | Severity | Meaning |
|---|---|---|
| `canary.exfiltration` | critical | A canary value reached the proxy (request blocked) |
| `canary.dns` | critical | A canary value was encoded in a DNS query |
| `canary.file_access` | warning | A canary file was opened |
| `egress.sni_mismatch` | warning | TLS server name differs from the `CONNECT` target |
| `egress.malformed_hello` | warning | A TLS ClientHello could not be parsed strictly (oversized, two server names...) and was refused |
| `egress.host_mismatch` | warning | A request's `Host` header names another host than its connection |
| `egress.private_address` | warning | An allowlisted name resolved only to non-public addresses |
| `egress.undecodable_body` | warning | A request body could not be decoded for scanning and was refused |

## Threat model

**Assets**: the host (files, credentials, local services), the user's other projects, secrets the
agent can see, and the integrity of the workspace the user will later run.

**Adversary**: the coding agent itself, after prompt injection (a malicious README, issue or
dependency) or misbehaviour, with arbitrary code execution **inside** the container.

**Trust boundaries**: the host, the Docker daemon and the gateway container are trusted; everything
inside the agent container is not.

**Covered**:

| Threat | Mitigation |
|---|---|
| Exfiltration to arbitrary hosts | Internal network + allowlist proxy |
| Credentials sent to an allowlisted host over HTTPS | Canary scanning of decrypted requests (`tls_inspect`) |
| Credentials sent over HTTPS to a passthrough host (`inspect = false`) | **Not detected**: only the allowlist, public-address and SNI checks apply; every such tunnel is logged (`egress.tls_passthrough`) |
| Credentials compressed or wrapped to slip past scanning | `gzip`/`deflate` bodies decoded, wrapping and percent escapes normalized, undecodable bodies refused (`undecodable_bodies`) |
| Write actions on allowlisted services (gists, issues, pushes) | Method and path rules (HTTPS needs `tls_inspect`) |
| Domain fronting through allowlisted front ends | SNI and `Host` must match the destination |
| DNS tunnelling | DNS sinkhole |
| Credential harvesting and exfiltration of credentials | Canary tokens: tripwire on access, block and alert on egress |
| Reaching host or LAN services | No route, no host address on the bridge, private addresses refused by the gateway |
| Container escape via kernel interfaces | Capabilities dropped, no-new-privileges, seccomp; with `runtime = "runsc"`, gVisor's user-space kernel between the agent and the host kernel |
| Persistence in the image | Read-only root filesystem |
| Code that later runs on the host | `.git/hooks` and `.git/config` read-only |
| Resource exhaustion | CPU, memory, PID and file descriptor limits |

**Kernel attack surface**:

| | `runtime = "runc"` (default) | `runtime = "runsc"` (gVisor) |
|---|---|---|
| The agent's system calls reach | the host kernel, through the seccomp profile | the Sentry, through the same profile |
| The host kernel is reached by | the agent's processes | the Sentry and its file proxy, through gVisor's own seccomp filters |
| The agent's sockets are implemented by | the host kernel's network stack | gVisor's network stack, in user space; the host kernel only sees the packets it builds |
| An escape needs | one host kernel bug reachable through the profile | a Sentry bug, then a host kernel bug reachable from the Sentry's filtered system calls |

**Out of scope**: kernel vulnerabilities reachable through the allowed system calls under runc
(the agent shares the host kernel) and gVisor vulnerabilities under runsc; the gateway shares the
host kernel under both. Also out of scope: a compromised Docker daemon, and what the user does
with the code afterwards.

## Limitations

- **TLS inspection is off by default.** Without it the gateway sees host names and SNI for HTTPS,
  not requests: a canary inside an HTTPS request to an allowlisted host (for example a POST to
  `github.com`) is **not** detected, and method and path rules do not apply to HTTPS.
- **What TLS inspection does not cover**:
  - clients that pin certificates or ship their own root store and ignore the environment
    variables above (Java's `cacerts`, some Rust and Go binaries, mobile SDKs) fail to connect;
    the gateway logs `tls.client_rejected`. Their hosts can be passed through with
    `inspect = false`, which makes those hosts blind spots: see the next item;
  - HTTP/2 and HTTP/3 are not available (clients fall back to HTTP/1.1; gRPC and other
    HTTP/2-only clients fail), and WebSocket and other `Upgrade` requests are refused: see
    [HTTP/2 and WebSocket](#http2-and-websocket);
  - non-HTTP protocols inside TLS tunnels are refused, not scanned;
  - request bodies in `br`, `zstd` or other codings than `gzip` and `deflate` are not decoded:
    refused by default under inspection, scanned as sent with `undecodable_bodies = "allow"`;
  - responses are not scanned (they come from the allowlisted server, not from the agent).
- **TLS passthrough hosts are not inspected.** A canary, or anything else, sent inside a tunnel
  to an `inspect = false` host is **not** detected, method and path rules cannot apply to it,
  and a shared front end behind that name can route the request to another backend (domain
  fronting). Only the allowlist, the public-address check and the server name check apply. Each
  tunnel is logged as `egress.tls_passthrough`; keep these entries few and specific.
- **Allowlisted hosts are exfiltration channels** for anything that is not a canary: source code,
  or any data the agent can read, can be sent with every method and path the rules allow
  (an issue comment if `POST` is allowed, a package upload, any API with write access). Method
  and path rules narrow the channel; they do not close it. Keep the allowlist minimal, and do not
  forward credentials the agent does not need: everything in `[env] pass` can leave through an
  allowlisted host.
- **Path rules are textual**: patterns match the raw request path. Ambiguous paths are refused,
  but a server that routes the same path to different handlers (for example by a header) can
  still be reached through an allowed path.
- **Encoding coverage is finite**: encryption, custom encodings (a reversed or XORed value,
  JSON `\u` escapes, archives such as zip or tar.gz uploaded as a file) and compression the
  gateway does not decode defeat canary matching, and so does a value padded with more
  whitespace or escapes than the scanner holds back at a chunk boundary (three times the
  longest encoded value). Canaries are tripwires, not a guarantee.
- **Shared kernel (runc).** seccomp reduces the attack surface but a kernel exploit escapes any
  container. For stronger isolation, set `runtime = "runsc"` (gVisor); Kata Containers and other
  VM-based runtimes are not supported.
- **gVisor**: slower system calls and I/O, and not every system call is implemented (see
  [gVisor (optional)](#gvisor-optional)); it needs gVisor 20261012.0 or later registered with
  `--oci-seccomp`, and it does not work on Docker Desktop. The tripwire still sees the agent
  open a canary file, because gVisor opens the host file on the agent's behalf.
- **The workspace is writable.** The agent can change any file in your project, including build
  scripts, `package.json` scripts, `Makefile`, `.vscode/tasks.json` or `.envrc`, which run on the
  host when you use them. Review the diff before running anything the agent touched.
- **Tripwire noise**: tools that read every file in the home directory (`grep -r ~`, backup
  tools) trigger file-access warnings. They are warnings, not blocks.
- **Docker Desktop** runs containers in a VM; the protections apply inside that VM. On Linux
  hosts the gateway writes logs as root into your state directory.
- Debugging tools that need `ptrace` do not work.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest --cov                              # unit tests (no Docker needed)
ruff check src tests && ruff format --check src tests
python -m agent_sandbox.seccomp --check   # profile matches the generator
agent-sandbox -w /tmp/demo verify --build # end-to-end on a real Docker daemon
```

The security-critical parsers (HTTP/1 framing, Content-Encoding decoding, canary matching and
the stream scanner, ClientHello parsing, allowlist host and path matching) also have
property-based tests, `tests/test_fuzz_*.py`, written with
[Hypothesis](https://hypothesis.readthedocs.io/). They run a few dozen examples each with the
rest of the suite; the `fuzz` profile runs about 4,000 per property (a few minutes per file):

```bash
HYPOTHESIS_PROFILE=fuzz pytest tests/test_fuzz_*.py
```

A failure prints the smallest example found and a `@reproduce_failure` decorator; examples that
failed are replayed first on the next run (from `.hypothesis/`). Each bug they found is also kept
as a plain regression test next to the module's unit tests.

The certificate tests run once per OpenSSL-compatible binary they find: `openssl` on the `PATH`,
`/usr/bin/openssl` (LibreSSL on macOS) and every binary listed in `OPENSSL` (separated like
`PATH`), which must exist. On Alpine, for example:

```bash
apk add libressl && OPENSSL=/usr/bin/libressl pytest tests/test_tls_inspection.py -v
```

`gateway/certs.py` was checked this way with OpenSSL 3.5 and LibreSSL 3.3.6 (the release macOS
ships as `/usr/bin/openssl`, built from the portable tarball), 4.1.2 and 4.3.1 (Alpine 3.22 and
3.24 packages), in a throwaway Alpine container: the CA and leaf certificates have the same
extensions and serial numbers with every binary, and pass `openssl verify -x509_strict` and
Python's `VERIFY_X509_STRICT`. No command needed changing. CI keeps it so: the GitLab `libressl`
job runs the TLS tests with LibreSSL as the only `openssl`, and the GitHub macOS jobs require
them to run against `/usr/bin/openssl` too.

[`scripts/e2e-dind.sh`](scripts/e2e-dind.sh) runs `verify --build` under runsc and runc, with
and without TLS inspection, inside a privileged `docker:dind` container: it installs a pinned
gVisor release (SHA-512 checked) into that container's own Docker daemon, so the host daemon is
left alone. The CLI runs in the same container, where the bind mounts resolve:

```bash
docker run -d --privileged --name agent-sandbox-e2e -e DOCKER_TLS_CERTDIR= docker:29.8.1-dind
git archive HEAD | docker exec -i agent-sandbox-e2e sh -c 'mkdir /src && tar -xf - -C /src'
docker exec agent-sandbox-e2e sh /src/scripts/e2e-dind.sh /src   # GVISOR_PLATFORM=ptrace on Docker Desktop
docker rm -f -v agent-sandbox-e2e
```

CI: [`.gitlab-ci.yml`](.gitlab-ci.yml) runs lint, unit tests on Python 3.11-3.13, the TLS tests
against LibreSSL and validates the generated Compose file (and the defense-in-depth demo's);
the manual `gvisor-end-to-end` job runs the script above (it needs a privileged runner). The
end-to-end test also runs in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) (for a future GitHub mirror) and locally.

```text
src/agent_sandbox/
  cli.py              agent-sandbox ...
  config.py           .agent-sandbox.toml, state paths
  runtime.py          docker info check for the configured runtime (runc or runsc)
  compose.py          Compose spec (hardening, networks, mounts)
  canary.py           canary generation and encoded-value matching
  allowlist.py        host:port allowlist with method and path rules, TLS passthrough
  seccomp.py          profile generator (+ docker/seccomp/)
  selftest.py         in-container self-test (copied into the agent image)
  gateway/            proxy.py, http1.py (request parsing), tls.py (SNI, ALPN, server-side TLS),
                      certs.py (CA and leaf certificates), decoding.py (Content-Encoding),
                      dns.py, tripwire.py, alerts.py
  docker/             agent.Dockerfile, gateway.Dockerfile (base images pinned by digest)
tests/                unit tests for every module, property-based tests (test_fuzz_*.py)
examples/             configuration for running Claude Code in the sandbox, and the
                      defense-in-depth demo (scanner + guard + sandbox)
scripts/e2e-dind.sh   end-to-end self-test under gVisor and runc in Docker-in-Docker
```

## License

[Apache License 2.0](LICENSE).
