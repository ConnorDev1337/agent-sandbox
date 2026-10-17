# agent-sandbox

A hardened Docker sandbox for coding agents. The agent gets a container with no capabilities, a
tightened seccomp profile and a read-only root filesystem; its only way out is a gateway that
enforces a domain **allowlist** (optionally down to HTTP methods and paths); and its home
directory is seeded with **canary credentials** that raise an alert the moment they show up in
outbound traffic or DNS queries. With the opt-in **TLS inspection**, that includes the bodies of
HTTPS requests to allowlisted hosts.

```text
$ agent-sandbox verify          # with tls_inspect = true and a read-only rule for github.com
PASS  runs as a non-root user                                       uid=1000
PASS  no capabilities                                               CapEff=0000000000000000 CapBnd=0000000000000000
PASS  no_new_privs and seccomp filter active                        NoNewPrivs=1 Seccomp=2
PASS  root filesystem is read-only                                  Read-only file system
PASS  dangerous syscalls return EPERM                               all blocked
PASS  no direct route to the internet                               Network is unreachable
PASS  host is unreachable on the sandbox network                    no answer from 172.31.250.1
PASS  external DNS is sinkholed                                     [Errno -2] Name or service not known
PASS  allowlisted host reachable through the proxy                  status=200
PASS  other hosts are refused by the proxy                          status=None Tunnel connection failed: 403 blocked: example.com:443 is not in the allowlist
PASS  canary exfiltration is blocked                                status=403 agent-sandbox gateway: blocked: canary credential detected in outbound data
PASS  canary in a DNS query is caught by the sinkhole               query answered NXDOMAIN (alert expected on the host)
PASS  HTTPS is re-signed by the sandbox CA (TLS inspection)         pypi.org certificate issued by agent-sandbox
PASS  CA bundle is read-only and holds no private key               /etc/agent-sandbox/tls/ca-bundle.crt Read-only file system
PASS  canary in an HTTPS request body is blocked                    status=403 agent-sandbox gateway: blocked: canary credential detected in outbound data
PASS  forbidden HTTP method is refused                              DELETE https://github.com/ status=403 agent-sandbox gateway: blocked: DELETE / is not allowed for github.com
PASS  gateway raised a canary.exfiltration alert                    found
PASS  gateway raised a canary.dns alert                             found
PASS  gateway raised a canary.file_access alert                     found
PASS  gateway raised a canary.exfiltration alert for decrypted TLS  found

20/20 checks passed
```

Checks that the configuration does not enable are reported as `SKIP` (with the defaults:
15 checks pass and the four TLS inspection and method rule checks are skipped).

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Running a coding agent](#running-a-coding-agent)
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
pip install git+https://github.com/ConnorDev1337/agent-sandbox.git   # or: pip install -e . from a clone
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
volume). `pip`, `npm` and `git` honor the proxy variables; Node's built-in `fetch` does too
through `NODE_USE_ENV_PROXY=1` on Node.js 22.21 or later (the default image ships Node.js 18,
where `fetch` ignores the proxy and fails to resolve names). Claude Code and other Node.js clients
trust the sandbox CA through `NODE_EXTRA_CA_CERTS` when TLS inspection is on.

## Configuration

`.agent-sandbox.toml` at the root of the workspace (optional; it contains no secrets):

```toml
[sandbox]
name = "my-project"                 # default: directory name
# agent_image = "my-registry/agent:1.0"  # custom image (must provide uid 1000)

[network]
allow = [
  "api.anthropic.com",
  "*.internal.example",
  "registry.example:8443",
  { host = "github.com", methods = ["GET", "HEAD"] },                         # read-only...
  { host = "github.com", methods = ["POST"], paths = ["/*/git-upload-pack"] }, # ...but clone/fetch
]
extend_default_allow = true         # keep PyPI, npm and GitHub
default_ports = [80, 443]
subnet = "172.31.250.0/24"          # private IPv4, /28 or larger
tls_inspect = false                 # true: decrypt HTTPS to scan bodies and enforce method rules

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
literals are only allowed when listed explicitly.

An entry can also be a table that limits what may be sent to the host:

| Key | Meaning |
|---|---|
| `host` | Same syntax as a string entry (`name`, `*.domain`, `name:port`) |
| `methods` | HTTP methods allowed, e.g. `["GET", "HEAD"]` (case-insensitive; `CONNECT` is not a valid value) |
| `paths` | Glob patterns matched against the request path without the query, e.g. `["/api/*"]` (`*` also matches `/`) |

Rules only ever **narrow** access: once a table entry with `methods` or `paths` matches a
destination, a request to it must be permitted by at least one such entry, whatever plain string
entries (including the defaults) say. Several tables for the same host add up, which is how the
example above keeps `git clone` and `git fetch` working (they POST to `git-upload-pack`) while
`git push` (`git-receive-pack`), gists, issues and other writes are refused. A path containing
dot segments, `//`, a backslash or an encoded `/`, `.` or `\` never matches a path pattern,
because servers may normalize it differently.

The gateway can only enforce these rules on requests it can read: always for plain HTTP, and for
HTTPS only with `tls_inspect = true`. Without inspection, HTTPS tunnels to a restricted host are
still allowed (the request inside is invisible), and `agent-sandbox up` prints a warning.

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

### Network

- **Internal network**: the agent has no route to the internet, and the bridge has no address for
  the host (`com.docker.network.bridge.inhibit_ipv4`), so host services listening on `0.0.0.0` are
  unreachable too.
- **Allowlist proxy**: only `CONNECT` and absolute `http://` requests to allowlisted `host:port`
  pairs are forwarded. The gateway resolves names itself and connects only to public addresses,
  so an allowlisted name that resolves to a private, loopback, link-local or cloud-metadata
  address is refused (DNS rebinding). For TLS tunnels, the server name in the ClientHello must
  match the `CONNECT` target; the whole ClientHello is reassembled first, so splitting it across
  packets or TLS records does not hide the name. In every request the gateway can read, the
  `Host` header (and an absolute request target) must name the destination too, so a shared
  front end (CDN, load balancer) cannot be used to reach another backend (domain fronting).
- **Strict request parsing**: requests the gateway forwards are parsed strictly (no bare CR or LF,
  no whitespace before a colon, no conflicting `Content-Length` and `Transfer-Encoding`, no exotic
  chunk sizes), so the gateway and the server cannot disagree about where a request ends.
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
3. For each `CONNECT`, after the allowlist and SNI checks, the gateway connects upstream with
   **full certificate verification** (system roots, host name check), then completes the
   agent's handshake with a leaf certificate for that name, minted with the `openssl` CLI on
   first use and cached in memory. A failed upstream verification is answered with a `502` and
   logged.
4. Only `http/1.1` is offered over ALPN, so every request can be parsed. Each one gets the same
   treatment as plain HTTP: canary scanning of the request line, headers, body and trailers,
   method and path rules, and the `Host` check. Bodies up to 10 MiB are held until fully scanned,
   so a request carrying a canary never reaches the server; larger bodies (uploads, `git push`)
   are streamed with enough data held back that a canary is caught before any part of it leaves,
   and the server only sees a truncated request.

Verified end to end with `pip` (Debian's and a virtualenv's), `npm`, `git clone`, `curl` and
Python's `urllib`. It is opt-in because it breaks clients that do not use the bundle: see
[Limitations](#limitations).

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
  allowlisted hosts, after decryption;
- plain or **encoded**: URL encoding, hex, base64 and base64url at every byte alignment, and
  base32/hex split across DNS labels;
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
  (`egress.denied` with a `path`), failed upstream TLS verification (`egress.tls_error`) and
  agent clients that rejected the sandbox CA (`tls.client_rejected`). The SHA-256 fingerprint
  of the sandbox CA is logged at start-up (`tls.inspection_enabled`).
- With `[alerts] webhook`, each alert is also POSTed as JSON (`{"text": ..., "alert": {...}}`,
  compatible with Slack incoming webhooks).
- `agent-sandbox alerts --fail` exits 1 if there is a critical alert, for use in scripts.

| Kind | Severity | Meaning |
|---|---|---|
| `canary.exfiltration` | critical | A canary value reached the proxy (request blocked) |
| `canary.dns` | critical | A canary value was encoded in a DNS query |
| `canary.file_access` | warning | A canary file was opened |
| `egress.sni_mismatch` | warning | TLS server name differs from the `CONNECT` target |
| `egress.host_mismatch` | warning | A request's `Host` header names another host than its connection |
| `egress.private_address` | warning | An allowlisted name resolved only to non-public addresses |

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
| Write actions on allowlisted services (gists, issues, pushes) | Method and path rules (HTTPS needs `tls_inspect`) |
| Domain fronting through allowlisted front ends | SNI and `Host` must match the destination |
| DNS tunnelling | DNS sinkhole |
| Credential harvesting and exfiltration of credentials | Canary tokens: tripwire on access, block and alert on egress |
| Reaching host or LAN services | No route, no host address on the bridge, private addresses refused by the gateway |
| Container escape via kernel interfaces | Capabilities dropped, no-new-privileges, seccomp |
| Persistence in the image | Read-only root filesystem |
| Code that later runs on the host | `.git/hooks` and `.git/config` read-only |
| Resource exhaustion | CPU, memory, PID and file descriptor limits |

**Out of scope**: kernel vulnerabilities (the container shares the host kernel), a compromised
Docker daemon, and what the user does with the code afterwards.

## Limitations

- **TLS inspection is off by default.** Without it the gateway sees host names and SNI for HTTPS,
  not requests: a canary inside an HTTPS request to an allowlisted host (for example a POST to
  `github.com`) is **not** detected, and method and path rules do not apply to HTTPS.
- **What TLS inspection does not cover**:
  - clients that pin certificates or ship their own root store and ignore the environment
    variables above (Java's `cacerts`, some Rust and Go binaries, mobile SDKs) fail to connect;
    the gateway logs `tls.client_rejected`. There is no per-host bypass;
  - HTTP/2 and HTTP/3 are not available (clients fall back to HTTP/1.1; gRPC and other
    HTTP/2-only clients fail), and WebSocket and other `Upgrade` requests are refused;
  - non-HTTP protocols inside TLS tunnels are refused, not scanned;
  - compressed or encrypted request bodies (`Content-Encoding: gzip`, client-side encryption)
    are scanned as is, so a canary inside them is missed;
  - responses are not scanned (they come from the allowlisted server, not from the agent).
- **Allowlisted hosts are exfiltration channels** for anything that is not a canary: source code,
  or any data the agent can read, can be sent with every method and path the rules allow
  (an issue comment if `POST` is allowed, a package upload, any API with write access). Method
  and path rules narrow the channel; they do not close it. Keep the allowlist minimal, and do not
  forward credentials the agent does not need: everything in `[env] pass` can leave through an
  allowlisted host.
- **Path rules are textual**: patterns match the raw request path. Ambiguous paths are refused,
  but a server that routes the same path to different handlers (for example by a header) can
  still be reached through an allowed path.
- **Encoding coverage is finite**: compression, encryption or custom encodings defeat canary
  matching. Canaries are tripwires, not a guarantee.
- **Shared kernel.** seccomp reduces the attack surface but a kernel exploit escapes any
  container. For stronger isolation, run the agent under gVisor or Kata Containers.
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

CI: [`.gitlab-ci.yml`](.gitlab-ci.yml) runs lint, unit tests on Python 3.11-3.13 and validates the
generated Compose file. The end-to-end test needs bind mounts on the Docker host, so it runs in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) (for a future GitHub mirror) and locally.

```text
src/agent_sandbox/
  cli.py              agent-sandbox ...
  config.py           .agent-sandbox.toml, state paths
  compose.py          Compose spec (hardening, networks, mounts)
  canary.py           canary generation and encoded-value matching
  allowlist.py        host:port allowlist with method and path rules
  seccomp.py          profile generator (+ docker/seccomp/)
  selftest.py         in-container self-test (copied into the agent image)
  gateway/            proxy.py, http1.py (request parsing), tls.py (SNI, server-side TLS),
                      certs.py (CA and leaf certificates), dns.py, tripwire.py, alerts.py
  docker/             agent.Dockerfile, gateway.Dockerfile (base images pinned by digest)
tests/                unit tests for every module
examples/             configuration for running Claude Code in the sandbox
```

## License

[Apache License 2.0](LICENSE).
