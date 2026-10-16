# agent-sandbox

A hardened Docker sandbox for coding agents. The agent gets a container with no capabilities, a
tightened seccomp profile and a read-only root filesystem; its only way out is a gateway that
enforces a domain **allowlist**; and its home directory is seeded with **canary credentials** that
raise an alert the moment they show up in outbound traffic or DNS queries.

```text
$ agent-sandbox verify
PASS  runs as a non-root user                          uid=1000
PASS  no capabilities                                  CapEff=0000000000000000 CapBnd=0000000000000000
PASS  no_new_privs and seccomp filter active           NoNewPrivs=1 Seccomp=2
PASS  root filesystem is read-only                     Read-only file system
PASS  dangerous syscalls return EPERM                  all blocked
PASS  no direct route to the internet                  Network is unreachable
PASS  host is unreachable on the sandbox network       no answer from 172.31.250.1
PASS  external DNS is sinkholed                        [Errno -2] Name or service not known
PASS  allowlisted host reachable through the proxy     status=200
PASS  other hosts are refused by the proxy             status=None Tunnel connection failed: 403 blocked: example.com:443 is not in the allowlist
PASS  canary exfiltration is blocked                   status=403 agent-sandbox gateway: blocked: canary credential detected in outbound data
PASS  canary in a DNS query is caught by the sinkhole  query answered NXDOMAIN (alert expected on the host)
PASS  gateway raised a canary.exfiltration alert       found
PASS  gateway raised a canary.dns alert                found
PASS  gateway raised a canary.file_access alert        found

15/15 checks passed
```

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
  scans everything it can read for canary values.
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
through `NODE_USE_ENV_PROXY=1`.

## Configuration

`.agent-sandbox.toml` at the root of the workspace (optional; it contains no secrets):

```toml
[sandbox]
name = "my-project"                 # default: directory name
# agent_image = "my-registry/agent:1.0"  # custom image (must provide uid 1000)

[network]
allow = ["api.anthropic.com", "*.internal.example", "registry.example:8443"]
extend_default_allow = true         # keep PyPI, npm and GitHub
default_ports = [80, 443]
subnet = "172.31.250.0/24"          # private IPv4, /28 or larger

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
  match the `CONNECT` target (no domain fronting).
- **DNS sinkhole**: every external lookup is answered `NXDOMAIN` and logged. The agent never needs
  DNS for the internet because the proxy resolves names; this closes DNS tunnelling.

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
- With `[alerts] webhook`, each alert is also POSTed as JSON (`{"text": ..., "alert": {...}}`,
  compatible with Slack incoming webhooks).
- `agent-sandbox alerts --fail` exits 1 if there is a critical alert, for use in scripts.

| Kind | Severity | Meaning |
|---|---|---|
| `canary.exfiltration` | critical | A canary value reached the proxy (request blocked) |
| `canary.dns` | critical | A canary value was encoded in a DNS query |
| `canary.file_access` | warning | A canary file was opened |
| `egress.sni_mismatch` | warning | TLS server name differs from the `CONNECT` target |
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

- **No TLS inspection.** The gateway sees host names and SNI for HTTPS, not bodies. A canary sent
  inside an HTTPS request to an allowlisted host (for example a POST to `github.com`) is **not**
  detected. Plain HTTP, DNS, host names and file access are covered.
- **Allowlisted hosts are exfiltration channels** for anything that is not a canary: GitHub gists
  and issues, package publishing, any API with write access. Keep the allowlist minimal, and do not
  forward credentials the agent does not need: everything in `[env] pass` can leave through an
  allowlisted host.
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
  allowlist.py        host:port allowlist
  seccomp.py          profile generator (+ docker/seccomp/)
  selftest.py         in-container self-test (copied into the agent image)
  gateway/            proxy.py, dns.py, tripwire.py, tls.py, alerts.py, __main__.py
  docker/             agent.Dockerfile, gateway.Dockerfile (base images pinned by digest)
tests/                unit tests for every module
examples/             configuration for running Claude Code in the sandbox
```

## License

[Apache License 2.0](LICENSE).
