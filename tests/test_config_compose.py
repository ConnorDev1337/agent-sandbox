import json

import pytest

from agent_sandbox import compose
from agent_sandbox.config import DEFAULT_ALLOW, ConfigError, load
from agent_sandbox.seccomp import DENIED, allowed_names, harden, load_upstream
from agent_sandbox.seccomp import main as seccomp_main


def write_config(workspace, text):
    (workspace / ".agent-sandbox.toml").write_text(text, encoding="utf-8")


def test_defaults(workspace, tmp_path):
    config = load(workspace)
    assert config.name == "my-project"
    assert config.project.startswith("agent-sandbox-my-project-")
    assert config.allow == DEFAULT_ALLOW
    assert (config.gateway_ip, config.agent_ip) == ("172.31.250.2", "172.31.250.3")
    assert config.state_dir.is_relative_to(tmp_path / "sandbox-home")
    assert not config.state_dir.is_relative_to(workspace)  # agent must not see canaries


def test_custom_config(workspace):
    write_config(
        workspace,
        """
[sandbox]
name = "Demo!"
[network]
allow = ["api.anthropic.com", "*.internal.example:8443"]
extend_default_allow = false
subnet = "10.99.0.0/26"
[resources]
cpus = 1
memory = "2g"
pids = 128
[env]
pass = ["ANTHROPIC_API_KEY"]
set = { TERM = "xterm-256color" }
[canaries]
kinds = ["aws", "ssh"]
[alerts]
webhook = "https://hooks.example/abc"
""",
    )
    config = load(workspace)
    assert config.name == "demo"
    assert config.allow == ("api.anthropic.com", "*.internal.example:8443")
    assert config.gateway_ip == "10.99.0.2"
    assert config.canary_kinds == ("aws", "ssh")
    assert config.gateway_settings()["webhook"] == "https://hooks.example/abc"


def test_rule_tables_and_tls_inspect(workspace):
    write_config(
        workspace,
        """
[network]
tls_inspect = true
allow = [
  "api.anthropic.com",
  { host = "github.com", methods = ["GET", "HEAD"] },
  { host = "github.com", methods = ["POST"], paths = ["/*/git-upload-pack"] },
]
""",
    )
    config = load(workspace)
    assert config.tls_inspect is True and config.warnings() == []
    assert config.allow[-1] == {
        "host": "github.com",
        "methods": ["POST"],
        "paths": ["/*/git-upload-pack"],
    }
    settings = config.gateway_settings()
    assert settings["tls_inspect"] is True and settings["allow"][-2]["methods"] == ["GET", "HEAD"]
    assert settings["undecodable_bodies"] == "block"  # the default under inspection
    assert json.loads(json.dumps(settings)) == settings


@pytest.mark.parametrize(
    ("text", "policy"),
    [
        ("", "allow"),
        ("[network]\ntls_inspect = true\n", "block"),
        ('[network]\nundecodable_bodies = "block"\n', "block"),
        ('[network]\ntls_inspect = true\nundecodable_bodies = "allow"\n', "allow"),
    ],
)
def test_undecodable_bodies_policy(workspace, text, policy):
    write_config(workspace, text)
    assert load(workspace).gateway_settings()["undecodable_bodies"] == policy


def test_rules_without_inspection_warn(workspace):
    write_config(workspace, '[network]\nallow = [{ host = "github.com", methods = ["GET"] }]\n')
    config = load(workspace)
    assert config.tls_inspect is False
    (warning,) = config.warnings()
    assert "github.com [GET]" in warning and "tls_inspect" in warning


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[nope]\n", "unknown section"),
        ('[network]\ntls_inspect = "yes"\n', "true or false"),
        ('[network]\nundecodable_bodies = "drop"\n', '"block" or "allow"'),
        ("[network]\nallow = [1]\n", "strings or tables"),
        (
            '[network]\nallow = [{ host = "x.example", methods = ["BAD METHOD"] }]\n',
            "network.allow",
        ),
        ("[network]\ncolour = 1\n", "unknown key"),
        ('[network]\nallow = ["bad host"]\n', "network.allow"),
        ('[network]\nsubnet = "8.8.8.0/24"\n', "private IPv4"),
        ('[network]\nsubnet = "10.0.0.0/30"\n', "/28 or larger"),
        ('[network]\nsubnet = "nope"\n', "not a network"),
        ("[network]\ndefault_ports = [0]\n", "TCP ports"),
        ("[resources]\ncpus = 0\n", "cpus"),
        ('[resources]\nmemory = "lots"\n', "memory"),
        ("[resources]\npids = 4\n", "pids"),
        ('[env]\npass = ["BAD-NAME"]\n', "invalid environment variable"),
        ("[env]\nset = { A = 1 }\n", "env.set"),
        ('[canaries]\nkinds = ["vault"]\n', "unknown kind"),
        ('[alerts]\nwebhook = "ftp://x"\n', "http"),
        ("network = 1\n", "must be a table"),
        ("[network\n", "cannot read"),
    ],
)
def test_invalid_config(workspace, text, message):
    write_config(workspace, text)
    with pytest.raises(ConfigError, match=message):
        load(workspace)


def test_missing_workspace(tmp_path):
    with pytest.raises(ConfigError, match="not a directory"):
        load(tmp_path / "missing")


def test_compose_hardening(workspace):
    config = load(workspace)
    spec = compose.build(config)
    agent, gateway = spec["services"]["agent"], spec["services"]["gateway"]

    assert agent["cap_drop"] == ["ALL"] and "cap_add" not in agent
    assert agent["read_only"] is True and agent["user"] == "1000:1000"
    assert "no-new-privileges:true" in agent["security_opt"]
    assert any(
        opt.startswith("seccomp=") and opt.endswith("agent.json") for opt in agent["security_opt"]
    )
    assert agent["networks"] == {"sandbox": {"ipv4_address": config.agent_ip}}
    assert agent["dns"] == [config.gateway_ip]
    assert agent["environment"]["HTTPS_PROXY"] == f"http://{config.gateway_ip}:3128"
    assert spec["networks"]["sandbox"]["internal"] is True
    assert spec["networks"]["sandbox"]["driver_opts"] == {
        "com.docker.network.bridge.inhibit_ipv4": "true"
    }
    assert config.bridge_ip == "172.31.250.1"
    assert set(gateway["networks"]) == {"sandbox", "egress"}
    assert set(gateway["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER", "NET_BIND_SERVICE"}

    mounts = {m["target"]: m for m in agent["volumes"]}
    assert mounts["/workspace"]["read_only"] is False
    assert mounts["/workspace/.git/hooks"]["read_only"] is True
    assert mounts["/workspace/.git/config"]["read_only"] is True
    gateway_mounts = {m["target"]: m for m in gateway["volumes"]}
    assert gateway_mounts["/etc/agent-sandbox/canaries.json"]["read_only"] is True
    assert all("canaries" not in m.get("source", "") for m in agent["volumes"])


def test_compose_env_passthrough_and_no_git(tmp_path):
    workspace = tmp_path / "plain"
    workspace.mkdir()
    (workspace / ".agent-sandbox.toml").write_text('[env]\npass = ["API_KEY"]\n', encoding="utf-8")
    agent = compose.build(load(workspace))["services"]["agent"]
    assert agent["environment"]["API_KEY"] is None
    assert [m["target"] for m in agent["volumes"]] == ["/workspace", "/home/agent"]


def test_compose_write(workspace):
    config = load(workspace)
    path = compose.write(config)
    assert json.loads(path.read_text(encoding="utf-8"))["name"] == config.project
    assert json.loads(config.gateway_file.read_text(encoding="utf-8"))["allow"] == list(
        DEFAULT_ALLOW
    )
    assert config.log_dir.is_dir()


def test_seccomp_profile_is_hardened_and_current():
    upstream = load_upstream()
    hardened = harden(upstream)
    allowed = allowed_names(hardened)
    assert not allowed & DENIED
    assert {"read", "write", "openat", "clone", "execve", "connect"} <= allowed
    families = sorted(
        r["args"][0]["value"] for r in hardened["syscalls"] if r["names"] == ["socket"]
    )
    assert families == [1, 2, 10, 16]
    assert hardened["defaultAction"] == "SCMP_ACT_ERRNO"
    assert seccomp_main(["--check"]) == 0  # the committed profile matches the generator


def test_seccomp_rejects_unexpected_upstream(tmp_path):
    fake = tmp_path / "default.json"
    fake.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        load_upstream(fake)


def test_compose_without_tls_inspection_has_no_ca(workspace):
    spec = compose.build(load(workspace))
    agent = spec["services"]["agent"]
    assert set(spec["volumes"]) == {"home"}
    assert not {"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"} & set(agent["environment"])


def test_compose_with_tls_inspection_keeps_the_ca_key_in_the_gateway(workspace):
    write_config(workspace, "[network]\ntls_inspect = true\n")
    spec = compose.build(load(workspace))
    agent, gateway = spec["services"]["agent"], spec["services"]["gateway"]
    assert set(spec["volumes"]) == {"home", "ca", "tls"}
    gateway_mounts = {m["target"]: m["source"] for m in gateway["volumes"]}
    assert gateway_mounts[compose.GATEWAY_CA_DIR] == "ca"
    assert gateway_mounts[compose.GATEWAY_TLS_DIR] == "tls"
    agent_mounts = {m["target"]: m for m in agent["volumes"]}
    assert agent_mounts[compose.AGENT_TLS_DIR] == {
        "type": "volume",
        "source": "tls",
        "target": compose.AGENT_TLS_DIR,
        "read_only": True,
    }
    assert all(m.get("source") != "ca" for m in agent["volumes"])
    assert agent["read_only"] is True
    env = agent["environment"]
    bundle = f"{compose.AGENT_TLS_DIR}/ca-bundle.crt"
    assert all(env[name] == bundle for name in compose.CA_BUNDLE_VARIABLES)
    assert env["NODE_EXTRA_CA_CERTS"] == f"{compose.AGENT_TLS_DIR}/ca.crt"


def test_runtime_defaults_to_runc_and_gateway_stays_on_runc(workspace):
    config = load(workspace)
    assert config.runtime == "runc"
    services = compose.build(config)["services"]
    assert services["agent"]["runtime"] == "runc"
    assert services["gateway"]["runtime"] == compose.GATEWAY_RUNTIME == "runc"


def test_runsc_runtime_keeps_the_seccomp_profile(workspace):
    write_config(workspace, '[sandbox]\nruntime = "runsc"\n')
    services = compose.build(load(workspace))["services"]
    agent = services["agent"]
    assert agent["runtime"] == "runsc" and services["gateway"]["runtime"] == "runc"
    # gVisor enforces the profile itself (runsc --oci-seccomp): defence in depth.
    assert any(opt.startswith("seccomp=") for opt in agent["security_opt"])
    assert agent["cap_drop"] == ["ALL"] and agent["read_only"] is True


@pytest.mark.parametrize("value", ['"kata"', '"RUNSC"', "1"])
def test_invalid_runtime(workspace, value):
    write_config(workspace, f"[sandbox]\nruntime = {value}\n")
    with pytest.raises(ConfigError, match=r"sandbox\.runtime must be one of: runc, runsc"):
        load(workspace)


def test_runsc_agent_resolves_names_through_the_gateway_only(workspace):
    write_config(workspace, '[sandbox]\nruntime = "runsc"\n')
    config = load(workspace)
    agent = compose.build(config)["services"]["agent"]
    mounts = {m["target"]: m for m in agent["volumes"]}
    assert mounts["/etc/resolv.conf"] == {
        "type": "bind",
        "source": str(config.resolv_file),
        "target": "/etc/resolv.conf",
        "read_only": True,
    }
    compose.write(config)
    resolv = config.resolv_file.read_bytes().decode("ascii")
    assert resolv.splitlines()[1:] == ["nameserver 172.31.250.2", "options ndots:0"]
    assert "\r" not in resolv


def test_runc_agent_keeps_dockers_resolver(workspace):
    config = load(workspace)
    compose.write(config)
    agent = compose.build(config)["services"]["agent"]
    assert "/etc/resolv.conf" not in {m["target"] for m in agent["volumes"]}
    assert not config.resolv_file.exists()
