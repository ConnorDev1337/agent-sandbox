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


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[nope]\n", "unknown section"),
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
