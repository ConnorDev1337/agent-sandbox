import json
import subprocess

import pytest

from agent_sandbox import cli
from agent_sandbox.canary import load_registry
from agent_sandbox.config import load


class FakeDocker:
    """Records docker invocations and returns scripted results."""

    def __init__(self):
        self.calls = []
        self.stdout = ""
        self.returncode = 0
        # What `docker info` reports; None makes it fail like an unreachable daemon.
        self.info = {
            "ServerVersion": "29.0.0",
            "OperatingSystem": "Test Linux",
            "KernelVersion": "6.8.0-test",
            "DefaultRuntime": "runc",
            "Runtimes": {"runc": {"path": "runc"}},
        }

    def __call__(self, command, check=True, text=True, capture_output=False, **kwargs):
        self.calls.append(command)
        if command[1] == "info":
            if self.info is None:
                raise subprocess.CalledProcessError(1, command, stderr="cannot connect")
            return subprocess.CompletedProcess(command, 0, json.dumps(self.info), "")
        if check and self.returncode:
            raise subprocess.CalledProcessError(self.returncode, command, stderr="boom")
        return subprocess.CompletedProcess(command, self.returncode, self.stdout, "")


@pytest.fixture
def docker(monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(cli.subprocess, "run", fake)
    return fake


def run(capsys, workspace, *argv):
    code = cli.main(["-w", str(workspace), *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_init_creates_state_and_keeps_canaries(capsys, workspace):
    code, out, _ = run(capsys, workspace, "init", "--write-config")
    assert code == 0 and "canaries   7" in out
    config = load(workspace)
    first = load_registry(config.canary_file)
    assert (workspace / ".agent-sandbox.toml").exists()
    run(capsys, workspace, "init")
    assert load_registry(config.canary_file) == first
    run(capsys, workspace, "init", "--rotate")
    assert load_registry(config.canary_file) != first


def test_up_down_and_exec_commands(capsys, workspace, docker):
    assert run(capsys, workspace, "up", "--build")[0] == 0
    up = docker.calls[-1]
    assert up[1:3] == ["compose", "-p"] and up[-4:] == ["up", "--build", "-d", "--wait"]
    assert run(capsys, workspace, "run", "--", "python3", "-V")[0] == 0
    assert docker.calls[-1][-5:] == ["exec", "-T", "agent", "python3", "-V"]
    assert run(capsys, workspace, "shell")[0] == 0
    assert docker.calls[-1][-2:] == ["bash", "-l"]
    assert run(capsys, workspace, "down", "--volumes")[0] == 0
    assert docker.calls[-1][-2:] == ["down", "--volumes"]
    assert run(capsys, workspace, "run")[0] == 2


def test_status_and_alerts(capsys, workspace, docker):
    config = load(workspace)
    assert "not initialized" in run(capsys, workspace, "status")[1]
    run(capsys, workspace, "init")
    alert = {"ts": "2026-01-01T00:00:00Z", "kind": "canary.exfiltration", "severity": "critical",
             "message": "canary aws (plain) found in request body"}  # fmt: skip
    (config.log_dir / "alerts.jsonl").write_text(
        json.dumps(alert) + "\nnot json\n", encoding="utf-8"
    )
    (config.log_dir / "events.jsonl").write_text(
        json.dumps({"ts": "t", "kind": "egress.denied", "host": "evil.example", "port": 443})
        + "\n",
        encoding="utf-8",
    )
    code, out, _ = run(capsys, workspace, "status")
    assert "1 critical" in out
    code, out, _ = run(capsys, workspace, "alerts", "--fail")
    assert code == 1 and "canary.exfiltration" in out
    code, out, _ = run(capsys, workspace, "alerts", "--events")
    assert "host=evil.example" in out
    code, out, _ = run(capsys, workspace, "alerts", "--json")
    assert json.loads(out.splitlines()[0])["severity"] == "critical"


def test_verify_reports_checks_and_expected_alerts(capsys, workspace, docker, monkeypatch):
    config = load(workspace)
    config.log_dir.mkdir(parents=True)
    docker.stdout = "\n".join(
        json.dumps({"check": name, "ok": True, "detail": "ok"}) for name in ("a", "b")
    )
    alerts = [
        {"ts": "9999-01-01T00:00:00Z", "kind": kind, "severity": "critical"}
        for kind in cli.EXPECTED_ALERTS
    ]
    (config.log_dir / "alerts.jsonl").write_text(
        "\n".join(json.dumps(a) for a in alerts) + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    code, out, _ = run(capsys, workspace, "verify")
    assert code == 0 and "5/5 checks passed" in out
    (config.log_dir / "alerts.jsonl").write_text("", encoding="utf-8")
    code, out, _ = run(capsys, workspace, "verify", "--no-up")
    assert code == 1 and "FAIL  gateway raised a canary.dns alert" in out
    docker.stdout = ""
    assert run(capsys, workspace, "verify", "--no-up")[0] == 2


def test_verify_with_tls_inspection_and_method_rules(capsys, workspace, docker, monkeypatch):
    (workspace / ".agent-sandbox.toml").write_text(
        '[network]\ntls_inspect = true\nallow = [{ host = "github.com", methods = ["GET"] }]\n',
        encoding="utf-8",
    )
    config = load(workspace)
    config.log_dir.mkdir(parents=True)
    docker.stdout = "\n".join(
        [
            json.dumps({"check": "a", "ok": True, "detail": "ok"}),
            json.dumps({"check": "b", "ok": True, "detail": "off", "skipped": True}),
        ]
    )
    alerts = [
        {"ts": "9999-01-01T00:00:00Z", "kind": kind, "severity": "critical"}
        for kind in cli.EXPECTED_ALERTS
    ]
    (config.log_dir / "alerts.jsonl").write_text(
        "\n".join(json.dumps(a) for a in alerts) + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    code, out, _ = run(capsys, workspace, "verify", "--no-up")
    selftest_call = docker.calls[-1]
    assert "--tls-inspect" in selftest_call
    assert selftest_call[-4:] == [
        "--restricted-host",
        "github.com",
        "--forbidden-method",
        "DELETE",
    ]
    assert (
        code == 1 and "FAIL  gateway raised a canary.exfiltration alert for decrypted TLS" in out
    )
    assert "SKIP  b" in out and "4/5 checks passed, 1 skipped" in out
    alerts.append({"ts": "9999-01-01T00:00:00Z", "kind": "canary.exfiltration", "tls": True})
    (config.log_dir / "alerts.jsonl").write_text(
        "\n".join(json.dumps(a) for a in alerts) + "\n", encoding="utf-8"
    )
    code, out, _ = run(capsys, workspace, "verify", "--no-up")
    assert code == 0 and "5/5 checks passed, 1 skipped" in out


@pytest.mark.parametrize(
    ("allow", "tls", "expected"),
    [
        ("[]", False, None),
        ('[{ host = "github.com", methods = ["GET", "POST"] }]', True, ("github.com", "DELETE")),
        ('[{ host = "*.example.com", methods = ["GET"] }]', True, None),
        ('[{ host = "a.example:8443", methods = ["GET"] }]', True, None),
        ('[{ host = "a.example", methods = ["DELETE", "PUT", "PATCH", "POST"] }]', False, None),
        ('[{ host = "a.example", paths = ["/api/*"] }]', False, ("a.example", "DELETE")),
    ],
)
def test_restricted_target(workspace, allow, tls, expected):
    (workspace / ".agent-sandbox.toml").write_text(
        f"[network]\ntls_inspect = {str(tls).lower()}\nallow = {allow}\n", encoding="utf-8"
    )
    assert cli._restricted_target(load(workspace)) == expected


def test_errors(capsys, workspace, docker, monkeypatch):
    docker.returncode = 1
    code, _, err = run(capsys, workspace, "up")
    assert code == 2 and "boom" in err
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    code, _, err = run(capsys, workspace, "up")
    assert code == 2 and "docker was not found" in err
    (workspace / ".agent-sandbox.toml").write_text("[nope]\n", encoding="utf-8")
    assert run(capsys, workspace, "config")[0] == 2


def test_rules_are_described_and_weak_settings_warned(capsys, workspace):
    (workspace / ".agent-sandbox.toml").write_text(
        '[network]\nallow = [{ host = "pypi.org", methods = ["GET"] }, "api.example.com"]\n',
        encoding="utf-8",
    )
    code, out, err = run(capsys, workspace, "init")
    assert code == 0 and "pypi.org [GET]" in out and "not inspected" in out
    assert "warning: network.allow" in err
    # pypi.org is read-only now, so the self-test must POST its canary elsewhere.
    assert cli._allowed_host(load(workspace)) == "files.pythonhosted.org"


def test_config_and_help(capsys, workspace):
    code, out, _ = run(capsys, workspace, "config")
    payload = json.loads(out)
    assert code == 0 and payload["gateway_ip"] == "172.31.250.2"
    assert payload["tls_inspect"] is False and payload["undecodable_bodies"] == "allow"
    assert cli.main([]) == 2


def use_runtime(workspace, runtime):
    (workspace / ".agent-sandbox.toml").write_text(
        f'[sandbox]\nruntime = "{runtime}"\n', encoding="utf-8"
    )


def register_runsc(docker, *args):
    docker.info["Runtimes"]["runsc"] = {"path": "/usr/local/bin/runsc", "runtimeArgs": [*args]}


def test_up_with_runsc_refuses_a_daemon_without_it(capsys, workspace, docker):
    use_runtime(workspace, "runsc")
    code, _, err = run(capsys, workspace, "up")
    assert code == 2 and "no runsc runtime" in err and "runsc install" in err
    assert [call[1] for call in docker.calls] == ["info"]  # nothing was started
    register_runsc(docker)
    code, _, err = run(capsys, workspace, "up")
    assert code == 2 and "without --oci-seccomp" in err
    docker.info = None
    code, _, err = run(capsys, workspace, "up")
    assert code == 2 and "cannot connect" in err


def test_up_with_runsc(capsys, workspace, docker):
    use_runtime(workspace, "runsc")
    register_runsc(docker, "--oci-seccomp")
    assert run(capsys, workspace, "up")[0] == 0
    assert docker.calls[-1][-3:] == ["up", "-d", "--wait"]
    spec = json.loads(load(workspace).compose_file.read_text(encoding="utf-8"))
    assert spec["services"]["agent"]["runtime"] == "runsc"
    assert spec["services"]["gateway"]["runtime"] == "runc"


def test_up_with_runc_tolerates_docker_info_failures(capsys, workspace, docker):
    docker.info = None
    assert run(capsys, workspace, "up")[0] == 0
    docker.info = {"Runtimes": {}}
    assert run(capsys, workspace, "up")[0] == 0
    docker.info = []
    assert run(capsys, workspace, "up")[0] == 0
    assert docker.calls[-1][-3:] == ["up", "-d", "--wait"]


def test_up_warns_when_runc_overrides_a_gvisor_default(capsys, workspace, docker):
    register_runsc(docker, "--oci-seccomp")
    docker.info["DefaultRuntime"] = "runsc"
    code, _, err = run(capsys, workspace, "up")
    assert code == 0 and "warning: the Docker daemon runs containers under runsc" in err


def test_verify_passes_the_runtime_to_the_self_test(capsys, workspace, docker, monkeypatch):
    use_runtime(workspace, "runsc")
    register_runsc(docker, "--oci-seccomp")
    docker.stdout = json.dumps({"check": "a", "ok": True, "detail": "ok"})
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    run(capsys, workspace, "verify")
    selftest_call = docker.calls[-1]
    assert "selftest.py" in selftest_call[selftest_call.index("agent") + 2]
    position = selftest_call.index("--runtime")
    assert selftest_call[position : position + 4] == [
        "--runtime",
        "runsc",
        "--host-kernel",
        "6.8.0-test",
    ]
    docker.info = None  # with --no-up and runc, verify does without the host kernel
    use_runtime(workspace, "runc")
    run(capsys, workspace, "verify", "--no-up")
    assert "--host-kernel" not in docker.calls[-1]
    assert docker.calls[-1][docker.calls[-1].index("--runtime") + 1] == "runc"


def test_doctor(capsys, workspace, docker):
    code, out, _ = run(capsys, workspace, "doctor")
    assert code == 0 and "29.0.0 (Test Linux)" in out and "agent      runc: ok" in out
    use_runtime(workspace, "runsc")
    code, _, err = run(capsys, workspace, "doctor")
    assert code == 2 and "no runsc runtime" in err
    register_runsc(docker, "--oci-seccomp")
    code, out, _ = run(capsys, workspace, "doctor")
    assert code == 0 and "runsc      /usr/local/bin/runsc --oci-seccomp" in out
    docker.info["Runtimes"]["runsc"] = {"runtimeType": "io.containerd.runsc.v1"}
    code, out, err = run(capsys, workspace, "doctor")
    assert code == 0 and "io.containerd.runsc.v1" in out and "cannot confirm" in err
    docker.info = None
    assert run(capsys, workspace, "doctor")[0] == 2


def test_runtime_in_init_and_config(capsys, workspace):
    use_runtime(workspace, "runsc")
    assert "runtime    runsc" in run(capsys, workspace, "init")[1]
    assert json.loads(run(capsys, workspace, "config")[1])["runtime"] == "runsc"
