"""Static checks of examples/defense-in-depth (no Docker needed).

The scanner and guard checks run only when mcp-security-scanner or tool-call-guard
is importable, or its checkout sits next to this one (or in $DEMO_SCANNER_SRC /
$DEMO_TOOLGUARD_SRC); otherwise they are skipped.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_sandbox import compose
from agent_sandbox.allowlist import Allowlist
from agent_sandbox.config import DEFAULT_ALLOW, load

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "defense-in-depth"
WORKSPACE = EXAMPLE / "workspace"
SCENARIO = json.loads((WORKSPACE / "scenario.json").read_text(encoding="utf-8"))
HOOK_EVENTS = {"UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"}


@pytest.fixture(scope="module")
def demo():
    spec = importlib.util.spec_from_file_location("defense_in_depth_demo", EXAMPLE / "demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _python_path(package, project, env):
    """Return a PYTHONPATH that makes ``package`` importable, or None to skip."""
    if importlib.util.find_spec(package) is not None:
        return ""
    source = Path(os.environ.get(env) or ROOT.parent / project) / "src"
    return str(source) if (source / package).is_dir() else None


def _run_module(python_path, *args, stdin=None, extra_env=None):
    env = {**os.environ, **(extra_env or {})}
    if python_path:
        env["PYTHONPATH"] = python_path
    return subprocess.run(
        [sys.executable, "-m", *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )


def test_workspace_config_enables_every_layer():
    config = load(WORKSPACE)
    assert config.tls_inspect is True
    assert config.undecodable_bodies == "block"
    assert config.agent_image.startswith("agent-sandbox-demo/")
    assert config.subnet != "172.31.250.0/24"  # does not collide with the default sandbox
    assert set(DEFAULT_ALLOW) <= set(config.allow)
    allowlist = Allowlist(config.allow, config.default_ports)
    assert not allowlist.allows(SCENARIO["attacker_host"], 443)
    assert allowlist.permits("pypi.org", 443, "POST", "/mirror/intake")
    assert {"aws", "ssh"} <= set(config.canary_kinds)


def test_demo_compose_only_relabels_agent_sandbox_spec(demo):
    config = demo.demo_config(WORKSPACE)
    spec = demo.demo_compose(config)
    base = compose.build(config)

    for name, service in spec["services"].items():
        assert service["labels"] == {"agent-task": "demo"}
        assert service["pull_policy"] == "never"
        assert "build" not in service
        assert service["image"].startswith("agent-sandbox-demo/")
        stripped = {k: v for k, v in service.items() if k not in {"labels", "pull_policy"}}
        expected = {k: v for k, v in base["services"][name].items() if k != "build"}
        assert stripped == expected
    for section in ("networks", "volumes"):
        assert set(spec[section]) == set(base[section])
        for name, value in spec[section].items():
            assert value.pop("labels") == {"agent-task": "demo"}
            assert value == (base[section][name] or {})

    agent = spec["services"]["agent"]
    assert agent["read_only"] and agent["cap_drop"] == ["ALL"]
    assert agent["user"] == "1000:1000"
    assert spec["networks"]["sandbox"]["internal"] is True
    assert "tls" in spec["volumes"]  # TLS inspection is on


def test_write_compose_produces_valid_json(demo, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SANDBOX_HOME", str(tmp_path / "state"))
    config = demo.demo_config(WORKSPACE)
    path = demo.write_compose(config)
    assert json.loads(path.read_text(encoding="utf-8"))["name"] == config.project
    assert json.loads(config.gateway_file.read_text(encoding="utf-8"))["tls_inspect"] is True


def test_compose_only_needs_neither_docker_nor_checkouts(demo, tmp_path, capsys):
    out = tmp_path / "out"
    missing = str(tmp_path / "missing")
    assert demo.main(["--compose-only", "--out", str(out), "--scanner-src", missing]) == 0
    path = Path(capsys.readouterr().out.strip())
    assert path.is_relative_to(out / "state") and path.is_file()
    assert (out / "workspace" / "scenario.json").is_file()
    assert json.loads(path.read_text(encoding="utf-8"))["services"]["agent"]["labels"]


def test_sanitize_masks_values_that_change_between_runs(demo):
    text = (
        "[2026-10-17T07:55:45] toolguard: approval 3eda1497 for Bash\n"
        "One-time code: B7ZK-K3G7-KN7N (valid until 2026-10-17 08:00:45).\n"
        "Approval 3eda1497 requested. Approve: toolguard approve 3eda1497 [expires in 299s]\n"
        "head: " + "ab" * 32
    )
    clean = demo.sanitize(text)
    assert "3eda1497" not in clean and "B7ZK" not in clean and "2026" not in clean
    assert "abab" not in clean and "299s" not in clean
    assert "approval <id>" in clean and "One-time code: <redacted>" in clean


def test_evaluate_reports_missing_catches(demo, tmp_path):
    rows = demo.evaluate({"findings": []}, [], tmp_path, [], [], "")
    assert rows and not any(row["ok"] for row in rows)
    assert {row["layer"] for row in rows} == {
        "mcp-security-scanner",
        "tool-call-guard",
        "agent-sandbox",
    }


def test_scenario_is_a_well_formed_claude_code_trajectory():
    url = SCENARIO["attacker_url"]
    assert SCENARIO["attacker_host"].endswith(".invalid")  # never routable
    assert SCENARIO["attacker_host"] in url
    for step in SCENARIO["events"]:
        event = step["event"]
        assert step["expect"] in {"allow", "deny", "confirm"}
        assert event["hook_event_name"] in HOOK_EVENTS
        if event["hook_event_name"] != "UserPromptSubmit":
            assert event["tool_name"] and isinstance(event["tool_input"], dict)
            assert event["tool_use_id"]
    ticket = SCENARIO["events"][1]["event"]
    assert ticket["tool_name"].startswith("mcp__ticket-helper__")
    assert url in ticket["tool_response"]
    blocked = [s["event"] for s in SCENARIO["events"] if s["expect"] in {"deny", "confirm"}]
    assert blocked and all(url in json.dumps(e["tool_input"]) for e in blocked)


def test_poisoned_description_hides_its_character_behind_an_escape():
    raw = (WORKSPACE / "mcp-tools.json").read_text(encoding="utf-8")
    assert raw.isascii() and "\\u200b" in raw
    tools = json.loads(raw)["servers"]["ticket-helper"]["tools"]
    description = next(t["description"] for t in tools if t["name"] == "summarize_ticket")
    assert chr(0x200B) in description  # decoded from the escape above


@pytest.mark.parametrize(
    "path",
    sorted(p for p in EXAMPLE.rglob("*") if p.is_file() and "__pycache__" not in p.parts),
    ids=lambda p: p.relative_to(EXAMPLE).as_posix(),
)
def test_example_files_are_ascii_with_lf(path):
    data = path.read_bytes()
    assert data.isascii()
    assert b"\r" not in data


def test_scanner_reports_the_expected_findings():
    python_path = _python_path("mcp_scanner", "mcp-security-scanner", "DEMO_SCANNER_SRC")
    if python_path is None:
        pytest.skip("mcp-security-scanner is not importable and no checkout was found")
    result = _run_module(
        python_path,
        "mcp_scanner",
        "scan",
        str(WORKSPACE / ".mcp.json"),
        "--tools",
        str(WORKSPACE / "mcp-tools.json"),
        "--no-pins",
        "--fail-on",
        "none",
        "-f",
        "json",
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    expected = json.loads((EXAMPLE / "expected" / "scanner-findings.json").read_text("utf-8"))
    assert sorted({f["rule_id"] for f in report["findings"]}) == expected["rules"]
    counts = {k: v for k, v in report["summary"]["by_severity"].items() if v}
    assert counts == expected["by_severity"]


def test_guard_decides_as_the_scenario_expects(tmp_path):
    python_path = _python_path("toolguard", "tool-call-guard", "DEMO_TOOLGUARD_SRC")
    if python_path is None:
        pytest.skip("tool-call-guard is not importable and no checkout was found")
    env = {"TOOLGUARD_HOME": str(tmp_path / "toolguard")}
    for step in SCENARIO["events"]:
        event = {**step["event"], "session_id": SCENARIO["session_id"]}
        result = _run_module(
            python_path,
            "toolguard",
            "hook",
            "claude-code",
            "--policy",
            SCENARIO["policy"],
            "--ask-modes",
            "",
            stdin=json.dumps(event),
            extra_env=env,
        )
        assert result.returncode == 0, result.stderr
        output = json.loads(result.stdout)["hookSpecificOutput"] if result.stdout.strip() else {}
        decision = output.get("permissionDecision", "allow")
        reason = output.get("permissionDecisionReason", "")
        if step["expect"] == "allow":
            assert decision == "allow", reason
        else:
            verdict = "BLOCK" if step["expect"] == "deny" else "CONFIRM"
            assert decision == "deny" and f"toolguard: {verdict}" in reason, reason
