"""Sources and docs must not contain invisible or bidi characters; examples must load."""

import unicodedata
from pathlib import Path

import pytest

from agent_sandbox.config import load

ROOT = Path(__file__).resolve().parent.parent
SUFFIXES = {".py", ".json", ".toml", ".yml", ".yaml", ".md", ".Dockerfile"}
FILES = [
    *sorted(
        p
        for folder in ("src", "tests", "examples", ".github")
        for p in (ROOT / folder).rglob("*")
        if p.is_file() and (p.suffix in SUFFIXES or p.name.endswith(".Dockerfile"))
    ),
    *(
        p
        for p in (ROOT / "README.md", ROOT / "pyproject.toml", ROOT / ".gitlab-ci.yml")
        if p.exists()
    ),
]


def _hidden(ch: str) -> bool:
    return ch not in "\n\t\r" and unicodedata.category(ch) in {"Cc", "Cf", "Co", "Zl", "Zp"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_hidden_characters(path):
    text = path.read_text(encoding="utf-8")
    hidden = [
        (n, f"U+{ord(ch):04X}")
        for n, line in enumerate(text.splitlines(), 1)
        for ch in line
        if _hidden(ch)
    ]
    assert hidden == []


def test_example_config_loads(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    example = ROOT / "examples" / "claude-code.agent-sandbox.toml"
    (workspace / ".agent-sandbox.toml").write_text(example.read_text(encoding="utf-8"), "utf-8")
    config = load(workspace)
    assert "api.anthropic.com" in config.allow and config.env_pass == ("ANTHROPIC_API_KEY",)
