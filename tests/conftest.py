from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path, monkeypatch):
    """Keep sandbox state out of the developer's real ~/.agent-sandbox."""
    monkeypatch.setenv("AGENT_SANDBOX_HOME", str(tmp_path / "sandbox-home"))


@pytest.fixture
def workspace(tmp_path):
    path = tmp_path / "My Project"
    (path / ".git" / "hooks").mkdir(parents=True)
    (path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    return path
