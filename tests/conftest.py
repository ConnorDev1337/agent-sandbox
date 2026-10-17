from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, settings

# Property-based tests run few examples by default, to keep the suite fast;
# HYPOTHESIS_PROFILE=fuzz runs many more (see "Development" in the README).
settings.register_profile("unit", max_examples=60, deadline=None, print_blob=True)
settings.register_profile(
    "fuzz",
    max_examples=4000,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "unit"))


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
