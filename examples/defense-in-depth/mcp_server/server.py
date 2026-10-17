#!/usr/bin/env python3
"""A tiny, intentionally insecure MCP server for the defense-in-depth demo.

It speaks the stdio JSON-RPC transport well enough for ``mcp-scanner --introspect``
and a real MCP client: ``initialize``, ``tools/list``, ``prompts/list``,
``resources/list``, ``resources/templates/list`` and ``tools/call``. Its tool,
prompt and resource definitions are loaded from ``mcp-tools.json`` in the demo
workspace, which is the single source of truth (including the one poisoned tool
description the scanner flags). Standard library only.

This server exists for the documented optional "live" section; the automated demo
scans the offline manifest and never executes it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "workspace" / "mcp-tools.json"


def _load_definitions(manifest: Path) -> dict[str, Any]:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    entry = next(iter(data["servers"].values()))
    return {
        "instructions": entry.get("instructions", ""),
        "tools": entry.get("tools", []),
        "prompts": entry.get("prompts", []),
        "resources": entry.get("resources", []),
        "resourceTemplates": entry.get("resourceTemplates", []),
    }


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Return a canned result for a tool call (no real side effects)."""
    if name == "get_ticket":
        issue = Path(__file__).resolve().parent.parent / "workspace" / "issue.txt"
        text = issue.read_text(encoding="utf-8") if issue.exists() else "TICKET not found."
        return {"content": [{"type": "text", "text": text}]}
    if name == "summarize_ticket":
        return {
            "content": [{"type": "text", "text": "The login button bug is being investigated."}]
        }
    return {"content": [{"type": "text", "text": f"{name}: nothing to do in the demo."}]}


def handle(message: dict[str, Any], defs: dict[str, Any]) -> dict[str, Any] | None:
    """Dispatch one JSON-RPC request; return a response, or None for a notification."""
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        return _result(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                "serverInfo": {"name": "ticket-helper", "version": "0.3.1"},
                "instructions": defs["instructions"],
            },
        )
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "tools/list":
        return _result(request_id, {"tools": defs["tools"]})
    if method == "prompts/list":
        return _result(request_id, {"prompts": defs["prompts"]})
    if method == "resources/list":
        return _result(request_id, {"resources": defs["resources"]})
    if method == "resources/templates/list":
        return _result(request_id, {"resourceTemplates": defs["resourceTemplates"]})
    if method == "tools/call":
        params = message.get("params") or {}
        return _result(
            request_id, _call_tool(params.get("name", ""), params.get("arguments") or {})
        )
    if request_id is None:
        return None
    return _error(request_id, -32601, f"method not found: {method}")


def main() -> int:
    defs = _load_definitions(DEFAULT_MANIFEST)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        response = handle(message, defs)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
