"""Structured event and alert log (JSON Lines), with an optional webhook.

``events.jsonl`` records every gateway decision; ``alerts.jsonl`` only the
security-relevant ones. Records never contain canary values or request bodies.
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any, TextIO

SEVERITIES = ("info", "warning", "critical")
WEBHOOK_TIMEOUT = 5.0


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="milliseconds")


class EventLog:
    def __init__(
        self,
        directory: Path | None = None,
        *,
        webhook: str | None = None,
        stream: TextIO | None = sys.stdout,
    ) -> None:
        self.directory = directory
        self.webhook = webhook
        self.stream = stream
        self._lock = threading.Lock()
        if directory is not None:
            directory.mkdir(parents=True, exist_ok=True)

    def _append(self, name: str, record: dict[str, Any]) -> None:
        if self.directory is None:
            return
        with (self.directory / name).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def event(self, kind: str, **fields: Any) -> dict[str, Any]:
        record = {"ts": _now(), "kind": kind, **fields}
        with self._lock:
            self._append("events.jsonl", record)
        return record

    def alert(self, kind: str, severity: str, message: str, **fields: Any) -> dict[str, Any]:
        if severity not in SEVERITIES:
            raise ValueError(f"unknown severity {severity!r}")
        record = {"ts": _now(), "kind": kind, "severity": severity, "message": message, **fields}
        with self._lock:
            self._append("events.jsonl", record)
            self._append("alerts.jsonl", record)
            if self.stream is not None:
                self.stream.write(f"ALERT [{severity}] {kind}: {message}\n")
                self.stream.flush()
        if self.webhook:
            threading.Thread(target=self._notify, args=(record,), daemon=True).start()
        return record

    def _notify(self, record: dict[str, Any]) -> None:
        text = f"[agent-sandbox] {record['severity']}: {record['message']}"
        body = json.dumps({"text": text, "alert": record}).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - URL comes from the operator's config
            self.webhook or "",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT):  # noqa: S310
                pass
        except OSError as exc:
            self.event("alert.webhook_failed", error=str(exc))
