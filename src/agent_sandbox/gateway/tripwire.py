"""Canary seeding and file-access tripwires.

The gateway writes the canary files into the agent's home volume before the
agent starts, then watches them with inotify. Reading a credential file the
agent was never asked to touch is an early sign of credential harvesting, so
it raises a warning; an actual exfiltration attempt is caught by the proxy.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import threading
import time
from pathlib import Path

from ..canary import Canary
from .alerts import EventLog

IN_ACCESS = 0x00000001
IN_OPEN = 0x00000020
IN_CLOEXEC = 0o2000000
EVENT_HEADER = struct.Struct("iIII")
DEBOUNCE_SECONDS = 60.0


def seed(home: Path, canaries: list[Canary], uid: int, gid: int) -> list[Path]:
    """Write canary files under ``home`` owned by ``uid:gid``; return their paths."""
    home.mkdir(parents=True, exist_ok=True)
    can_chown = hasattr(os, "chown") and os.geteuid() == 0  # type: ignore[attr-defined]
    written = []
    for canary in canaries:
        target = (home / canary.path).resolve()
        if home.resolve() not in target.parents:
            raise ValueError(f"canary path escapes the home directory: {canary.path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(canary.content, encoding="utf-8")
        target.chmod(canary.mode)
        if can_chown:
            for directory in [*reversed(target.relative_to(home).parents)][1:]:
                os.chown(home / directory, uid, gid)
                (home / directory).chmod(0o700)
            os.chown(target, uid, gid)
        written.append(target)
    if can_chown:
        os.chown(home, uid, gid)
    return written


def parse_events(buffer: bytes) -> list[tuple[int, int]]:
    """Decode ``(watch_descriptor, mask)`` pairs from an inotify read buffer."""
    events, offset = [], 0
    while offset + EVENT_HEADER.size <= len(buffer):
        wd, mask, _cookie, name_len = EVENT_HEADER.unpack_from(buffer, offset)
        events.append((wd, mask))
        offset += EVENT_HEADER.size + name_len
    return events


class Tripwire(threading.Thread):
    """Raise an alert when a planted canary file is opened or read."""

    def __init__(self, files: dict[Path, Canary], log: EventLog) -> None:
        super().__init__(name="tripwire", daemon=True)
        self.files = files
        self.log = log
        self._last: dict[Path, float] = {}

    def run(self) -> None:
        libc_name = ctypes.util.find_library("c")
        libc = ctypes.CDLL(libc_name, use_errno=True) if libc_name else None
        if libc is None or not hasattr(libc, "inotify_init1"):
            self.log.event("tripwire.unavailable", reason="inotify not supported")
            return
        fd = libc.inotify_init1(IN_CLOEXEC)
        if fd < 0:
            self.log.event("tripwire.unavailable", reason=os.strerror(ctypes.get_errno()))
            return
        watches = {}
        for path, canary in self.files.items():
            wd = libc.inotify_add_watch(fd, os.fsencode(path), IN_OPEN | IN_ACCESS)
            if wd >= 0:
                watches[wd] = (path, canary)
        self.log.event("tripwire.armed", files=len(watches))
        while True:
            buffer = os.read(fd, 64 * 1024)
            for wd, _mask in parse_events(buffer):
                if wd in watches:
                    self.triggered(*watches[wd])

    def triggered(self, path: Path, canary: Canary) -> None:
        now = time.monotonic()
        if now - self._last.get(path, -DEBOUNCE_SECONDS) < DEBOUNCE_SECONDS:
            return
        self._last[path] = now
        self.log.alert(
            "canary.file_access",
            "warning",
            f"canary file ~/{canary.path} ({canary.kind}) was opened",
            canary_id=canary.id,
            canary_kind=canary.kind,
            path=f"~/{canary.path}",
        )
