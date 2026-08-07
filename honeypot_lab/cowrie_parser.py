"""Parse Cowrie JSON event logs into structured sessions."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .utils import parse_ts


@dataclass
class Session:
    session_id: str
    src_ip: str | None = None
    protocol: str | None = None
    dst_port: int | None = None
    sensor: str | None = None
    client_version: str | None = None
    start: str | None = None
    end: str | None = None
    duration: float | None = None
    login_attempts: list[dict[str, Any]] = field(default_factory=list)
    commands: list[dict[str, Any]] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return any(a.get("success") for a in self.login_attempts)

    @property
    def failed_logins(self) -> int:
        return sum(1 for a in self.login_attempts if not a.get("success"))


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    events.sort(key=lambda e: e.get("timestamp") or "")
    return events


def build_sessions(events: list[dict[str, Any]]) -> dict[str, Session]:
    sessions: dict[str, Session] = {}

    for ev in events:
        sid = ev.get("session") or "unknown"
        if sid not in sessions:
            sessions[sid] = Session(session_id=sid)
        s = sessions[sid]
        s.events.append(ev)
        s.src_ip = ev.get("src_ip") or s.src_ip
        s.sensor = ev.get("sensor") or s.sensor

        eid = ev.get("eventid", "")
        if eid == "cowrie.session.connect":
            s.start = ev.get("timestamp")
            s.protocol = ev.get("protocol") or s.protocol
            s.dst_port = ev.get("dst_port") or s.dst_port
        elif eid == "cowrie.client.version":
            s.client_version = ev.get("version")
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            s.login_attempts.append(
                {
                    "timestamp": ev.get("timestamp"),
                    "username": ev.get("username"),
                    "password": ev.get("password"),
                    "success": eid.endswith("success"),
                }
            )
        elif eid == "cowrie.command.input":
            s.commands.append(
                {
                    "timestamp": ev.get("timestamp"),
                    "input": ev.get("input", ""),
                }
            )
        elif eid == "cowrie.session.file_download":
            s.downloads.append(
                {
                    "timestamp": ev.get("timestamp"),
                    "url": ev.get("url"),
                    "outfile": ev.get("outfile"),
                    "shasum": ev.get("shasum"),
                }
            )
        elif eid == "cowrie.session.closed":
            s.end = ev.get("timestamp")
            s.duration = ev.get("duration")

    return sessions


def sessions_by_ip(sessions: dict[str, Session]) -> dict[str, list[Session]]:
    by_ip: dict[str, list[Session]] = defaultdict(list)
    for s in sessions.values():
        if s.src_ip:
            by_ip[s.src_ip].append(s)
    for ip in by_ip:
        by_ip[ip].sort(key=lambda x: parse_ts(x.start) or parse_ts("1970-01-01T00:00:00Z"))
    return dict(by_ip)


def summarize_events(events: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        counts[e.get("eventid", "unknown")] += 1
        if e.get("src_ip"):
            counts["unique_ips_placeholder"] = 0
    ips = {e.get("src_ip") for e in events if e.get("src_ip")}
    counts["unique_attacker_ips"] = len(ips)
    counts["total_events"] = len(events)
    return dict(counts)
