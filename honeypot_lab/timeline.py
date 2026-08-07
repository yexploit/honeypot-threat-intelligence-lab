"""Build chronological attack timelines from Cowrie sessions."""

from __future__ import annotations

from typing import Any

from .cowrie_parser import Session
from .utils import parse_ts


def session_timeline(session: Session, classification: dict[str, Any] | None = None) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for ev in session.events:
        eid = ev.get("eventid", "")
        detail = ev.get("message") or ""
        if eid == "cowrie.command.input":
            detail = ev.get("input", detail)
        elif eid.startswith("cowrie.login"):
            detail = f"{ev.get('username')}/{'*' * len(ev.get('password') or '')}"
        elif eid == "cowrie.session.file_download":
            detail = ev.get("url") or detail
        events.append(
            {
                "timestamp": ev.get("timestamp"),
                "event": eid,
                "detail": detail,
            }
        )

    events.sort(key=lambda e: e.get("timestamp") or "")
    return {
        "session_id": session.session_id,
        "src_ip": session.src_ip,
        "protocol": session.protocol,
        "classification": (classification or {}).get("primary_type"),
        "automation": (classification or {}).get("automation"),
        "start": session.start,
        "end": session.end,
        "duration_seconds": session.duration,
        "events": events,
    }


def build_timelines(
    sessions: dict[str, Session],
    classifications: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    by_sid = {c["session_id"]: c for c in (classifications or [])}
    per_session = [session_timeline(s, by_sid.get(sid)) for sid, s in sessions.items()]
    per_session.sort(key=lambda t: t.get("start") or "")

    # Global chronological stream
    global_events: list[dict[str, Any]] = []
    for t in per_session:
        for ev in t["events"]:
            global_events.append(
                {
                    "timestamp": ev["timestamp"],
                    "src_ip": t["src_ip"],
                    "session_id": t["session_id"],
                    "classification": t["classification"],
                    "event": ev["event"],
                    "detail": ev["detail"],
                }
            )
    global_events.sort(key=lambda e: e.get("timestamp") or "")

    # Per-attacker condensed timelines
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for t in per_session:
        ip = t.get("src_ip") or "unknown"
        by_ip.setdefault(ip, []).append(
            {
                "session_id": t["session_id"],
                "start": t["start"],
                "end": t["end"],
                "classification": t["classification"],
                "event_count": len(t["events"]),
            }
        )

    return {
        "sessions": per_session,
        "global": global_events,
        "by_attacker": by_ip,
        "stats": {
            "sessions": len(per_session),
            "global_events": len(global_events),
            "attackers": len(by_ip),
        },
    }


def timeline_markdown(timelines: dict[str, Any]) -> str:
    lines = [
        "# Attack Timeline",
        "",
        f"Sessions: **{timelines['stats']['sessions']}** | "
        f"Events: **{timelines['stats']['global_events']}** | "
        f"Attackers: **{timelines['stats']['attackers']}**",
        "",
        "## Global Chronology",
        "",
        "| Timestamp (UTC) | Attacker IP | Session | Type | Event | Detail |",
        "|---|---|---|---|---|---|",
    ]
    for ev in timelines["global"]:
        detail = str(ev.get("detail") or "").replace("|", "\\|")
        if len(detail) > 80:
            detail = detail[:77] + "..."
        lines.append(
            f"| {ev.get('timestamp','')} | `{ev.get('src_ip','')}` | "
            f"`{ev.get('session_id','')}` | {ev.get('classification','')} | "
            f"{ev.get('event','')} | {detail} |"
        )

    lines.extend(["", "## By Attacker", ""])
    for ip, sessions in sorted(timelines["by_attacker"].items()):
        lines.append(f"### `{ip}`")
        for s in sessions:
            lines.append(
                f"- **{s['start']} → {s['end']}** — `{s['classification']}` "
                f"(session `{s['session_id']}`, {s['event_count']} events)"
            )
        lines.append("")
    return "\n".join(lines)
