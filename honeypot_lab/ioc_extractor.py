"""Extract Indicators of Compromise (IOCs) from honeypot sessions."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .cowrie_parser import Session
from .utils import extract_ips, extract_urls


def extract_iocs(
    sessions: dict[str, Session],
    classifications: list[dict[str, Any]] | None = None,
    feed_hits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    class_by_sid = {c["session_id"]: c for c in (classifications or [])}
    ip_feed = {r["ip"]: r for r in (feed_hits or {}).get("ips", [])}
    url_feed = {r["url"]: r for r in (feed_hits or {}).get("urls", [])}
    hash_feed = {r["hash"]: r for r in (feed_hits or {}).get("hashes", [])}

    attacker_ips: dict[str, dict[str, Any]] = {}
    urls: dict[str, dict[str, Any]] = {}
    hashes: dict[str, dict[str, Any]] = {}
    usernames: Counter[str] = Counter()
    passwords: Counter[str] = Counter()
    commands: Counter[str] = Counter()
    user_agents: Counter[str] = Counter()

    for sid, s in sessions.items():
        clf = class_by_sid.get(sid, {})
        if s.src_ip:
            entry = attacker_ips.setdefault(
                s.src_ip,
                {
                    "type": "ipv4",
                    "value": s.src_ip,
                    "sessions": [],
                    "attack_types": set(),
                    "first_seen": s.start,
                    "last_seen": s.end or s.start,
                    "threat_feed": ip_feed.get(s.src_ip),
                },
            )
            entry["sessions"].append(sid)
            if clf.get("primary_type"):
                entry["attack_types"].add(clf["primary_type"])
            if s.start and (not entry["first_seen"] or s.start < entry["first_seen"]):
                entry["first_seen"] = s.start
            end = s.end or s.start
            if end and (not entry["last_seen"] or end > entry["last_seen"]):
                entry["last_seen"] = end

        if s.client_version:
            user_agents[s.client_version] += 1

        for attempt in s.login_attempts:
            if attempt.get("username"):
                usernames[attempt["username"]] += 1
            if attempt.get("password"):
                passwords[attempt["password"]] += 1

        for cmd in s.commands:
            text = (cmd.get("input") or "").strip()
            if text:
                commands[text] += 1
                for u in extract_urls(text):
                    urls.setdefault(
                        u,
                        {
                            "type": "url",
                            "value": u,
                            "sessions": [],
                            "threat_feed": url_feed.get(u),
                        },
                    )["sessions"].append(sid)
                for ip in extract_ips(text):
                    if ip == s.src_ip:
                        continue
                    attacker_ips.setdefault(
                        ip,
                        {
                            "type": "ipv4",
                            "value": ip,
                            "sessions": [],
                            "attack_types": {"referenced_in_command"},
                            "first_seen": cmd.get("timestamp"),
                            "last_seen": cmd.get("timestamp"),
                            "threat_feed": ip_feed.get(ip),
                            "note": "Observed inside attacker command",
                        },
                    )

        for d in s.downloads:
            u = d.get("url")
            if u:
                rec = urls.setdefault(
                    u,
                    {
                        "type": "url",
                        "value": u,
                        "sessions": [],
                        "threat_feed": url_feed.get(u),
                    },
                )
                if sid not in rec["sessions"]:
                    rec["sessions"].append(sid)
                rec["sha256"] = d.get("shasum")
            h = d.get("shasum")
            if h:
                hashes[h] = {
                    "type": "sha256",
                    "value": h,
                    "url": u,
                    "outfile": d.get("outfile"),
                    "sessions": [sid],
                    "threat_feed": hash_feed.get(h),
                }

    def _finalize_ip(entry: dict[str, Any]) -> dict[str, Any]:
        out = dict(entry)
        types = entry.get("attack_types") or set()
        out["attack_types"] = sorted(types) if isinstance(types, set) else list(types)
        out["session_count"] = len(entry.get("sessions") or [])
        return out

    ioc_list = (
        [_finalize_ip(v) for v in attacker_ips.values()]
        + list(urls.values())
        + list(hashes.values())
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "attacker_ips": len(attacker_ips),
            "urls": len(urls),
            "hashes": len(hashes),
            "unique_usernames": len(usernames),
            "unique_passwords": len(passwords),
            "unique_commands": len(commands),
        },
        "attacker_ips": [_finalize_ip(v) for v in sorted(attacker_ips.values(), key=lambda x: x["value"])],
        "urls": list(urls.values()),
        "file_hashes": list(hashes.values()),
        "top_usernames": usernames.most_common(15),
        "top_passwords": passwords.most_common(15),
        "top_commands": commands.most_common(20),
        "ssh_client_banners": user_agents.most_common(10),
        "ioc_flat": ioc_list,
    }
