"""Generate attacker behavior threat reports and defensive recommendations."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


def _defensive_recommendations(classifications: list[dict[str, Any]], iocs: dict[str, Any]) -> list[str]:
    types = {c.get("primary_type") for c in classifications}
    recs = [
        "Disable password authentication for SSH; enforce key-based auth and fail2ban/crowdsec.",
        "Never expose Telnet (TCP/23) on production systems; disable the service entirely.",
        "Rate-limit new SSH connections at the edge firewall and block known bad ASN ranges.",
        "Monitor outbound HTTP(S) from servers — unexpected wget/curl to unknown hosts is high-signal.",
        "Alert on execution from /tmp, /var/tmp, and hidden filenames (e.g. /tmp/.x).",
        "Keep an IOC watchlist from this lab and push to firewall / EDR deny lists.",
        "Segment management interfaces onto a VPN or jump-host VLAN (Honeynet-aligned isolation).",
    ]
    if "cryptominer_deployment" in types:
        recs.append("Detect mining pools (stratum) and high sustained CPU; block mining pool domains.")
    if "iot_botnet_propagation" in types:
        recs.append("Inventory IoT devices; change default credentials; block WAN access to device management ports.")
    if "defense_evasion" in types:
        recs.append("Forward logs to a remote SIEM immediately — local log deletion must not erase evidence.")
    if "manual_reconnaissance" in types:
        recs.append("Treat slow interactive SSH sessions after auth as potential hands-on-keyboard intrusions.")
    if iocs.get("attacker_ips"):
        recs.append(
            f"Block or geo-fence the {len(iocs['attacker_ips'])} attacker IPs extracted in this run "
            "(validate against false positives first)."
        )
    return recs


def generate_report(
    event_summary: dict[str, Any],
    classifications: list[dict[str, Any]],
    feed_corr: dict[str, Any],
    iocs: dict[str, Any],
    timelines: dict[str, Any],
    payloads: list[dict[str, Any]],
) -> dict[str, Any]:
    type_counts = Counter(c.get("primary_type") for c in classifications)
    auto_counts = Counter(c.get("automation") for c in classifications)

    return {
        "title": "Honeypot Threat Intelligence Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "PROJECT 5 - Honeypot Threat Intelligence Lab",
        "methodology": {
            "honeypot": "Cowrie (SSH/Telnet medium-interaction)",
            "siem": "ELK Stack (Elasticsearch, Logstash, Kibana)",
            "threat_feeds": feed_corr.get("summary", {}).get("feed_sources")
            or ["AbuseIPDB", "AlienVault OTX", "The Honeynet Project", "lab_offline_feeds"],
            "reference": "The Honeynet Project research practices",
        },
        "executive_summary": {
            "total_events": event_summary.get("total_events"),
            "unique_attacker_ips": event_summary.get("unique_attacker_ips"),
            "sessions_analyzed": len(classifications),
            "threat_feed_ips_listed": feed_corr.get("summary", {}).get("ips_listed"),
            "payloads_analyzed": len(payloads),
            "dominant_attack": type_counts.most_common(1)[0][0] if type_counts else None,
        },
        "attack_type_breakdown": dict(type_counts),
        "automation_breakdown": dict(auto_counts),
        "classifications": classifications,
        "threat_feed_correlation": feed_corr.get("summary"),
        "ioc_counts": iocs.get("counts"),
        "notable_attackers": [
            {
                "ip": ip["value"],
                "sessions": ip.get("session_count"),
                "types": ip.get("attack_types"),
                "feed": (ip.get("threat_feed") or {}).get("risk")
                or ((ip.get("threat_feed") or {}).get("offline_match") or {}).get("reputation"),
            }
            for ip in iocs.get("attacker_ips", [])
        ],
        "payload_findings": [
            {
                "filename": p["filename"],
                "risk": p["risk"],
                "indicators": p["indicators"],
                "sha256": p["sha256"],
            }
            for p in payloads
        ],
        "timeline_stats": timelines.get("stats"),
        "defensive_recommendations": _defensive_recommendations(classifications, iocs),
    }


def report_markdown(report: dict[str, Any]) -> str:
    ex = report["executive_summary"]
    lines = [
        f"# {report['title']}",
        "",
        f"**Generated:** {report['generated_at']}",
        f"**Project:** {report['project']}",
        "",
        "## 1. Executive Summary",
        "",
        f"- Events analyzed: **{ex['total_events']}**",
        f"- Unique attacker IPs: **{ex['unique_attacker_ips']}**",
        f"- Sessions: **{ex['sessions_analyzed']}**",
        f"- IPs listed on threat feeds: **{ex['threat_feed_ips_listed']}**",
        f"- Payloads analyzed: **{ex['payloads_analyzed']}**",
        f"- Dominant attack type: **{ex['dominant_attack']}**",
        "",
        "## 2. Methodology",
        "",
        f"- Honeypot: {report['methodology']['honeypot']}",
        f"- SIEM: {report['methodology']['siem']}",
        f"- Threat feeds: {', '.join(report['methodology']['threat_feeds'])}",
        f"- Reference: {report['methodology']['reference']}",
        "",
        "## 3. Attack Classification",
        "",
        "| Attack Type | Count |",
        "|---|---:|",
    ]
    for k, v in sorted(report["attack_type_breakdown"].items(), key=lambda x: -x[1]):
        lines.append(f"| `{k}` | {v} |")

    lines.extend(
        [
            "",
            "### Automation vs Manual",
            "",
            "| Mode | Count |",
            "|---|---:|",
        ]
    )
    for k, v in sorted(report["automation_breakdown"].items(), key=lambda x: -x[1]):
        lines.append(f"| {k} | {v} |")

    lines.extend(["", "## 4. Notable Attackers", "", "| IP | Sessions | Types | Feed Risk/Reputation |", "|---|---:|---|---|"])
    for a in report["notable_attackers"]:
        lines.append(
            f"| `{a['ip']}` | {a['sessions']} | {', '.join(a.get('types') or [])} | {a.get('feed') or '-'} |"
        )

    lines.extend(["", "## 5. Payload Analysis", "", "| File | Risk | Indicators | SHA256 |", "|---|---|---|---|"])
    for p in report["payload_findings"]:
        lines.append(
            f"| `{p['filename']}` | {p['risk']} | {', '.join(p['indicators'])} | `{p['sha256']}` |"
        )

    lines.extend(
        [
            "",
            "## 6. IOC Summary",
            "",
            f"- Attacker IPs: {report['ioc_counts'].get('attacker_ips')}",
            f"- URLs: {report['ioc_counts'].get('urls')}",
            f"- File hashes: {report['ioc_counts'].get('hashes')}",
            f"- Unique usernames tried: {report['ioc_counts'].get('unique_usernames')}",
            f"- Unique passwords tried: {report['ioc_counts'].get('unique_passwords')}",
            "",
            "## 7. Timeline Stats",
            "",
            f"- Sessions: {report['timeline_stats'].get('sessions')}",
            f"- Global events: {report['timeline_stats'].get('global_events')}",
            f"- Attackers: {report['timeline_stats'].get('attackers')}",
            "",
            "## 8. Defensive Recommendations",
            "",
        ]
    )
    for i, rec in enumerate(report["defensive_recommendations"], 1):
        lines.append(f"{i}. {rec}")

    lines.extend(
        [
            "",
            "## 9. Deliverables Produced",
            "",
            "- IOC database (`output/iocs/`)",
            "- Attacker behavior report (this file + JSON)",
            "- Attack timeline (`output/timelines/`)",
            "- Defensive recommendations (section 8)",
            "",
        ]
    )
    return "\n".join(lines)
