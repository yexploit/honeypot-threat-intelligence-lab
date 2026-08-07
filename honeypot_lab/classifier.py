"""Classify honeypot attack sessions into threat types."""

from __future__ import annotations

import re
from typing import Any

from .cowrie_parser import Session

# Heuristic signatures (defensive classification of observed attacker behavior)
BOTNET_PATTERNS = [
    r"mirai",
    r"busybox\s+wget",
    r"bot\.arm",
    r"/bins/",
    r"chmod\s+777",
    r"\.x86|\.arm|\.mips",
]
MINER_PATTERNS = [
    r"xmrig",
    r"minexmr",
    r"stratum",
    r"monero",
    r"cryptonight",
    r"pool\.",
]
PERSISTENCE_PATTERNS = [
    r"crontab",
    r"systemctl",
    r"rc\.local",
    r"@reboot",
]
DEFENSE_EVASION = [
    r"iptables\s+-F",
    r"rm\s+-rf\s+/var/log",
    r"history\s+-c",
    r"unset\s+HISTFILE",
]
RECON_COMMANDS = [
    r"^uname",
    r"^whoami",
    r"^ps\s",
    r"^netstat",
    r"^free\s",
    r"^cat\s+/etc/passwd",
    r"^cat\s+/proc/cpuinfo",
    r"^find\s+/",
    r"^ls\s",
    r"^history$",
]


def _match_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def classify_session(session: Session) -> dict[str, Any]:
    cmds = "\n".join(c.get("input", "") for c in session.commands)
    urls = " ".join(d.get("url") or "" for d in session.downloads)
    blob = f"{cmds}\n{urls}\n{session.client_version or ''}"

    labels: list[str] = []
    confidence = 0.4
    automation = "unknown"
    notes: list[str] = []

    failed = session.failed_logins
    if failed >= 5 and not session.success:
        labels.append("credential_stuffing")
        confidence = max(confidence, 0.75)
        automation = "automated"
        notes.append(f"{failed} failed logins, no successful auth")
    elif failed >= 3 and session.success:
        labels.append("ssh_bruteforce")
        confidence = max(confidence, 0.8)
        automation = "automated"
        notes.append(f"bruteforce then success ({failed} prior fails)")
    elif failed >= 1 and not session.success:
        labels.append("auth_probe")
        confidence = max(confidence, 0.55)
        automation = "automated"

    if _match_any(blob, BOTNET_PATTERNS) or any("mirai" in (d.get("url") or "").lower() for d in session.downloads):
        labels.append("iot_botnet_propagation")
        confidence = max(confidence, 0.9)
        automation = "automated"
        notes.append("Mirai/IoT botnet tooling indicators")

    if _match_any(blob, MINER_PATTERNS):
        labels.append("cryptominer_deployment")
        confidence = max(confidence, 0.92)
        automation = "automated"
        notes.append("Cryptominer / mining-pool indicators")

    if _match_any(blob, PERSISTENCE_PATTERNS):
        labels.append("persistence")
        confidence = max(confidence, 0.7)
        notes.append("Persistence mechanism attempted")

    if _match_any(blob, DEFENSE_EVASION):
        labels.append("defense_evasion")
        confidence = max(confidence, 0.75)
        notes.append("Log wiping / firewall flush")

    if session.downloads:
        labels.append("malware_download")
        confidence = max(confidence, 0.85)
        if automation == "unknown":
            automation = "automated"

    recon_hits = sum(1 for c in session.commands if _match_any(c.get("input", ""), RECON_COMMANDS))
    if recon_hits >= 4 and not session.downloads and "cryptominer_deployment" not in labels:
        labels.append("manual_reconnaissance")
        confidence = max(confidence, 0.7)
        automation = "likely_manual"
        notes.append(f"{recon_hits} recon commands, human-like pacing")

    # Client fingerprint hints
    ver = (session.client_version or "").lower()
    if "libssh" in ver or "paramiko" in ver:
        automation = "automated"
        notes.append(f"scripted SSH client: {session.client_version}")
    elif "openssh" in ver and automation == "unknown":
        automation = "likely_manual"
        notes.append(f"interactive OpenSSH client: {session.client_version}")

    # Fast command bursts with downloads => automated even without banner
    if session.downloads and session.duration is not None and session.duration < 20:
        automation = "automated"

    if session.protocol == "telnet":
        labels.append("telnet_abuse")
        notes.append("Telnet channel used (common for IoT bots)")

    if not labels:
        labels.append("unclassified_session")
        confidence = 0.3

    # Primary label = highest-severity preference
    priority = [
        "iot_botnet_propagation",
        "cryptominer_deployment",
        "malware_download",
        "ssh_bruteforce",
        "credential_stuffing",
        "defense_evasion",
        "persistence",
        "manual_reconnaissance",
        "telnet_abuse",
        "auth_probe",
        "unclassified_session",
    ]
    primary = next((p for p in priority if p in labels), labels[0])

    return {
        "session_id": session.session_id,
        "src_ip": session.src_ip,
        "protocol": session.protocol,
        "primary_type": primary,
        "labels": sorted(set(labels)),
        "automation": automation,
        "confidence": round(confidence, 2),
        "failed_logins": failed,
        "success": session.success,
        "command_count": len(session.commands),
        "download_count": len(session.downloads),
        "notes": notes,
    }


def classify_all(sessions: dict[str, Session]) -> list[dict[str, Any]]:
    results = [classify_session(s) for s in sessions.values()]
    results.sort(key=lambda r: (r.get("src_ip") or "", r.get("session_id") or ""))
    return results
