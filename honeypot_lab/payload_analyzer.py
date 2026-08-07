"""Analyze payloads captured by the honeypot (safe static analysis)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .utils import extract_ips, extract_urls, file_sha256


SUSPICIOUS_STRINGS = [
    (r"iptables\s+-F", "firewall_flush"),
    (r"rm\s+-rf\s+/var/log", "log_wipe"),
    (r"crontab", "persistence_cron"),
    (r"xmrig|minexmr|stratum", "cryptominer"),
    (r"mirai|bot\.arm|/bins/", "iot_botnet"),
    (r"wget|curl", "downloader"),
    (r"chmod\s+(\+x|777)", "make_executable"),
    (r"nohup| &\s*$", "background_exec"),
    (r"busybox", "busybox_abuse"),
]


def analyze_payload_file(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "filename": path.name,
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "sha256": None,
        "urls": [],
        "ips": [],
        "indicators": [],
        "risk": "low",
        "notes": [],
    }
    if not path.exists():
        result["notes"].append("file missing")
        return result

    result["sha256"] = file_sha256(path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = ""

    result["urls"] = sorted(set(extract_urls(text)))
    result["ips"] = sorted(set(extract_ips(text)))

    for pattern, label in SUSPICIOUS_STRINGS:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            result["indicators"].append(label)

    name = path.name.lower()
    if "mirai" in name or "bot" in name:
        result["indicators"].append("filename_botnet_hint")
    if "xmrig" in name or "miner" in name:
        result["indicators"].append("filename_miner_hint")
    if name.endswith(".sh"):
        result["indicators"].append("shell_script")

    indicators = set(result["indicators"])
    if indicators & {"iot_botnet", "cryptominer", "log_wipe", "firewall_flush"}:
        result["risk"] = "critical"
    elif indicators & {"downloader", "make_executable", "persistence_cron"}:
        result["risk"] = "high"
    elif indicators:
        result["risk"] = "medium"

    result["indicators"] = sorted(set(result["indicators"]))
    result["notes"].append("Static lab analysis only — samples are safe mocks unless from live Cowrie downloads")
    return result


def analyze_downloads_dir(directory: Path) -> list[dict[str, Any]]:
    if not directory.exists():
        return []
    results = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and not path.name.startswith("."):
            results.append(analyze_payload_file(path))
    return results
