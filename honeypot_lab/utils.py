"""Shared helpers for the honeypot lab."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from colorama import Fore, Style, init
from pyfiglet import Figlet

init(autoreset=True)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def center_text(text: str) -> str:
    try:
        width = shutil.get_terminal_size().columns
    except OSError:
        width = 80
    return text.center(width)


def banner() -> None:
    f = Figlet(font="slant")
    left = f.renderText("HONEY").splitlines()
    right = f.renderText("POT").splitlines()
    print("\n")
    for a, b in zip(left, right):
        print(center_text(Fore.CYAN + a + "  " + Fore.RED + b))
    print("\n")
    print(center_text(Style.BRIGHT + "HONEYPOT THREAT INTELLIGENCE LAB"))
    print(center_text(Fore.YELLOW + "Cowrie  |  ELK Stack  |  Threat Feeds  |  Honeynet"))
    print(center_text(Fore.RED + "By yexploit"))
    print("\n")


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value.replace("Z", ""), fmt)
            except ValueError:
                continue
    return None


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_urls(text: str) -> list[str]:
    return URL_RE.findall(text or "")


def extract_ips(text: str) -> list[str]:
    return IP_RE.findall(text or "")
