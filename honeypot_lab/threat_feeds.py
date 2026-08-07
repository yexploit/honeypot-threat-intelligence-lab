"""Correlate attacker artifacts with threat intelligence feeds."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

from .cowrie_parser import Session
from .utils import project_root


def load_offline_feeds(path: Path | None = None) -> dict[str, Any]:
    feed_path = path or (project_root() / "data" / "threat_feeds" / "offline_feeds.json")
    if not feed_path.exists():
        return {"malicious_ips": {}, "malicious_urls": {}, "malicious_hashes": {}}
    return json.loads(feed_path.read_text(encoding="utf-8"))


def lookup_abuseipdb(ip: str, api_key: str) -> dict[str, Any] | None:
    """Optional live AbuseIPDB lookup when ABUSEIPDB_API_KEY is set."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = Request(
        url,
        headers={"Key": api_key, "Accept": "application/json", "User-Agent": "honeypot-lab/1.0"},
    )
    try:
        with urlopen(req, timeout=8) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            data = payload.get("data", {})
            return {
                "source": "AbuseIPDB",
                "abuse_score": data.get("abuseConfidenceScore"),
                "country": data.get("countryCode"),
                "total_reports": data.get("totalReports"),
                "usage_type": data.get("usageType"),
            }
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError, KeyError):
        return None


def lookup_otx(ip: str, api_key: str) -> dict[str, Any] | None:
    """Optional live AlienVault OTX lookup when OTX_API_KEY is set."""
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    req = Request(url, headers={"X-OTX-API-KEY": api_key, "User-Agent": "honeypot-lab/1.0"})
    try:
        with urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "source": "AlienVault OTX",
                "pulse_count": (data.get("pulse_info") or {}).get("count"),
                "reputation": data.get("reputation"),
                "country": (data.get("country_name") or data.get("country_code")),
            }
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError, KeyError):
        return None


def correlate_ip(ip: str, feeds: dict[str, Any], use_live: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ip": ip,
        "listed": False,
        "offline_match": None,
        "live_matches": [],
        "feeds_hit": [],
        "risk": "unknown",
    }

    offline = (feeds.get("malicious_ips") or {}).get(ip)
    if offline:
        result["listed"] = True
        result["offline_match"] = offline
        result["feeds_hit"].extend(offline.get("feeds") or [])
        score = offline.get("abuse_score") or 0
        result["risk"] = "critical" if score >= 90 else "high" if score >= 70 else "medium"

    if use_live:
        abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
        otx_key = os.environ.get("OTX_API_KEY", "").strip()
        if abuse_key:
            hit = lookup_abuseipdb(ip, abuse_key)
            if hit:
                result["live_matches"].append(hit)
                result["listed"] = True
                result["feeds_hit"].append("AbuseIPDB")
        if otx_key:
            hit = lookup_otx(ip, otx_key)
            if hit:
                result["live_matches"].append(hit)
                result["listed"] = True
                result["feeds_hit"].append("AlienVault OTX")

    result["feeds_hit"] = sorted(set(result["feeds_hit"]))
    if not result["listed"]:
        result["risk"] = "unlisted"
    return result


def correlate_url(url: str, feeds: dict[str, Any]) -> dict[str, Any]:
    match = (feeds.get("malicious_urls") or {}).get(url)
    return {
        "url": url,
        "listed": bool(match),
        "match": match,
        "feeds_hit": list((match or {}).get("feeds") or []),
    }


def correlate_hash(sha: str, feeds: dict[str, Any]) -> dict[str, Any]:
    match = (feeds.get("malicious_hashes") or {}).get(sha)
    return {
        "hash": sha,
        "listed": bool(match),
        "match": match,
        "feeds_hit": list((match or {}).get("feeds") or []),
    }


def correlate_sessions(
    sessions: dict[str, Session],
    feeds: dict[str, Any] | None = None,
    use_live: bool = True,
) -> dict[str, Any]:
    feeds = feeds or load_offline_feeds()
    ips = sorted({s.src_ip for s in sessions.values() if s.src_ip})
    urls: set[str] = set()
    hashes: set[str] = set()
    for s in sessions.values():
        for d in s.downloads:
            if d.get("url"):
                urls.add(d["url"])
            if d.get("shasum"):
                hashes.add(d["shasum"])

    ip_results = [correlate_ip(ip, feeds, use_live=use_live) for ip in ips]
    url_results = [correlate_url(u, feeds) for u in sorted(urls)]
    hash_results = [correlate_hash(h, feeds) for h in sorted(hashes)]

    listed_ips = sum(1 for r in ip_results if r["listed"])
    return {
        "summary": {
            "ips_checked": len(ip_results),
            "ips_listed": listed_ips,
            "urls_checked": len(url_results),
            "urls_listed": sum(1 for r in url_results if r["listed"]),
            "hashes_checked": len(hash_results),
            "hashes_listed": sum(1 for r in hash_results if r["listed"]),
            "honeynet_aligned": True,
            "feed_sources": sorted(
                {
                    f
                    for r in ip_results + url_results + hash_results
                    for f in r.get("feeds_hit") or []
                }
            ),
        },
        "ips": ip_results,
        "urls": url_results,
        "hashes": hash_results,
    }
