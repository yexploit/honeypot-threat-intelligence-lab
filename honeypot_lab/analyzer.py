"""CLI orchestrator for the Honeypot Threat Intelligence Lab."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from colorama import Fore, Style

from .classifier import classify_all
from .cowrie_parser import build_sessions, load_events, summarize_events
from .ioc_extractor import extract_iocs
from .payload_analyzer import analyze_downloads_dir
from .reporter import generate_report, report_markdown
from .threat_feeds import correlate_sessions, load_offline_feeds
from .timeline import build_timelines, timeline_markdown
from .utils import banner, ensure_dir, project_root, write_json


def default_paths() -> dict[str, Path]:
    root = project_root()
    return {
        "logs": root / "data" / "sample_cowrie" / "cowrie.json",
        "downloads": root / "data" / "downloaded",
        "feeds": root / "data" / "threat_feeds" / "offline_feeds.json",
        "out_iocs": root / "output" / "iocs",
        "out_reports": root / "output" / "reports",
        "out_timelines": root / "output" / "timelines",
    }


def export_iocs_csv(iocs: dict, path: Path) -> None:
    ensure_dir(path.parent)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ioc_type", "value", "extra", "sessions", "feed_listed"])
        for ip in iocs.get("attacker_ips", []):
            feed = ip.get("threat_feed") or {}
            writer.writerow(
                [
                    "ipv4",
                    ip["value"],
                    ";".join(ip.get("attack_types") or []),
                    len(ip.get("sessions") or []),
                    bool(feed.get("listed")),
                ]
            )
        for u in iocs.get("urls", []):
            feed = u.get("threat_feed") or {}
            writer.writerow(
                ["url", u["value"], u.get("sha256") or "", len(u.get("sessions") or []), bool(feed.get("listed"))]
            )
        for h in iocs.get("file_hashes", []):
            feed = h.get("threat_feed") or {}
            writer.writerow(
                ["sha256", h["value"], h.get("url") or "", len(h.get("sessions") or []), bool(feed.get("listed"))]
            )


def run_pipeline(
    log_path: Path,
    downloads_dir: Path,
    feeds_path: Path,
    out_iocs: Path,
    out_reports: Path,
    out_timelines: Path,
    use_live_feeds: bool,
) -> int:
    if not log_path.exists():
        print(Fore.RED + f"[!] Cowrie log not found: {log_path}")
        return 1

    print(Fore.CYAN + f"[*] Loading Cowrie events from {log_path}")
    events = load_events(log_path)
    if not events:
        print(Fore.RED + "[!] No events parsed.")
        return 1

    sessions = build_sessions(events)
    summary = summarize_events(events)
    print(
        Fore.GREEN
        + f"[+] Events={summary.get('total_events')}  "
        f"IPs={summary.get('unique_attacker_ips')}  "
        f"Sessions={len(sessions)}"
    )

    print(Fore.CYAN + "[*] Classifying attack types...")
    classifications = classify_all(sessions)
    for c in classifications:
        color = Fore.RED if c["confidence"] >= 0.8 else Fore.YELLOW
        print(
            color
            + f"    {c['src_ip']:16}  {c['primary_type']:28}  "
            f"auto={c['automation']:14}  conf={c['confidence']}"
        )

    print(Fore.CYAN + "[*] Correlating with threat feeds...")
    feeds = load_offline_feeds(feeds_path)
    feed_corr = correlate_sessions(sessions, feeds=feeds, use_live=use_live_feeds)
    fs = feed_corr["summary"]
    print(
        Fore.GREEN
        + f"[+] Feed hits - IPs {fs['ips_listed']}/{fs['ips_checked']}, "
        f"URLs {fs['urls_listed']}/{fs['urls_checked']}, "
        f"hashes {fs['hashes_listed']}/{fs['hashes_checked']}"
    )
    if fs.get("feed_sources"):
        print(Fore.YELLOW + f"    Sources: {', '.join(fs['feed_sources'])}")

    print(Fore.CYAN + "[*] Analyzing payloads...")
    payloads = analyze_downloads_dir(downloads_dir)
    for p in payloads:
        color = Fore.RED if p["risk"] == "critical" else Fore.YELLOW if p["risk"] == "high" else Fore.WHITE
        print(color + f"    {p['filename']:40} risk={p['risk']:8} indicators={p['indicators']}")

    print(Fore.CYAN + "[*] Extracting IOCs...")
    iocs = extract_iocs(sessions, classifications, feed_corr)

    print(Fore.CYAN + "[*] Building attack timelines...")
    timelines = build_timelines(sessions, classifications)

    print(Fore.CYAN + "[*] Generating threat report...")
    report = generate_report(summary, classifications, feed_corr, iocs, timelines, payloads)

    ensure_dir(out_iocs)
    ensure_dir(out_reports)
    ensure_dir(out_timelines)

    write_json(out_iocs / "ioc_database.json", iocs)
    export_iocs_csv(iocs, out_iocs / "ioc_database.csv")
    write_json(out_reports / "classifications.json", classifications)
    write_json(out_reports / "threat_feed_correlation.json", feed_corr)
    write_json(out_reports / "payload_analysis.json", payloads)
    write_json(out_reports / "threat_report.json", report)
    (out_reports / "threat_report.md").write_text(report_markdown(report), encoding="utf-8")
    (out_reports / "attacker_behavior_report.md").write_text(report_markdown(report), encoding="utf-8")
    write_json(out_timelines / "attack_timeline.json", timelines)
    (out_timelines / "attack_timeline.md").write_text(timeline_markdown(timelines), encoding="utf-8")
    write_json(out_reports / "defensive_recommendations.json", {"recommendations": report["defensive_recommendations"]})

    print("\n" + Style.BRIGHT + Fore.GREEN + "=== Deliverables ===")
    print(f"  IOC database:            {out_iocs / 'ioc_database.json'}")
    print(f"  IOC CSV:                 {out_iocs / 'ioc_database.csv'}")
    print(f"  Attacker behavior report:{out_reports / 'attacker_behavior_report.md'}")
    print(f"  Threat report:           {out_reports / 'threat_report.md'}")
    print(f"  Attack timeline:         {out_timelines / 'attack_timeline.md'}")
    print(f"  Defensive recommendations:{out_reports / 'defensive_recommendations.json'}")
    print(Style.BRIGHT + Fore.GREEN + "\n[OK] Pipeline complete.\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    defaults = default_paths()
    p = argparse.ArgumentParser(
        description="Honeypot Threat Intelligence Lab — analyze Cowrie logs, "
        "correlate threat feeds, extract IOCs, build timelines & reports."
    )
    p.add_argument(
        "-f",
        "--file",
        type=Path,
        default=defaults["logs"],
        help="Path to Cowrie JSON log (default: sample data)",
    )
    p.add_argument(
        "-d",
        "--downloads",
        type=Path,
        default=defaults["downloads"],
        help="Directory of captured/mock payloads",
    )
    p.add_argument(
        "--feeds",
        type=Path,
        default=defaults["feeds"],
        help="Offline threat feed JSON",
    )
    p.add_argument(
        "--live-feeds",
        action="store_true",
        help="Also query AbuseIPDB/OTX if API keys are set in the environment",
    )
    p.add_argument("--out-iocs", type=Path, default=defaults["out_iocs"])
    p.add_argument("--out-reports", type=Path, default=defaults["out_reports"])
    p.add_argument("--out-timelines", type=Path, default=defaults["out_timelines"])
    return p


def main(argv: list[str] | None = None) -> int:
    banner()
    args = build_parser().parse_args(argv)
    return run_pipeline(
        log_path=args.file,
        downloads_dir=args.downloads,
        feeds_path=args.feeds,
        out_iocs=args.out_iocs,
        out_reports=args.out_reports,
        out_timelines=args.out_timelines,
        use_live_feeds=args.live_feeds,
    )


if __name__ == "__main__":
    sys.exit(main())
