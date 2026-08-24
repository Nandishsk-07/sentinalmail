#!/usr/bin/env python3
"""
test_header_parser.py — Quick smoke-test for the HeaderParser engine.

Runs all .eml files in data/sample_emails/ through the parser and prints
a coloured summary of the results.

Usage:
    python test_header_parser.py                 # online mode (live DNS + geo)
    python test_header_parser.py --offline       # offline mode (header-only)
    python test_header_parser.py --no-geo        # DNS but skip geo API
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path so `engines` is importable
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from engines.header_parser import HeaderParser  # noqa: E402

# ── ANSI colours (graceful no-op on terminals that don't support them) ─

_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bg_red": "\033[41m",
    "bg_green": "\033[42m",
    "bg_yellow": "\033[43m",
}


def c(text: str, *styles: str) -> str:
    """Wrap *text* in ANSI escape codes."""
    prefix = "".join(_COLORS.get(s, "") for s in styles)
    return f"{prefix}{text}{_COLORS['reset']}" if prefix else text


# ── Pretty-printers ───────────────────────────────────────────────────


def print_banner(title: str) -> None:
    width = 78
    print()
    print(c("═" * width, "cyan"))
    print(c(f"  {title}", "bold", "cyan"))
    print(c("═" * width, "cyan"))


def print_section(title: str) -> None:
    print(f"\n  {c(title, 'bold', 'white')}")
    print(f"  {'─' * 60}")


def print_relay_path(relay_path: list[dict]) -> None:
    print_section("📡  Relay Path (Received Chain)")
    if not relay_path:
        print("    (no Received headers found)")
        return
    for hop in relay_path:
        num = hop["hop"]
        host = hop.get("from_host") or "—"
        ip = hop.get("from_ip") or "—"
        by = hop.get("by_host") or "—"
        proto = hop.get("protocol") or "—"
        ts = hop.get("timestamp_utc") or "—"
        delay = hop.get("delay_seconds")
        delay_str = f"(+{delay}s)" if delay is not None else ""

        # Flag large delays
        if delay is not None and delay > 60:
            delay_str = c(f"(+{delay}s ⚠ SLOW)", "yellow")

        print(f"    {c(f'Hop {num}', 'bold')}  {host} [{c(ip, 'cyan')}]")
        print(f"          → {by}  via {proto}  {delay_str}")
        print(f"          {c(ts, 'dim')}")


def _verdict_color(verdict: str | None) -> str:
    if not verdict:
        return "dim"
    v = verdict.lower()
    if v in ("pass",):
        return "green"
    if v in ("fail", "none"):
        return "red"
    if v in ("softfail",):
        return "yellow"
    return "white"


def print_auth_results(auth: dict) -> None:
    print_section("🔐  Authentication Results")

    hdr = auth.get("header", {})
    for proto in ("spf", "dkim", "dmarc"):
        entry = hdr.get(proto)
        if entry:
            v = entry.get("verdict", "?")
            detail = entry.get("detail") or ""
            print(f"    {proto.upper():6s}  {c(v.upper(), _verdict_color(v))}"
                  f"  {c(detail, 'dim')}")
        else:
            print(f"    {proto.upper():6s}  {c('not present', 'dim')}")

    # Domains
    env = auth.get("envelope_domain") or "—"
    hfrom = auth.get("header_from_domain") or "—"
    print(f"\n    Envelope (Return-Path) domain : {c(env, 'cyan')}")
    print(f"    Header (From) domain         : {c(hfrom, 'cyan')}")

    # Live DNS
    live = auth.get("live_dns")
    if live:
        print(f"\n    {c('Live DNS lookups:', 'bold')}")
        spf_rec = live.get("spf_record")
        dmarc_rec = live.get("dmarc_record")
        dkim_info = live.get("dkim")

        if spf_rec:
            print(f"      SPF record   : {c(spf_rec[:90], 'dim')}")
        else:
            print(f"      SPF record   : {c('(not found / lookup failed)', 'yellow')}")

        if dmarc_rec:
            print(f"      DMARC record : {c(dmarc_rec[:90], 'dim')}")
        else:
            print(f"      DMARC record : {c('(not found / lookup failed)', 'yellow')}")

        if dkim_info:
            found = dkim_info.get("public_key_found", False)
            sel = dkim_info.get("selector", "?")
            dom = dkim_info.get("domain", "?")
            status = c("FOUND", "green") if found else c("NOT FOUND", "red")
            print(f"      DKIM key     : {sel}._domainkey.{dom} → {status}")
        else:
            print(f"      DKIM key     : {c('(no DKIM-Signature header)', 'dim')}")
    elif auth.get("live_dns") is None:
        print(f"\n    {c('(live DNS skipped — offline mode or dnspython not installed)', 'dim')}")


def print_spoofing_flags(flags: list[dict]) -> None:
    print_section("🚩  Spoofing Flags")
    if not flags:
        print(f"    {c('✓ No spoofing indicators detected', 'green')}")
        return

    for f in flags:
        severity = f.get("severity", "medium")
        sev_map = {
            "critical": ("bg_red", "white", "bold"),
            "high": ("red", "bold"),
            "medium": ("yellow",),
            "low": ("dim",),
        }
        sev_style = sev_map.get(severity, ("white",))
        badge = c(f" {severity.upper()} ", *sev_style)
        ftype = f.get("type", "unknown")
        desc = f.get("description", "")

        print(f"    {badge}  [{ftype}]")
        print(f"           {desc}")


def print_geo_trace(geo: list[dict]) -> None:
    print_section("🌍  IP Geolocation Trace")
    if not geo:
        print("    (no public IPs to geolocate)")
        return

    for entry in geo:
        ip = entry.get("ip", "?")
        if entry.get("private"):
            print(f"    {c(ip, 'cyan'):>18s}  {c('(private / RFC-1918)', 'dim')}")
            continue
        if entry.get("geo") == "disabled":
            print(f"    {c(ip, 'cyan'):>18s}  {c('(geo lookup disabled)', 'dim')}")
            continue
        if entry.get("geo_error"):
            print(f"    {c(ip, 'cyan'):>18s}  {c('error: ' + entry['geo_error'], 'red')}")
            continue

        country = entry.get("country", "?")
        city = entry.get("city", "?")
        isp = entry.get("isp", "?")
        org = entry.get("org", "")
        print(f"    {c(ip, 'cyan'):>18s}  {country}, {city}")
        print(f"                     ISP: {isp}"
              + (f"  Org: {org}" if org and org != isp else ""))


# ── Main ──────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Test the HeaderParser engine")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip all network calls (DNS + geo)",
    )
    parser.add_argument(
        "--no-geo",
        action="store_true",
        help="Skip IP geolocation but still do DNS lookups",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Dump raw JSON output instead of pretty-printing",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Specific .eml files to test (default: all in data/sample_emails/)",
    )
    args = parser.parse_args()

    # Discover sample emails
    sample_dir = PROJECT_ROOT / "data" / "sample_emails"
    if args.files:
        eml_files = [Path(f) for f in args.files]
    else:
        eml_files = sorted(sample_dir.glob("*.eml"))

    if not eml_files:
        print(c("No .eml files found!", "red"))
        sys.exit(1)

    print(c(f"\n{'='*78}", "bold"))
    print(c("  SENTINEL-MAIL  ·  Header Parser Engine Test", "bold", "magenta"))
    print(c(f"{'='*78}", "bold"))
    print(f"  Mode   : {'OFFLINE' if args.offline else 'ONLINE'}")
    print(f"  Geo    : {'disabled' if args.no_geo or args.offline else 'enabled'}")
    print(f"  Emails : {len(eml_files)} file(s)")

    # Initialise the parser
    hp = HeaderParser(
        offline_mode=args.offline,
        geo_enabled=not args.no_geo,
    )

    all_results: list[dict] = []

    for eml_path in eml_files:
        print_banner(f"📧  {eml_path.name}")
        result = hp.analyse(str(eml_path))
        all_results.append(result)

        if args.json:
            print(json.dumps(result, indent=2, default=str))
            continue

        # Subject & From
        print(f"\n  Subject : {c(result.get('subject', ''), 'white', 'bold')}")
        print(f"  From    : {c(result.get('from', ''), 'white')}")

        print_relay_path(result["relay_path"])
        print_auth_results(result["auth_results"])
        print_spoofing_flags(result["spoofing_flags"])
        print_geo_trace(result["geo_trace"])

    # ── Summary table ──────────────────────────────────────────────────

    print(c(f"\n{'═'*78}", "cyan"))
    print(c("  SUMMARY", "bold", "cyan"))
    print(c(f"{'═'*78}", "cyan"))

    print(f"\n  {'File':<36s} {'SPF':>6s} {'DKIM':>6s} {'DMARC':>7s} {'Flags':>6s}")
    print(f"  {'─'*36} {'─'*6} {'─'*6} {'─'*7} {'─'*6}")

    for r in all_results:
        name = r["file"][:35]
        hdr = r["auth_results"].get("header", {})
        spf_v = (hdr.get("spf") or {}).get("verdict", "—")
        dkim_v = (hdr.get("dkim") or {}).get("verdict", "—")
        dmarc_v = (hdr.get("dmarc") or {}).get("verdict", "—")
        n_flags = len(r["spoofing_flags"])

        flag_str = c(str(n_flags), "green") if n_flags == 0 else c(str(n_flags), "red", "bold")

        print(
            f"  {name:<36s} "
            f"{c(spf_v.upper(), _verdict_color(spf_v)):>17s} "
            f"{c(dkim_v.upper(), _verdict_color(dkim_v)):>17s} "
            f"{c(dmarc_v.upper(), _verdict_color(dmarc_v)):>18s} "
            f"{flag_str:>17s}"
        )

    print()


if __name__ == "__main__":
    main()
