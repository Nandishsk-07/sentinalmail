#!/usr/bin/env python3
"""
test_visual_engine.py — Smoke-test for the Visual Analysis engine.

Runs all .eml files through the VisualEngine and prints results.
The QR-phishing sample should produce decoded URLs + risk flags;
the others should report zero images / QR codes.

Usage:
    python test_visual_engine.py                   # all samples
    python test_visual_engine.py path/to/file.eml  # single file
    python test_visual_engine.py --json             # raw JSON
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from engines.visual_engine import VisualEngine  # noqa: E402

# ── ANSI helpers ──────────────────────────────────────────────────────

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m", "bg_red": "\033[41m", "bg_green": "\033[42m",
}


def c(text: str, *styles: str) -> str:
    prefix = "".join(_C.get(s, "") for s in styles)
    return f"{prefix}{text}{_C['reset']}" if prefix else text


def print_banner(title: str) -> None:
    w = 78
    print(f"\n{c('=' * w, 'cyan')}")
    print(c(f"  {title}", "bold", "cyan"))
    print(c("=" * w, "cyan"))


def print_section(title: str) -> None:
    print(f"\n  {c(title, 'bold', 'white')}")
    print(f"  {'-' * 60}")


# ── Pretty-printer ────────────────────────────────────────────────────


def print_result(result: dict) -> None:
    # Attachment inventory
    attachments = result.get("attachments", [])
    images = result.get("images_scanned", 0)
    qr_count = result.get("qr_codes_found", 0)

    print_section("Attachment Inventory")
    if not attachments:
        print(f"    {c('(no image attachments found)', 'dim')}")
    else:
        for att in attachments:
            fn = att.get("filename", "?")
            ct = att.get("content_type", "?")
            sz = att.get("size_bytes", 0)
            qr_n = len(att.get("qr_codes", []))
            qr_badge = f"  {c(f'[{qr_n} QR]', 'red', 'bold')}" if qr_n else ""
            print(f"    {c(fn, 'cyan')}  {ct}  ({sz:,} bytes){qr_badge}")

    print(f"\n    Images scanned : {c(str(images), 'bold')}")
    print(f"    QR codes found : {c(str(qr_count), 'red' if qr_count else 'green', 'bold')}")

    # Decoded QR data
    decoded = result.get("decoded_urls", [])
    if decoded:
        print_section("Decoded QR URLs")
        for i, url in enumerate(decoded, 1):
            print(f"    {i}. {c(url, 'yellow', 'bold')}")

    # URL risk flags
    flags = result.get("url_risk_flags", [])
    if flags:
        print_section("URL Risk Assessment")
        for entry in flags:
            url = entry.get("url", "?")
            host = entry.get("hostname", "?")
            score = entry.get("risk_score", 0)
            level = entry.get("risk_level", "?")

            if level == "high":
                lvl_c = c(level.upper(), "red", "bold")
            elif level == "medium":
                lvl_c = c(level.upper(), "yellow", "bold")
            else:
                lvl_c = c(level.upper(), "green")

            # Score bar
            filled = int(round(score * 20))
            bar = c("X" * filled, "red") + c("." * (20 - filled), "dim")

            print(f"    URL  : {c(url[:80], 'cyan')}")
            print(f"    Host : {host}")
            print(f"    Risk : [{bar}]  {score:.2f}  {lvl_c}")

            for f in entry.get("flags", []):
                sev = f.get("severity", "?")
                flag_name = f.get("flag", "?")
                detail = f.get("detail", "")
                sev_c = {"critical": "red", "high": "red", "medium": "yellow", "low": "dim"}.get(sev, "white")
                print(f"           {c(sev.upper(), sev_c, 'bold'):>20s}  {flag_name}: {detail}")
            print()


# ── Main ──────────────────────────────────────────────────────────────


def main() -> None:
    ap = argparse.ArgumentParser(description="Test the VisualEngine")
    ap.add_argument("--json", action="store_true", help="Dump raw JSON")
    ap.add_argument("files", nargs="*", help=".eml files (default: all samples)")
    args = ap.parse_args()

    sample_dir = PROJECT_ROOT / "data" / "sample_emails"
    eml_files = [Path(f) for f in args.files] if args.files else sorted(sample_dir.glob("*.eml"))

    if not eml_files:
        print(c("No .eml files found!", "red"))
        sys.exit(1)

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  SENTINEL-MAIL  .  Visual Engine Test", "bold", "magenta"))
    print(c(f"{'=' * 78}", "bold"))
    print(f"  Files : {len(eml_files)}")

    # Dependency check
    from engines.visual_engine import _HAS_CV2, _HAS_PYZBAR, _HAS_PIL
    print(f"  OpenCV : {c('YES', 'green') if _HAS_CV2 else c('NO', 'red')}")
    print(f"  pyzbar : {c('YES', 'green') if _HAS_PYZBAR else c('NO', 'red')}")
    print(f"  Pillow : {c('YES', 'green') if _HAS_PIL else c('NO', 'red')}")

    summary: list[tuple[str, int, int, int]] = []

    for path in eml_files:
        print_banner(f"  {path.name}")

        engine = VisualEngine()
        result = engine.analyse_eml(str(path))

        if args.json:
            # Strip raw bytes from JSON output
            for att in result.get("attachments", []):
                att.pop("payload", None)
            print(json.dumps(result, indent=2, default=str))
        else:
            print_result(result)

        summary.append((
            path.name,
            result.get("images_scanned", 0),
            result.get("qr_codes_found", 0),
            len(result.get("decoded_urls", [])),
        ))

    # Summary table
    print(f"\n{c('=' * 78, 'cyan')}")
    print(c("  SUMMARY", "bold", "cyan"))
    print(c("=" * 78, "cyan"))
    print(f"\n  {'File':<38s} {'Images':>7s} {'QR':>5s} {'URLs':>6s}")
    print(f"  {'-' * 38} {'-' * 7} {'-' * 5} {'-' * 6}")

    for name, imgs, qr, urls in summary:
        qr_c = c(str(qr), "red", "bold") if qr else c(str(qr), "green")
        print(f"  {name:<38s} {imgs:>7d} {qr_c:>16s} {urls:>6d}")

    print()


if __name__ == "__main__":
    main()
