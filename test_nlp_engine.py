#!/usr/bin/env python3
"""
test_nlp_engine.py — Smoke-test for the NLP analysis engine.

Runs all .eml files in data/sample_emails/ through the NLPEngine
and prints a coloured, structured summary.

Usage:
    python test_nlp_engine.py                    # heuristic mode (fast)
    python test_nlp_engine.py --full             # enable transformer models
    python test_nlp_engine.py --json             # raw JSON output
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from engines.nlp_engine import NLPEngine  # noqa: E402

# ── ANSI helpers ──────────────────────────────────────────────────────

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m", "bg_red": "\033[41m",
}


def c(text: str, *styles: str) -> str:
    prefix = "".join(_C.get(s, "") for s in styles)
    return f"{prefix}{text}{_C['reset']}" if prefix else text


# ── Pretty printers ──────────────────────────────────────────────────


def print_banner(title: str) -> None:
    w = 78
    print(f"\n{c('═' * w, 'cyan')}")
    print(c(f"  {title}", "bold", "cyan"))
    print(c("═" * w, "cyan"))


def print_section(title: str) -> None:
    print(f"\n  {c(title, 'bold', 'white')}")
    print(f"  {'─' * 60}")


def _score_bar(score: float, width: int = 20) -> str:
    """Render a visual bar ████░░░░ for a 0-1 score."""
    filled = int(round(score * width))
    empty = width - filled
    if score >= 0.7:
        colour = "red"
    elif score >= 0.4:
        colour = "yellow"
    else:
        colour = "green"
    return c("█" * filled, colour) + c("░" * empty, "dim")


def print_phishing(phish: dict) -> None:
    print_section("🎯  Phishing Classification")
    score = phish.get("score", 0)
    label = phish.get("label", "?")
    method = phish.get("method", "?")

    bar = _score_bar(score)
    label_c = c(label.upper(), "red", "bold") if label == "phishing" else c(label.upper(), "green")
    print(f"    Score : {bar}  {score:.2f}  [{label_c}]")
    print(f"    Method: {c(method, 'dim')}", end="")
    if method == "transformer":
        print(f"  ({phish.get('model', '')}  raw_label={phish.get('raw_label', '')})")
    else:
        print()

    signals = phish.get("signals") or phish.get("heuristic_signals")
    if signals and isinstance(signals, dict):
        print(f"\n    {c('Signal breakdown:', 'bold')}")
        for cat, info in signals.items():
            if isinstance(info, dict):
                cs = info.get("score", 0)
                hits = info.get("matches", info.get("suspicious_urls", 0))
                bar = _score_bar(cs, 12)
                print(f"      {cat:<16s}  {bar}  {cs:.2f}  ({hits} match{'es' if hits != 1 else ''})")


def print_ai(ai: dict) -> None:
    print_section("🤖  AI-Generated Text Detection")
    score = ai.get("score", 0)
    label = ai.get("label", "?")
    method = ai.get("method", "?")

    bar = _score_bar(score)
    if "human" in label:
        label_c = c(label, "green")
    elif "AI" in label:
        label_c = c(label, "red", "bold")
    else:
        label_c = c(label, "yellow")

    print(f"    Score : {bar}  {score:.2f}  [{label_c}]")
    print(f"    Method: {c(method, 'dim')}")

    if method == "gpt2":
        ppl = ai.get("perplexity")
        burst = ai.get("burstiness")
        n_sent = ai.get("sentences_analysed", 0)
        print(f"    Perplexity : {ppl:.1f}" if ppl else "")
        if burst is not None:
            print(f"    Burstiness : {burst:.1f}  ({n_sent} sentences)")
    else:
        ttr = ai.get("type_token_ratio")
        sv = ai.get("sentence_length_stdev")
        if ttr is not None:
            print(f"    Type-token ratio     : {ttr:.3f}")
        if sv is not None:
            print(f"    Sent. length σ       : {sv:.2f}")


def print_entities(ents: dict) -> None:
    print_section("📋  Extracted Entities")
    total = 0

    for group_name, items in ents.items():
        if items is None:
            continue
        if isinstance(items, list) and items:
            total += len(items)
            label = group_name.replace("_", " ").title()
            print(f"    {c(label, 'bold')} ({len(items)}):")
            for item in items[:10]:  # cap display
                if isinstance(item, dict):
                    t = item.get("type") or item.get("label", "")
                    v = item.get("value") or item.get("text") or item.get("url", "")
                    extra = ""
                    if "risk_score" in item:
                        rs = item["risk_score"]
                        flag = c(" ⚠ SUSPICIOUS", "red") if item.get("suspicious") else ""
                        extra = f"  risk={rs:.2f}{flag}"
                    print(f"      [{t}] {c(str(v)[:70], 'cyan')}{extra}")
                else:
                    print(f"      {c(str(item)[:70], 'cyan')}")

    if total == 0:
        print(f"    {c('(no entities found)', 'dim')}")


def print_phrases(phrases: list) -> None:
    print_section("⚠️   Flagged Phrases")
    if not phrases:
        print(f"    {c('✓ No suspicious phrases detected', 'green')}")
        return

    sev_style = {
        "critical": ("bg_red", "white", "bold"),
        "high": ("red", "bold"),
        "medium": ("yellow",),
        "low": ("dim",),
    }

    for p in phrases[:15]:  # cap display
        sev = p.get("severity", "medium")
        cat = p.get("category", "")
        phrase = p.get("phrase", "")
        ctx = p.get("context", "")
        badge = c(f" {sev.upper()} ", *sev_style.get(sev, ("white",)))
        print(f"    {badge}  [{cat}] \"{c(phrase, 'bold')}\"")
        print(f"           {c(ctx, 'dim')}")


# ── Main ──────────────────────────────────────────────────────────────


def main() -> None:
    ap = argparse.ArgumentParser(description="Test the NLP engine")
    ap.add_argument("--full", action="store_true", help="Enable transformer models (slow first run)")
    ap.add_argument("--json", action="store_true", help="Dump raw JSON")
    ap.add_argument("files", nargs="*", help="Specific .eml files (default: all samples)")
    args = ap.parse_args()

    sample_dir = PROJECT_ROOT / "data" / "sample_emails"
    eml_files = [Path(f) for f in args.files] if args.files else sorted(sample_dir.glob("*.eml"))
    if not eml_files:
        print(c("No .eml files found!", "red"))
        sys.exit(1)

    lightweight = not args.full
    mode = "FULL (transformers)" if args.full else "LIGHTWEIGHT (heuristic)"

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  SENTINEL-MAIL  ·  NLP Engine Test", "bold", "magenta"))
    print(c(f"{'=' * 78}", "bold"))
    print(f"  Mode   : {mode}")
    print(f"  Emails : {len(eml_files)} file(s)")

    engine = NLPEngine(lightweight=lightweight)
    summary_rows: list[tuple] = []

    for path in eml_files:
        print_banner(f"📧  {path.name}")

        subject, body, urls = NLPEngine.extract_email_text(str(path))
        print(f"\n  Subject : {c(subject, 'white', 'bold')}")
        print(f"  Body    : {c(str(len(body)) + ' chars', 'dim')}, "
              f"{c(str(len(urls)) + ' URL(s)', 'dim')}")

        result = engine.analyse(subject, body, urls)

        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print_phishing(result["phishing_score"])
            print_ai(result["ai_generated_score"])
            print_entities(result["extracted_entities"])
            print_phrases(result["flagged_phrases"])

        # Collect for summary
        ps = result["phishing_score"]["score"]
        ai = result["ai_generated_score"]["score"]
        n_ent = sum(
            len(v) for v in result["extracted_entities"].values()
            if isinstance(v, list)
        )
        n_flags = len(result["flagged_phrases"])
        summary_rows.append((path.name, ps, ai, n_ent, n_flags))

    # ── Summary table ──────────────────────────────────────────────────

    print(f"\n{c('═' * 78, 'cyan')}")
    print(c("  SUMMARY", "bold", "cyan"))
    print(c("═" * 78, "cyan"))

    header = f"  {'File':<36s} {'Phish':>7s} {'AI':>7s} {'Ents':>6s} {'Flags':>6s}"
    print(f"\n{header}")
    print(f"  {'─' * 36} {'─' * 7} {'─' * 7} {'─' * 6} {'─' * 6}")

    for name, ps, ai, ne, nf in summary_rows:
        ps_c = c(f"{ps:.2f}", "red" if ps >= 0.5 else "green")
        ai_c = c(f"{ai:.2f}", "red" if ai >= 0.5 else "green")
        ne_c = c(str(ne), "cyan")
        nf_c = c(str(nf), "red" if nf > 0 else "green")
        print(f"  {name:<36s} {ps_c:>18s} {ai_c:>18s} {ne_c:>17s} {nf_c:>17s}")

    print()


if __name__ == "__main__":
    main()
