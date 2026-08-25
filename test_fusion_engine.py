#!/usr/bin/env python3
"""
test_fusion_engine.py — Smoke-test for the Dempster-Shafer Multi-Engine Score Fusion.

Runs all 5 sample emails through the entire pipeline:
  HeaderParser -> NLPEngine -> VisualEngine -> AttributionGraph -> FusionEngine
and prints the final verdict, threat score, tier, and reasoning trace.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from engines.header_parser import HeaderParser
from engines.nlp_engine import NLPEngine
from engines.visual_engine import VisualEngine
from engines.attribution_graph import AttributionGraph
from fusion.fusion_engine import FusionEngine

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m", "bg_red": "\033[41m",
}


def c(text: str, *styles: str) -> str:
    prefix = "".join(_C.get(s, "") for s in styles)
    return f"{prefix}{text}{_C['reset']}" if prefix else text


def main() -> None:
    ap = argparse.ArgumentParser(description="Test the Fusion Engine")
    ap.add_argument("files", nargs="*", help="Specific .eml files")
    args = ap.parse_args()

    sample_dir = PROJECT_ROOT / "data" / "sample_emails"
    eml_files = [Path(f) for f in args.files] if args.files else sorted(sample_dir.glob("*.eml"))

    if not eml_files:
        print(c("No .eml files found!", "red"))
        sys.exit(1)

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  SENTINEL-MAIL  .  Fusion Engine Pipeline Test", "bold", "magenta"))
    print(c(f"{'=' * 78}", "bold"))
    print(f"  Emails : {len(eml_files)}")

    # Initialize all engines
    hp = HeaderParser(offline_mode=True)
    nlp = NLPEngine(lightweight=True)
    visual = VisualEngine()
    attribution = AttributionGraph()
    fusion = FusionEngine()

    summary_rows = []

    for path in eml_files:
        print(f"\n📧  {c(path.name, 'bold', 'cyan')}")
        print(f"  {'─' * 60}")

        # 1. Run Header Parser
        header_res = hp.analyse(str(path))

        # 2. Run NLP Engine
        subject, body, urls = NLPEngine.extract_email_text(str(path))
        nlp_res = nlp.analyse(subject, body, urls)

        # 3. Run Visual Engine
        visual_res = visual.analyse_eml(str(path))

        # 4. Run Attribution Graph Builder
        attr_res = attribution.build(header_res, nlp_res, visual_res)

        # 5. Run Fusion Engine
        verdict = fusion.fuse(header_res, nlp_res, visual_res, attr_res)

        # Print Details
        score = verdict["threat_score"]
        tier = verdict["tier"]
        
        # Color tier
        if tier == "CONFIRMED_THREAT":
            tier_c = c(tier, "red", "bold", "bg_red")
        elif tier == "LIKELY_PHISH":
            tier_c = c(tier, "red", "bold")
        elif tier == "SUSPICIOUS":
            tier_c = c(tier, "yellow", "bold")
        else:
            tier_c = c(tier, "green")

        print(f"    Threat Score : {score}/100")
        print(f"    Verdict Tier : {tier_c}")
        print(f"    Belief Dist. : Threat={verdict['raw_belief']['threat']:.3f}, "
              f"Safe={verdict['raw_belief']['safe']:.3f}, Uncertainty={verdict['raw_belief']['uncertainty']:.3f}")
        
        print(f"    Reasoning trace:")
        steps = verdict["reasoning"].split(" | ")
        for s in steps:
            print(f"      - {s}")
            
        print(f"    Engine Contributions:")
        for contrib in verdict["signal_contributions"]:
            print(f"      * {contrib['engine']:<16s} -> Threat={contrib['threat_belief']:.2f}, "
                  f"Safe={contrib['safe_belief']:.2f}, Uncertainty={contrib['uncertainty']:.2f}")

        summary_rows.append((path.name, score, tier))

    # Summary table
    print(f"\n{c('=' * 78, 'cyan')}")
    print(c("  PIPELINE SUMMARY VERDICTS", "bold", "cyan"))
    print(c("=" * 78, "cyan"))
    print(f"\n  {'File':<36s} {'Score':>7s} {'Tier':>18s}")
    print(f"  {'-' * 36} {'-' * 7} {'-' * 18}")

    for name, score, tier in summary_rows:
        if tier == "CONFIRMED_THREAT":
            t_c = c(tier, "red", "bold")
        elif tier == "LIKELY_PHISH":
            t_c = c(tier, "red")
        elif tier == "SUSPICIOUS":
            t_c = c(tier, "yellow", "bold")
        else:
            t_c = c(tier, "green")

        print(f"  {name:<36s} {score:>7d} {t_c:>27s}")
    print()


if __name__ == "__main__":
    main()
