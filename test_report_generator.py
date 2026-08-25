#!/usr/bin/env python3
"""
test_report_generator.py — End-to-End Pipeline & Forensic Report Generator Test.

Runs all 5 sample emails through the full pipeline:
  Header -> NLP -> Visual -> Attribution -> Fusion -> Report Generator
and writes JSON, Jinja2 HTML, and PDF reports for each email into reports/output/.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from engines.header_parser import HeaderParser
from engines.nlp_engine import NLPEngine
from engines.visual_engine import VisualEngine
from engines.attribution_graph import AttributionGraph
from fusion.fusion_engine import FusionEngine
from reports.report_generator import ReportGenerator, _HAS_WEASYPRINT

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m",
}


def c(text: str, *styles: str) -> str:
    prefix = "".join(_C.get(s, "") for s in styles)
    return f"{prefix}{text}{_C['reset']}" if prefix else text


def main() -> None:
    ap = argparse.ArgumentParser(description="Test the End-to-End Pipeline & Report Generator")
    ap.add_argument("files", nargs="*", help="Specific .eml files")
    args = ap.parse_args()

    sample_dir = PROJECT_ROOT / "data" / "sample_emails"
    eml_files = [Path(f) for f in args.files] if args.files else sorted(sample_dir.glob("*.eml"))

    if not eml_files:
        print(c("No .eml files found!", "red"))
        sys.exit(1)

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  SENTINEL-MAIL  .  End-to-End Forensic Report Pipeline", "bold", "magenta"))
    print(c(f"{'=' * 78}", "bold"))
    print(f"  Emails to Process : {len(eml_files)}")
    print(f"  WeasyPrint Status : {'Functional (PDF active)' if _HAS_WEASYPRINT else 'Disabled (Fallback PDF active)'}")

    # Output directory required by prompt
    out_dir = PROJECT_ROOT / "reports" / "output"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Initialize all engines
    hp = HeaderParser(offline_mode=True)
    nlp = NLPEngine(lightweight=True)
    visual = VisualEngine()
    attribution = AttributionGraph()
    fusion = FusionEngine()
    reports = ReportGenerator()

    results_summary = []

    for path in eml_files:
        print(f"\n📧  {c(path.name, 'bold', 'cyan')}")
        print(f"  {'─' * 60}")

        # 1. Header Parser
        header_res = hp.analyse(str(path))

        # 2. NLP Engine
        subject, body, urls = NLPEngine.extract_email_text(str(path))
        nlp_res = nlp.analyse(subject, body, urls)

        # 3. Visual Engine
        visual_res = visual.analyse_eml(str(path))

        # 4. Attribution Graph
        attr_res = attribution.build(header_res, nlp_res, visual_res)

        # 5. Fusion Engine (Weighted Risk Verdict 0-100)
        verdict = fusion.fuse(header_res, nlp_res, visual_res, attr_res)

        # 6. Generate All 3 Reports (JSON, Jinja2 HTML, PDF) into reports/output
        engines = {
            "HeaderParser": header_res,
            "NLPEngine": nlp_res,
            "VisualEngine": visual_res,
            "AttributionGraph": attr_res,
        }

        report_files = reports.generate_reports(
            eml_path=path,
            fusion_verdict=verdict,
            engine_results=engines,
            output_dir=out_dir,
        )

        score = verdict["threat_score"]
        tier = verdict["tier"]
        tier_style = "red" if score >= 80 else ("yellow" if score >= 50 else "green")

        print(f"    Verdict Score : [{c(str(score) + '/100', tier_style, 'bold')}] - {c(tier, 'bold')}")
        print(f"    Saved JSON    : {c(str(report_files['json'].relative_to(PROJECT_ROOT)), 'green')} ({report_files['json'].stat().st_size:,} bytes)")
        print(f"    Saved HTML    : {c(str(report_files['html'].relative_to(PROJECT_ROOT)), 'green')} ({report_files['html'].stat().st_size:,} bytes)")
        print(f"    Saved PDF     : {c(str(report_files['pdf'].relative_to(PROJECT_ROOT)), 'green')} ({report_files['pdf'].stat().st_size:,} bytes)")

        # Read JSON report to verify SHA-256 custody hash present
        json_data = json.loads(report_files["json"].read_text(encoding="utf-8"))
        custody_hash = json_data.get("chain_of_custody", {}).get("sha256")
        assert custody_hash is not None and len(custody_hash) == 64, "SHA-256 chain of custody hash missing!"
        print(f"    SHA-256 Hash  : {custody_hash[:16]}...")

        results_summary.append((path.name, score, tier, custody_hash))

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  PIPELINE EXECUTION SUMMARY (reports/output)", "bold", "cyan"))
    print(c(f"{'=' * 78}", "bold"))
    print(f"  {'File':<34} {'Score':>6}  {'Tier':<18} {'SHA-256 Hash'}")
    print(f"  {'─' * 34} {'─' * 6}  {'─' * 18} {'─' * 20}")
    for fname, score, tier, chash in results_summary:
        t_style = "red" if score >= 80 else ("yellow" if score >= 50 else "green")
        print(f"  {fname:<34} {score:>6}  {c(tier, t_style):<18} {chash[:20]}...")

    print(c(f"\n[SUCCESS] Generated all 3 forensic report formats for 5 emails into {out_dir.relative_to(PROJECT_ROOT)}/\n", "green", "bold"))


if __name__ == "__main__":
    main()
