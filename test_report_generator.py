#!/usr/bin/env python3
"""
test_report_generator.py — Smoke-test for the Forensic Report Generator.

Runs all 5 sample emails through the pipeline:
  Header -> NLP -> Visual -> Attribution -> Fusion -> Report
and outputs PDF, HTML, and JSON reports in data/reports/.
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
from reports.report_generator import ReportGenerator

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
    ap = argparse.ArgumentParser(description="Test the Report Generator")
    ap.add_argument("files", nargs="*", help="Specific .eml files")
    args = ap.parse_args()

    sample_dir = PROJECT_ROOT / "data" / "sample_emails"
    eml_files = [Path(f) for f in args.files] if args.files else sorted(sample_dir.glob("*.eml"))

    if not eml_files:
        print(c("No .eml files found!", "red"))
        sys.exit(1)

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  SENTINEL-MAIL  .  Report Generator Pipeline Test", "bold", "magenta"))
    print(c(f"{'=' * 78}", "bold"))
    print(f"  Emails : {len(eml_files)}")

    # Initialize all engines
    hp = HeaderParser(offline_mode=True)
    nlp = NLPEngine(lightweight=True)
    visual = VisualEngine()
    attribution = AttributionGraph()
    fusion = FusionEngine()
    reports = ReportGenerator()

    # Output directory
    out_dir = PROJECT_ROOT / "data" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    from reports.report_generator import _HAS_WEASYPRINT
    print(f"  WeasyPrint import status: {'functional' if _HAS_WEASYPRINT else 'disabled (fallback active)'}")

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

        # 6. Generate Reports
        engines = {
            "HeaderParser": header_res,
            "NLPEngine": nlp_res,
            "VisualEngine": visual_res,
            "AttributionGraph": attr_res,
        }

        # 6a. Generate PDF bytes
        pdf_bytes = reports.generate_pdf(verdict, engines)
        pdf_path = out_dir / f"{path.stem}_report.pdf"
        pdf_path.write_bytes(pdf_bytes)
        print(f"    Saved PDF report  : {c(str(pdf_path.relative_to(PROJECT_ROOT)), 'green')} ({len(pdf_bytes):,} bytes)")

        # 6b. Generate JSON dict
        json_report = reports.generate_json(verdict, engines)
        json_path = out_dir / f"{path.stem}_report.json"
        json_path.write_text(json.dumps(json_report, indent=2), encoding="utf-8")
        print(f"    Saved JSON report : {c(str(json_path.relative_to(PROJECT_ROOT)), 'green')} ({json_path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
