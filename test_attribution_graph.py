#!/usr/bin/env python3
"""
test_attribution_graph.py — Smoke-test for the Threat Attribution Knowledge Graph.

Analyses all sample emails through the three main engines, builds the graph,
and prints node-link statistics along with threat intelligence attributions.
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
    ap = argparse.ArgumentParser(description="Test the Attribution Graph Engine")
    ap.add_argument("files", nargs="*", help="Specific .eml files")
    args = ap.parse_args()

    sample_dir = PROJECT_ROOT / "data" / "sample_emails"
    eml_files = [Path(f) for f in args.files] if args.files else sorted(sample_dir.glob("*.eml"))

    if not eml_files:
        print(c("No .eml files found!", "red"))
        sys.exit(1)

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  SENTINEL-MAIL  .  Attribution Graph Engine Test", "bold", "magenta"))
    print(c(f"{'=' * 78}", "bold"))
    print(f"  Emails : {len(eml_files)}")

    # Initialize all engines
    hp = HeaderParser(offline_mode=True)
    nlp = NLPEngine(lightweight=True)
    visual = VisualEngine()
    attribution = AttributionGraph()

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

        print(f"    Graph summary:")
        print(f"      Nodes: {len(attr_res['nodes'])}")
        print(f"      Edges: {len(attr_res['edges'])}")

        # Print Nodes grouped by type
        nodes_by_type = {}
        for node in attr_res["nodes"]:
            ntype = node.get("type", "unknown")
            nodes_by_type.setdefault(ntype, []).append(node["id"])
        
        print(f"      Node breakdown:")
        for ntype, ids in nodes_by_type.items():
            print(f"        - {ntype}: {len(ids)} ({', '.join(ids[:3])}{'...' if len(ids) > 3 else ''})")

        # Threat attributions
        attributions = attr_res["attributions"]
        indicators = attr_res["indicators"]
        print(f"\n    Threat Intel Attribution:")
        print(f"      Summary: {attr_res['summary']}")
        
        if attributions:
            for attr in attributions:
                badge_style = "red" if attr["severity"] == "critical" else "yellow"
                print(f"      * [{c(attr['severity'].upper(), badge_style, 'bold')}] {attr['actor_name']} ({attr['actor_type']})")
                print(f"        Confidence: {attr['confidence']}%")
                print(f"        Matches: {', '.join(attr['matched_indicators'])}")
        
        if indicators["total_malicious_nodes"] > 0:
            print(f"      IOC hits:")
            if indicators["blocklisted_domains"]:
                print(f"        Domains: {c(', '.join(indicators['blocklisted_domains']), 'red')}")
            if indicators["blocklisted_ips"]:
                print(f"        IPs: {c(', '.join(indicators['blocklisted_ips']), 'red')}")


if __name__ == "__main__":
    main()
