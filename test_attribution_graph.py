#!/usr/bin/env python3
"""
test_attribution_graph.py — End-to-End Test for Threat Attribution & Campaign Graph.

Runs all 5 sample emails through the full engine pipeline (HeaderParser, NLPEngine,
VisualEngine), builds the batch Attribution Graph, detects campaign clusters, exports
JSON node-link format, and renders a static PNG visualization using Matplotlib.
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
from engines.attribution_graph import AttributionGraph, render_graph_png

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
    ap = argparse.ArgumentParser(description="Test the Attribution Graph & Campaign Engine")
    ap.add_argument("files", nargs="*", help="Specific .eml files")
    args = ap.parse_args()

    sample_dir = PROJECT_ROOT / "data" / "sample_emails"
    eml_files = [Path(f) for f in args.files] if args.files else sorted(sample_dir.glob("*.eml"))

    if not eml_files:
        print(c("No .eml files found!", "red"))
        sys.exit(1)

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  SENTINEL-MAIL  .  Batch Attribution Graph & Campaign Test", "bold", "magenta"))
    print(c(f"{'=' * 78}", "bold"))
    print(f"  Target Emails: {len(eml_files)}")
    for ef in eml_files:
        print(f"   - {ef.name}")

    # Initialize engines
    hp = HeaderParser(offline_mode=True)
    nlp = NLPEngine(lightweight=True)
    visual = VisualEngine()
    attribution = AttributionGraph()

    # 1. Run all emails through pipeline steps 3-5
    email_results = []
    print(f"\n[*] Processing emails through Header, NLP, and Visual engines...")
    for path in eml_files:
        header_res = hp.analyse(str(path))
        subject, body, urls = NLPEngine.extract_email_text(str(path))
        nlp_res = nlp.analyse(subject, body, urls)
        visual_res = visual.analyse_eml(str(path))
        email_results.append((header_res, nlp_res, visual_res))
        print(f"    [+] {c(path.name, 'green')}: parsed successfully.")

    # 2. Build Batch Attribution Graph
    print(f"\n[*] Building Batch Attribution Graph & Detecting Campaigns...")
    batch_res = attribution.build_batch(email_results)

    graph = batch_res["graph"]
    nodes = batch_res["nodes"]
    edges = batch_res["edges"]
    json_data = batch_res["json_data"]
    campaigns = batch_res["campaigns"]
    attributions = batch_res["attributions"]
    indicators = batch_res["indicators"]

    print(f"\n    {c('Graph Statistics:', 'bold', 'cyan')}")
    print(f"      Total Nodes : {len(nodes)}")
    print(f"      Total Edges : {len(edges)}")
    print(f"      JSON Data   : {len(json_data.get('nodes', []))} nodes, {len(json_data.get('links', []))} links exported")

    # Node Breakdown
    node_types: dict[str, list[str]] = {}
    for n in nodes:
        ntype = n.get("type", "unknown")
        node_types.setdefault(ntype, []).append(n["id"])

    print(f"\n    {c('Node Type Distribution:', 'bold')}")
    for ntype, nlist in node_types.items():
        print(f"      - {ntype:<15}: {len(nlist)} ({', '.join(nlist[:3])}{'...' if len(nlist) > 3 else ''})")

    # 3. Campaign / Cluster Verification
    print(f"\n    {c('Detected Campaign Clusters:', 'bold', 'yellow')}")
    phish_emails_clustered = set()
    for camp in campaigns:
        e_list = camp["emails"]
        badge = c("PHISHING CAMPAIGN", "red", "bold") if camp["is_phishing"] else c("LEGITIMATE / ISOLATED", "green")
        print(f"\n      [{badge}] {camp['campaign_id']} ({len(e_list)} emails)")
        print(f"        Emails : {', '.join(e_list)}")
        if camp["shared_domains"]:
            print(f"        Shared Domains : {', '.join(camp['shared_domains'])}")
        if camp["shared_ips"]:
            print(f"        Shared IPs     : {', '.join(camp['shared_ips'])}")
        if camp["shared_hosts"]:
            print(f"        Shared Relays  : {', '.join(camp['shared_hosts'])}")

        if camp["is_phishing"]:
            for e in e_list:
                phish_emails_clustered.add(e)

    # Confirm phishing emails cluster
    expected_phish = {"phish_qr_mfa.eml", "phish_ceo_wire_fraud.eml", "phish_microsoft_security.eml"}
    found_phish = expected_phish & phish_emails_clustered
    print(f"\n    {c('Clustering Verification:', 'bold', 'cyan')}")
    print(f"      Expected Phishing Emails : {', '.join(sorted(expected_phish))}")
    print(f"      Clustered Phishing Emails: {', '.join(sorted(found_phish))}")
    assert len(found_phish) >= 2, "Expected phishing emails to cluster together!"

    # 4. Threat Intel Attribution
    print(f"\n    {c('Threat Intel Attributions:', 'bold', 'magenta')}")
    print(f"      Summary: {batch_res['summary']}")
    for attr in attributions:
        print(f"      * [{c(attr['severity'].upper(), 'red' if attr['severity'] == 'critical' else 'yellow', 'bold')}] {attr['actor_name']} ({attr['confidence']}% confidence)")
        print(f"        Matches: {', '.join(attr['matched_indicators'])}")

    # 5. Render PNG Sanity Check
    print(f"\n[*] Rendering static PNG graph with Matplotlib...")
    png_path = PROJECT_ROOT / "attribution_graph.png"
    out_png = render_graph_png(graph, str(png_path))
    assert Path(out_png).exists(), "PNG file was not generated!"
    print(c(f"  [+] Saved static PNG visualization to: {out_png}", "green", "bold"))

    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  [SUCCESS] All attribution graph and campaign clustering tests passed!", "green", "bold"))
    print(c(f"{'=' * 78}\n", "bold"))


if __name__ == "__main__":
    main()
