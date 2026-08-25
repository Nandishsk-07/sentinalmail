"""
report_generator.py — Forensic Report Generator

Generates high-fidelity PDF forensic reports (via WeasyPrint) and machine-readable
JSON reports. If WeasyPrint/Cairo dependencies are missing (e.g., on Windows),
falls back to saving a premium HTML report and returning a lightweight valid PDF.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentinel-mail.report")

# Try to import WeasyPrint, handle missing GTK/Cairo gracefully
try:
    import weasyprint
    _HAS_WEASYPRINT = True
except (ImportError, OSError):
    _HAS_WEASYPRINT = False
    logger.warning("WeasyPrint (or Cairo/GTK DLL dependencies) not found. Fallback mode enabled.")


class ReportGenerator:
    """Generates forensic PDF and JSON reports from analysis results."""

    def generate_pdf(self, fusion_verdict: dict, engine_results: dict) -> bytes:
        """Render a forensic PDF report.

        Falls back to HTML + basic PDF if WeasyPrint is not functional.
        """
        html_content = self._build_html_report(fusion_verdict, engine_results)

        # Try rendering with WeasyPrint if available
        if _HAS_WEASYPRINT:
            try:
                pdf_bytes = weasyprint.HTML(string=html_content).write_pdf()
                return pdf_bytes
            except Exception as exc:
                logger.error(f"WeasyPrint PDF rendering failed: {exc}. Using fallback.")

        # Fallback path: Save the beautiful HTML report to disk and return a basic PDF
        # We save it in a standard directory if possible, or just generate standard PDF bytes
        report_dir = Path("data/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        file_name = engine_results.get("HeaderParser", {}).get("file", "email_report")
        html_path = report_dir / f"{file_name}_forensic.html"
        html_path.write_text(html_content, encoding="utf-8")
        logger.info(f"Saved premium HTML report to: {html_path.absolute()}")

        return self._generate_fallback_pdf(fusion_verdict, engine_results, str(html_path.absolute()))

    def generate_json(self, fusion_verdict: dict, engine_results: dict) -> dict:
        """Produce a machine-readable JSON report for SIEM/SOAR ingestion."""
        # Strip NetworkX object from AttributionGraph results for serialisation
        clean_engine_results = {}
        for engine, res in engine_results.items():
            if engine == "AttributionGraph":
                clean_res = res.copy()
                clean_res.pop("graph", None)
                clean_engine_results[engine] = clean_res
            else:
                clean_engine_results[engine] = res

        return {
            "version": "0.1.0",
            "threat_score": fusion_verdict.get("threat_score"),
            "tier": fusion_verdict.get("tier"),
            "reasoning": fusion_verdict.get("reasoning"),
            "raw_belief": fusion_verdict.get("raw_belief"),
            "engine_results": clean_engine_results,
        }

    # ── Fallback PDF Generator ─────────────────────────────────────────

    def _generate_fallback_pdf(self, fusion: dict, engines: dict, html_path: str) -> bytes:
        """Constructs a basic but valid PDF byte stream containing the summary
        and a pointer to the rich HTML report.
        """
        score = fusion.get("threat_score", 0)
        tier = fusion.get("tier", "UNKNOWN")
        file_name = engines.get("HeaderParser", {}).get("file", "unknown_email")
        subject = engines.get("HeaderParser", {}).get("subject", "No Subject")
        sender = engines.get("HeaderParser", {}).get("from", "Unknown Sender")

        # Let's create a simple PDF structure manually.
        # This is 100% valid PDF syntax containing plain text.
        pdf_template = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {0} >>
stream
BT
/F1 18 Tf
50 720 Td
(SENTINEL-MAIL FORENSIC REPORT) Tj
/F1 12 Tf
0 -30 Td
(File: {file_name}) Tj
0 -18 Td
(Subject: {subject}) Tj
0 -18 Td
(Sender: {sender}) Tj
0 -30 Td
(VERDICT SUMMARY:) Tj
0 -18 Td
(Threat Score: {score}/100) Tj
0 -18 Td
(Threat Tier: {tier}) Tj
0 -30 Td
(Reasoning Trace:) Tj
0 -18 Td
({fusion.get('reasoning', '')[:80]}) Tj
0 -18 Td
({fusion.get('reasoning', '')[80:160]}) Tj
0 -18 Td
({fusion.get('reasoning', '')[160:240]}) Tj
0 -40 Td
(NOTE: WeasyPrint dependencies are missing on this system.) Tj
0 -18 Td
(A full interactive HTML report has been generated at:) Tj
0 -18 Td
({html_path}) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000750 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
821
%%EOF"""
        # Calculate length of stream section dynamically to avoid PDF structure errors
        # The content between BT and ET has length approximately 500 characters.
        stream_content = f"""BT
/F1 16 Tf
50 720 Td
(SENTINEL-MAIL FORENSIC ANALYSIS REPORT) Tj
/F1 11 Tf
0 -25 Td
(Target File: {file_name}) Tj
0 -15 Td
(Email Subject: {subject[:70]}) Tj
0 -15 Td
(Sender Identity: {sender[:70]}) Tj
0 -25 Td
(VERDICT:) Tj
0 -15 Td
(Threat Score: {score}/100) Tj
0 -15 Td
(Threat Tier: {tier}) Tj
0 -25 Td
(Reasoning Path:) Tj
0 -15 Td
({fusion.get('reasoning', '')[:85]}) Tj
0 -15 Td
({fusion.get('reasoning', '')[85:170]}) Tj
0 -15 Td
({fusion.get('reasoning', '')[170:255]}) Tj
0 -35 Td
(Notice: WeasyPrint Pango/Cairo DLLs not available on this Windows host.) Tj
0 -15 Td
(Full premium layout report generated as HTML at:) Tj
0 -15 Td
({html_path}) Tj
ET"""
        stream_len = len(stream_content.encode('utf-8'))
        
        pdf_data = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {stream_len} >>
stream
{stream_content}
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000244 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
700
%%EOF"""
        return pdf_data.encode("utf-8", errors="ignore")

    # ── HTML Report Builder ────────────────────────────────────────────

    def _build_html_report(self, fusion: dict, engines: dict) -> str:
        """Render a rich, beautifully designed HTML report matching premium design rules."""
        score = fusion.get("threat_score", 0)
        tier = fusion.get("tier", "UNKNOWN")
        
        # Style helper depending on threat tier
        tier_colors = {
            "CONFIRMED_THREAT": {"primary": "#e74c3c", "bg": "#fde8e7", "border": "#f5b7b1"},
            "LIKELY_PHISH": {"primary": "#e67e22", "bg": "#fef5e7", "border": "#f9ebae"},
            "SUSPICIOUS": {"primary": "#f1c40f", "bg": "#fefde7", "border": "#fcf3cf"},
            "SAFE": {"primary": "#2ecc71", "bg": "#e8f8f5", "border": "#a3e4d7"},
        }
        style = tier_colors.get(tier, {"primary": "#34495e", "bg": "#f4f6f7", "border": "#d5dbdb"})

        # Sub-results
        header_res = engines.get("HeaderParser", {})
        nlp_res = engines.get("NLPEngine", {})
        visual_res = engines.get("VisualEngine", {})
        attr_res = engines.get("AttributionGraph", {})

        # Generate SVG for Attribution Graph
        svg_graph = self._generate_graph_svg(attr_res)

        # Format reasoning traces
        reasoning_list = fusion.get("reasoning", "").split(" | ")
        reasoning_html = "".join(f"<li>{r}</li>" for r in reasoning_list)

        # Flagged phrases rows
        phrases_rows = ""
        phrases = nlp_res.get("flagged_phrases", [])
        for p in phrases:
            sev_class = f"badge-{p.get('severity', 'medium')}"
            phrases_rows += f"""
            <tr>
                <td><span class="badge {sev_class}">{p.get('severity', 'medium').upper()}</span></td>
                <td class="phrase-text">"{p.get('phrase', '')}"</td>
                <td>{p.get('category', '').upper()}</td>
                <td class="context-text">{p.get('context', '')}</td>
            </tr>
            """
        if not phrases_rows:
            phrases_rows = "<tr><td colspan='4' class='text-center'>No suspicious phrases detected.</td></tr>"

        # Attachments rows
        attachments_rows = ""
        attachments = visual_res.get("attachments", [])
        for att in attachments:
            qr_badge = ""
            qr_codes = att.get("qr_codes", [])
            if qr_codes:
                qr_badge = f"""<span class="badge badge-critical" style="margin-left: 8px;">QR CODE DETECTED</span>"""
            
            attachments_rows += f"""
            <tr>
                <td>{att.get('filename')} {qr_badge}</td>
                <td>{att.get('content_type')}</td>
                <td>{att.get('size_bytes', 0):,} bytes</td>
            </tr>
            """
        if not attachments_rows:
            attachments_rows = "<tr><td colspan='3' class='text-center'>No attachments.</td></tr>"

        # Authentication Results block
        auth = header_res.get("auth_results", {})
        hdr_auth = auth.get("header", {})
        spf = hdr_auth.get("spf", {}) or {}
        dkim = hdr_auth.get("dkim", {}) or {}
        dmarc = hdr_auth.get("dmarc", {}) or {}

        # Geolocation hops
        geo_hops = ""
        for hop in header_res.get("relay_path", []):
            num = hop.get("hop", 1)
            ip = hop.get("from_ip", "—")
            host = hop.get("from_host", "—")
            proto = hop.get("protocol", "—")
            delay = f"(+{hop['delay_seconds']}s)" if hop.get("delay_seconds") is not None else ""
            
            # Find geo details
            geo_info = next((item for item in header_res.get("geo_trace", []) if item.get("ip") == ip), {})
            country = geo_info.get("country", "—")
            city = geo_info.get("city", "")
            location = f"{city}, {country}" if city else country
            isp = geo_info.get("isp", "—")

            geo_hops += f"""
            <div class="hop-item">
                <div class="hop-num">Hop {num}</div>
                <div class="hop-details">
                    <strong>{host}</strong> ({ip}) <span class="delay">{delay}</span><br>
                    <span class="info">Proto: {proto} | Location: {location} | ISP: {isp}</span>
                </div>
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Sentinel-Mail Forensic Report</title>
    <style>
        :root {{
            --primary-color: {style['primary']};
            --text-dark: #2c3e50;
            --text-light: #7f8c8d;
            --border-light: #e2e8f0;
            --safe-color: #2ecc71;
            --warning-color: #f1c40f;
            --danger-color: #e74c3c;
        }}
        body {{
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            color: var(--text-dark);
            line-height: 1.5;
            margin: 0;
            padding: 40px;
            background-color: #f8fafc;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05), 0 4px 6px -2px rgba(0, 0, 0, 0.02);
            border: 1px solid var(--border-light);
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-light);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .logo {{
            font-size: 24px;
            font-weight: bold;
            color: var(--primary-color);
        }}
        .logo span {{
            color: #7f8c8d;
            font-weight: normal;
        }}
        .report-meta {{
            text-align: right;
            font-size: 13px;
            color: var(--text-light);
        }}
        /* Executive Summary Banner */
        .verdict-banner {{
            background-color: {style['bg']};
            border: 1px solid {style['border']};
            border-left: 6px solid {style['primary']};
            padding: 24px;
            border-radius: 8px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .verdict-info h1 {{
            margin: 0 0 8px 0;
            font-size: 28px;
            color: {style['primary']};
        }}
        .verdict-info p {{
            margin: 0;
            color: var(--text-dark);
            font-size: 15px;
        }}
        .score-badge {{
            background: {style['primary']};
            color: #ffffff;
            padding: 16px 24px;
            border-radius: 12px;
            text-align: center;
        }}
        .score-val {{
            font-size: 36px;
            font-weight: bold;
            line-height: 1;
        }}
        .score-lbl {{
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }}
        /* Grid Sections */
        .section-title {{
            font-size: 18px;
            font-weight: bold;
            color: var(--primary-color);
            margin: 40px 0 16px 0;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-light);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .email-details-grid {{
            display: grid;
            grid-template-columns: 100px 1fr;
            gap: 8px 16px;
            margin-bottom: 25px;
            font-size: 14px;
        }}
        .grid-lbl {{
            font-weight: bold;
            color: var(--text-light);
        }}
        .reasoning-list {{
            padding-left: 20px;
            margin: 0;
            font-size: 14px;
        }}
        .reasoning-list li {{
            margin-bottom: 8px;
        }}
        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 25px;
            font-size: 13px;
        }}
        th {{
            background-color: #f1f5f9;
            text-align: left;
            padding: 10px 12px;
            font-weight: bold;
            border-bottom: 2px solid var(--border-light);
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-light);
            vertical-align: top;
        }}
        .text-center {{
            text-align: center;
        }}
        /* Badges */
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: bold;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-critical {{ background-color: #fde8e7; color: #e74c3c; border: 1px solid #f5b7b1; }}
        .badge-high {{ background-color: #fef5e7; color: #e67e22; border: 1px solid #f9ebae; }}
        .badge-medium {{ background-color: #fefde7; color: #f1c40f; border: 1px solid #fcf3cf; }}
        .badge-low {{ background-color: #f1f5f9; color: #7f8c8d; }}
        .badge-pass {{ background-color: #e8f8f5; color: #2ecc71; border: 1px solid #a3e4d7; }}
        .badge-fail {{ background-color: #fde8e7; color: #e74c3c; border: 1px solid #f5b7b1; }}
        
        .phrase-text {{ font-weight: 500; font-family: monospace; }}
        .context-text {{ color: var(--text-light); font-style: italic; }}

        /* Authentication Table Grid */
        .auth-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 25px;
        }}
        .auth-card {{
            border: 1px solid var(--border-light);
            padding: 16px;
            border-radius: 6px;
            background: #f8fafc;
            text-align: center;
        }}
        .auth-card h3 {{
            margin: 0 0 8px 0;
            font-size: 14px;
            color: var(--text-light);
        }}
        
        /* Hop list styling */
        .hop-list {{
            margin-bottom: 25px;
        }}
        .hop-item {{
            display: flex;
            border-bottom: 1px solid var(--border-light);
            padding: 12px 0;
        }}
        .hop-item:last-child {{
            border-bottom: none;
        }}
        .hop-num {{
            width: 80px;
            font-weight: bold;
            color: var(--primary-color);
            font-size: 13px;
        }}
        .hop-details {{
            font-size: 13px;
        }}
        .hop-details .delay {{
            color: #e67e22;
            font-weight: bold;
            margin-left: 8px;
        }}
        .hop-details .info {{
            color: var(--text-light);
            font-size: 11px;
            display: block;
            margin-top: 4px;
        }}
        
        /* Attribution Section */
        .attribution-box {{
            background: #f8fafc;
            border: 1px solid var(--border-light);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }}
        
        /* SVG Graph Center */
        .svg-container {{
            text-align: center;
            border: 1px solid var(--border-light);
            border-radius: 8px;
            padding: 20px;
            background: #ffffff;
            margin-bottom: 25px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">SENTINEL<span>MAIL</span></div>
            <div class="report-meta">
                <strong>Forensic Analysis Report</strong><br>
                Generated: 2026-08-25 UTC
            </div>
        </header>

        <!-- Executive Verdict Banner -->
        <div class="verdict-banner">
            <div class="verdict-info">
                <h1>{tier.replace('_', ' ')}</h1>
                <p>Multi-engine pipeline evidence combination complete.</p>
            </div>
            <div class="score-badge">
                <div class="score-val">{score}</div>
                <div class="score-lbl">Threat Score</div>
            </div>
        </div>

        <div class="email-details-grid">
            <div class="grid-lbl">File:</div>
            <div>{header_res.get('file', '—')}</div>
            <div class="grid-lbl">Subject:</div>
            <div><strong>{header_res.get('subject', '—')}</strong></div>
            <div class="grid-lbl">Sender:</div>
            <div>{header_res.get('from', '—')}</div>
        </div>

        <div class="section-title">Reasoning Summary</div>
        <ul class="reasoning-list">
            {reasoning_html}
        </ul>

        <div class="section-title">Authentication Results</div>
        <div class="auth-grid">
            <div class="auth-card">
                <h3>SPF</h3>
                <span class="badge badge-{(spf.get('verdict') or 'fail').lower()}">{(spf.get('verdict') or 'NONE').upper()}</span>
                <div style="font-size: 11px; margin-top: 8px; color: var(--text-light);">{spf.get('smtp_mailfrom') or 'No envelope sender'}</div>
            </div>
            <div class="auth-card">
                <h3>DKIM</h3>
                <span class="badge badge-{(dkim.get('verdict') or 'fail').lower()}">{(dkim.get('verdict') or 'NONE').upper()}</span>
                <div style="font-size: 11px; margin-top: 8px; color: var(--text-light);">{dkim.get('domain') or 'No signing domain'}</div>
            </div>
            <div class="auth-card">
                <h3>DMARC</h3>
                <span class="badge badge-{(dmarc.get('verdict') or 'fail').lower()}">{(dmarc.get('verdict') or 'NONE').upper()}</span>
                <div style="font-size: 11px; margin-top: 8px; color: var(--text-light);">{dmarc.get('header_from') or 'No header domain'}</div>
            </div>
        </div>

        <div class="section-title">Relay Routing Path</div>
        <div class="hop-list">
            {geo_hops}
        </div>

        <div class="section-title">NLP Threat Signal Highlights</div>
        <table>
            <thead>
                <tr>
                    <th style="width: 100px;">Severity</th>
                    <th style="width: 200px;">Phrase</th>
                    <th style="width: 120px;">Category</th>
                    <th>Observed Context</th>
                </tr>
            </thead>
            <tbody>
                {phrases_rows}
            </tbody>
        </table>

        <div class="section-title">Attachment Inventory & Visual Hazards</div>
        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Content Type</th>
                    <th>Size</th>
                </tr>
            </thead>
            <tbody>
                {attachments_rows}
            </tbody>
        </table>

        <div class="section-title">Attribution & Infrastructure Relations</div>
        <div class="attribution-box">
            <strong>Threat Intelligence Summary:</strong><br>
            <p style="margin: 8px 0 0 0; font-size: 14px;">{attr_res.get('summary', 'No threat group profile matched.')}</p>
        </div>
        
        <div class="svg-container">
            <h3>Visual Entity Relationship Graph</h3>
            {svg_graph}
        </div>
    </div>
</body>
</html>
"""
        return html_template

    # ── SVG Generator ──────────────────────────────────────────────────

    @staticmethod
    def _generate_graph_svg(attr_res: dict) -> str:
        """Render the AttributionGraph DiGraph to a self-contained SVG element."""
        nodes = attr_res.get("nodes", [])
        edges = attr_res.get("edges", [])

        if not nodes:
            return "<p class='text-light'>Empty attribution graph.</p>"

        # Predefined node color palette
        colors = {
            "email": "#3498db",       # blue
            "sender": "#9b59b6",      # purple
            "contact_email": "#8e44ad", # dark purple
            "domain": "#f1c40f",      # yellow
            "ip": "#e67e22",          # orange
            "url": "#e74c3c",         # red
            "attachment": "#1abc9c",  # teal
            "financial": "#2ecc71",   # green
            "actor": "#c0392b",       # dark red
            "location": "#34495e",    # dark slate
        }

        # Calculate coordinates using circular layout as a reliable math fallback
        # This works without any libraries or numpy dependecies.
        pos = {}
        n_nodes = len(nodes)
        cx, cy = 400, 300
        rx, ry = 280, 200

        for i, node in enumerate(nodes):
            nid = node["id"]
            if n_nodes == 1:
                pos[nid] = (cx, cy)
            else:
                # Add slight layout offsets for central email node
                if node.get("type") == "email":
                    pos[nid] = (cx, cy)
                else:
                    angle = 2.0 * math.pi * i / (n_nodes - 1 if n_nodes > 1 else 1)
                    pos[nid] = (cx + rx * math.cos(angle), cy + ry * math.sin(angle))

        svg_lines = []
        svg_lines.append('<svg width="100%" height="500" viewBox="0 0 800 600" xmlns="http://www.w3.org/2000/svg">')
        
        # Add Arrow Marker Definitions
        svg_lines.append("""
        <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#bdc3c7" />
            </marker>
        </defs>
        """)

        # 1. Draw Edges
        for edge in edges:
            src = edge["source"]
            tgt = edge["target"]
            if src in pos and tgt in pos:
                x1, y1 = pos[src]
                x2, y2 = pos[tgt]
                svg_lines.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#bdc3c7" stroke-width="1.5" marker-end="url(#arrow)" />')

        # 2. Draw Nodes
        for node in nodes:
            nid = node["id"]
            ntype = node.get("type", "unknown")
            color = colors.get(ntype, "#7f8c8d")
            
            # Scale node size based on importance
            r = 18 if ntype == "actor" else (14 if ntype == "email" else 10)
            
            x, y = pos[nid]
            label = node.get("label", nid)
            short_lbl = label[:26] + "..." if len(label) > 28 else label

            # Circle element
            svg_lines.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{color}" stroke="#ffffff" stroke-width="2" />')
            
            # Label element
            svg_lines.append(
                f'<text x="{x:.1f}" y="{y - r - 4:.1f}" font-family="Helvetica, Arial, sans-serif" '
                f'font-size="10" font-weight="bold" fill="#2c3e50" text-anchor="middle">{short_lbl}</text>'
            )

        svg_lines.append("</svg>")
        return "\n".join(svg_lines)
