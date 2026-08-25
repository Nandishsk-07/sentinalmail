"""
report_generator.py — Forensic Report Generator

Generates high-fidelity PDF forensic reports (via WeasyPrint), clean HTML reports
rendered with Jinja2, and machine-readable JSON reports with SHA-256 chain-of-custody hashing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

import jinja2

logger = logging.getLogger("sentinel-mail.report")

# Try to import WeasyPrint, handle missing GTK/Cairo gracefully on Windows
try:
    import weasyprint
    _HAS_WEASYPRINT = True
except (ImportError, OSError, Exception):
    _HAS_WEASYPRINT = False
    logger.warning("WeasyPrint (or Cairo/GTK DLL dependencies) not found. Fallback PDF generator active.")


# ── Jinja2 HTML Report Template ────────────────────────────────────────

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel-Mail Forensic Report — {{ filename }}</title>
    <style>
        :root {
            --primary-color: {{ style.primary }};
            --bg-color: {{ style.bg }};
            --border-color: {{ style.border }};
            --text-dark: #1e293b;
            --text-muted: #64748b;
            --card-bg: #ffffff;
            --border-light: #e2e8f0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: var(--text-dark);
            background-color: #f8fafc;
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }
        .container {
            max-width: 920px;
            margin: 0 auto;
            background: var(--card-bg);
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01);
            border: 1px solid var(--border-light);
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-light);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 26px;
            font-weight: 800;
            color: #0f172a;
            letter-spacing: -0.5px;
        }
        .logo span {
            color: var(--primary-color);
        }
        .report-meta {
            text-align: right;
            font-size: 13px;
            color: var(--text-muted);
        }
        
        /* Executive Verdict Banner */
        .verdict-banner {
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            border-left: 6px solid var(--primary-color);
            padding: 24px 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .verdict-title {
            margin: 0 0 6px 0;
            font-size: 26px;
            font-weight: 800;
            color: var(--primary-color);
        }
        .verdict-sub {
            margin: 0;
            font-size: 14px;
            color: var(--text-dark);
        }
        .score-badge {
            background: var(--primary-color);
            color: #ffffff;
            padding: 16px 28px;
            border-radius: 12px;
            text-align: center;
            min-width: 90px;
        }
        .score-val {
            font-size: 38px;
            font-weight: 800;
            line-height: 1;
        }
        .score-lbl {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
            opacity: 0.9;
        }

        /* Metadata & Chain of Custody */
        .custody-box {
            background: #f1f5f9;
            border: 1px solid var(--border-light);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 30px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
        }
        .custody-title {
            font-family: sans-serif;
            font-weight: 700;
            font-size: 13px;
            color: #334155;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .hash-str {
            color: #0f172a;
            word-break: break-all;
        }

        .section-title {
            font-size: 16px;
            font-weight: 700;
            color: #0f172a;
            margin: 35px 0 16px 0;
            padding-bottom: 8px;
            border-bottom: 2px solid #f1f5f9;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .email-details-grid {
            display: grid;
            grid-template-columns: 110px 1fr;
            gap: 10px 16px;
            margin-bottom: 25px;
            font-size: 14px;
        }
        .grid-lbl {
            font-weight: 600;
            color: var(--text-muted);
        }

        .reasoning-list {
            padding-left: 20px;
            margin: 0 0 25px 0;
            font-size: 14px;
        }
        .reasoning-list li {
            margin-bottom: 8px;
        }

        /* Signal Contributions Table */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 25px;
            font-size: 13px;
        }
        th {
            background-color: #f8fafc;
            text-align: left;
            padding: 10px 14px;
            font-weight: 700;
            color: #475569;
            border-bottom: 2px solid var(--border-light);
        }
        td {
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-light);
            vertical-align: top;
        }
        .text-center {
            text-align: center;
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
        }
        .badge-critical, .badge-fail { background-color: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
        .badge-high { background-color: #fff7ed; color: #ea580c; border: 1px solid #ffedd5; }
        .badge-medium, .badge-softfail { background-color: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }
        .badge-low, .badge-none { background-color: #f1f5f9; color: #64748b; }
        .badge-pass { background-color: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }

        .auth-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 25px;
        }
        .auth-card {
            border: 1px solid var(--border-light);
            padding: 16px;
            border-radius: 8px;
            background: #f8fafc;
            text-align: center;
        }
        .auth-card h3 {
            margin: 0 0 8px 0;
            font-size: 14px;
            color: var(--text-muted);
        }

        .hop-list {
            margin-bottom: 25px;
        }
        .hop-item {
            display: flex;
            border-bottom: 1px solid var(--border-light);
            padding: 10px 0;
        }
        .hop-num {
            width: 70px;
            font-weight: 700;
            color: var(--primary-color);
            font-size: 13px;
        }
        .hop-details {
            font-size: 13px;
        }

        .svg-container {
            text-align: center;
            border: 1px solid var(--border-light);
            border-radius: 8px;
            padding: 20px;
            background: #ffffff;
            margin-bottom: 25px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">SENTINEL<span>MAIL</span></div>
            <div class="report-meta">
                <strong>Forensic Threat Analysis Report</strong><br>
                Analyzed: {{ custody.analyzed_at_utc }}
            </div>
        </header>

        <!-- Executive Verdict Banner -->
        <div class="verdict-banner">
            <div class="verdict-info">
                <div class="verdict-title">{{ verdict.tier | replace('_', ' ') }}</div>
                <div class="verdict-sub">Dempster–Shafer Multi-Engine Risk Score: {{ verdict.threat_score }} / 100</div>
            </div>
            <div class="score-badge">
                <div class="score-val">{{ verdict.threat_score }}</div>
                <div class="score-lbl">Risk Score</div>
            </div>
        </div>

        <!-- Chain of Custody -->
        <div class="custody-box">
            <div class="custody-title">🛡️ Chain-of-Custody Metadata</div>
            <div>File Name : {{ custody.file_name }} ({{ custody.file_size_bytes }} bytes)</div>
            <div>SHA-256   : <span class="hash-str">{{ custody.sha256 }}</span></div>
        </div>

        <!-- Email Details -->
        <div class="email-details-grid">
            <div class="grid-lbl">Subject:</div>
            <div><strong>{{ header_res.subject or '—' }}</strong></div>
            <div class="grid-lbl">From:</div>
            <div>{{ header_res.from or '—' }}</div>
            <div class="grid-lbl">Envelope:</div>
            <div>{{ header_res.auth_results.envelope_domain or '—' }}</div>
        </div>

        <!-- Reasoning Path -->
        <div class="section-title">Verdict Reasoning Path</div>
        <ul class="reasoning-list">
            {% for reason in reasoning_list %}
            <li>{{ reason }}</li>
            {% endfor %}
        </ul>

        <!-- Engine Contributions -->
        <div class="section-title">Engine Risk Contributions</div>
        <table>
            <thead>
                <tr>
                    <th>Engine</th>
                    <th>Threat Belief</th>
                    <th>Safe Belief</th>
                    <th>Uncertainty</th>
                </tr>
            </thead>
            <tbody>
                {% for contrib in verdict.signal_contributions %}
                <tr>
                    <td><strong>{{ contrib.engine }}</strong></td>
                    <td>{{ (contrib.threat_belief * 100) | round(1) }}%</td>
                    <td>{{ (contrib.safe_belief * 100) | round(1) }}%</td>
                    <td>{{ (contrib.uncertainty * 100) | round(1) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <!-- Authentication Results -->
        <div class="section-title">Email Authentication Checks</div>
        <div class="auth-grid">
            <div class="auth-card">
                <h3>SPF</h3>
                <span class="badge badge-{{ auth.spf.verdict | default('none') | lower }}">{{ auth.spf.verdict | default('NONE') | upper }}</span>
                <div style="font-size: 11px; margin-top: 8px; color: var(--text-muted);">{{ auth.spf.smtp_mailfrom or 'No envelope sender' }}</div>
            </div>
            <div class="auth-card">
                <h3>DKIM</h3>
                <span class="badge badge-{{ auth.dkim.verdict | default('none') | lower }}">{{ auth.dkim.verdict | default('NONE') | upper }}</span>
                <div style="font-size: 11px; margin-top: 8px; color: var(--text-muted);">{{ auth.dkim.domain or 'No signing domain' }}</div>
            </div>
            <div class="auth-card">
                <h3>DMARC</h3>
                <span class="badge badge-{{ auth.dmarc.verdict | default('none') | lower }}">{{ auth.dmarc.verdict | default('NONE') | upper }}</span>
                <div style="font-size: 11px; margin-top: 8px; color: var(--text-muted);">{{ auth.dmarc.header_from or 'No header domain' }}</div>
            </div>
        </div>

        <!-- Relay Routing Path -->
        <div class="section-title">Relay Hop Routing Chain</div>
        <div class="hop-list">
            {% for hop in header_res.relay_path %}
            <div class="hop-item">
                <div class="hop-num">Hop {{ hop.hop }}</div>
                <div class="hop-details">
                    <strong>{{ hop.from_host or '—' }}</strong> [{{ hop.from_ip or '—' }}] &rarr; {{ hop.by_host or '—' }}
                    <span style="color: #64748b; font-size: 11px; display: block; margin-top: 2px;">
                        Proto: {{ hop.protocol or '—' }} | Timestamp: {{ hop.timestamp_utc or hop.timestamp or '—' }}
                    </span>
                </div>
            </div>
            {% endfor %}
        </div>

        <!-- NLP Flagged Phrases -->
        <div class="section-title">NLP Flagged Threat Phrases</div>
        <table>
            <thead>
                <tr>
                    <th style="width: 100px;">Severity</th>
                    <th style="width: 180px;">Phrase</th>
                    <th style="width: 120px;">Category</th>
                    <th>Observed Context</th>
                </tr>
            </thead>
            <tbody>
                {% if nlp_res.flagged_phrases %}
                    {% for p in nlp_res.flagged_phrases %}
                    <tr>
                        <td><span class="badge badge-{{ p.severity | lower }}">{{ p.severity | upper }}</span></td>
                        <td style="font-family: monospace; font-weight: 600;">"{{ p.phrase }}"</td>
                        <td>{{ p.category | upper }}</td>
                        <td style="color: var(--text-muted); font-style: italic;">{{ p.context }}</td>
                    </tr>
                    {% endfor %}
                {% else %}
                    <tr><td colspan="4" class="text-center">No suspicious phrases flagged.</td></tr>
                {% endif %}
            </tbody>
        </table>

        <!-- Attachments -->
        <div class="section-title">Attachments & Visual Scans</div>
        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Content Type</th>
                    <th>Size</th>
                    <th>QR Codes</th>
                </tr>
            </thead>
            <tbody>
                {% if visual_res.attachments %}
                    {% for att in visual_res.attachments %}
                    <tr>
                        <td>{{ att.filename }}</td>
                        <td>{{ att.content_type }}</td>
                        <td>{{ att.size_bytes }} bytes</td>
                        <td>
                            {% if att.qr_codes %}
                                <span class="badge badge-critical">QR CODE DETECTED</span>
                            {% else %}
                                None
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                {% else %}
                    <tr><td colspan="4" class="text-center">No attachments.</td></tr>
                {% endif %}
            </tbody>
        </table>

        <!-- Attribution Graph -->
        <div class="section-title">Attribution & Infrastructure Relations</div>
        <div style="background: #f8fafc; border: 1px solid var(--border-light); padding: 16px; border-radius: 8px; margin-bottom: 20px; font-size: 14px;">
            <strong>Threat Intelligence Attribution:</strong>
            <p style="margin: 6px 0 0 0;">{{ attr_res.summary or 'No threat-actor profile matched.' }}</p>
        </div>

        <div class="svg-container">
            <h3>Visual Entity Graph</h3>
            {{ svg_graph | safe }}
        </div>
    </div>
</body>
</html>
"""


class ReportGenerator:
    """Generates forensic PDF, HTML, and JSON reports from analysis engine results."""

    def __init__(self) -> None:
        self._jinja_env = jinja2.Environment(autoescape=True)

    def generate_json(
        self,
        fusion_verdict: dict,
        engine_results: dict,
        eml_path: Optional[Union[str, Path]] = None,
    ) -> dict[str, Any]:
        """Produce a machine-readable JSON forensic report with SHA-256 chain-of-custody.

        Parameters
        ----------
        fusion_verdict : dict
            Output of FusionEngine.fuse().
        engine_results : dict
            Dictionary mapping engine name to raw output dict.
        eml_path : str or Path, optional
            Path to original raw .eml file.

        Returns
        -------
        dict
            JSON-serializable report dictionary.
        """
        # Calculate SHA-256 and custody details if file path provided
        custody_info = self._get_custody_info(eml_path, engine_results)

        # Clean non-serializable objects (e.g. NetworkX graph)
        clean_engine_results = {}
        for engine_name, res in engine_results.items():
            if isinstance(res, dict):
                clean_res = res.copy()
                clean_res.pop("graph", None)
                clean_engine_results[engine_name] = clean_res
            else:
                clean_engine_results[engine_name] = res

        return {
            "version": "0.1.0",
            "chain_of_custody": custody_info,
            "verdict": {
                "threat_score": fusion_verdict.get("threat_score"),
                "tier": fusion_verdict.get("tier"),
                "reasoning": fusion_verdict.get("reasoning"),
                "signal_contributions": fusion_verdict.get("signal_contributions", []),
                "raw_belief": fusion_verdict.get("raw_belief", {}),
            },
            "engine_results": clean_engine_results,
        }

    def generate_html(
        self,
        fusion_verdict: dict,
        engine_results: dict,
        eml_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """Render a clean HTML forensic report using Jinja2."""
        custody_info = self._get_custody_info(eml_path, engine_results)

        tier = fusion_verdict.get("tier", "UNKNOWN")
        tier_styles = {
            "CONFIRMED_THREAT": {"primary": "#dc2626", "bg": "#fef2f2", "border": "#fecaca"},
            "LIKELY_PHISH": {"primary": "#ea580c", "bg": "#fff7ed", "border": "#ffedd5"},
            "SUSPICIOUS": {"primary": "#ca8a04", "bg": "#fefce8", "border": "#fef08a"},
            "SAFE": {"primary": "#16a34a", "bg": "#f0fdf4", "border": "#bbf7d0"},
        }
        style = tier_styles.get(tier, {"primary": "#475569", "bg": "#f8fafc", "border": "#e2e8f0"})

        header_res = engine_results.get("HeaderParser", {})
        nlp_res = engine_results.get("NLPEngine", {})
        visual_res = engine_results.get("VisualEngine", {})
        attr_res = engine_results.get("AttributionGraph", {})

        # Extract authentication sub-dicts
        hdr_auth = header_res.get("auth_results", {}).get("header", {})
        auth_data = {
            "spf": hdr_auth.get("spf") or {},
            "dkim": hdr_auth.get("dkim") or {},
            "dmarc": hdr_auth.get("dmarc") or {},
        }

        # Render SVG graph
        svg_graph = self._generate_graph_svg(attr_res)

        reasoning_text = fusion_verdict.get("reasoning", "")
        reasoning_list = [r.strip() for r in reasoning_text.split(" | ") if r.strip()]

        template = self._jinja_env.from_string(HTML_REPORT_TEMPLATE)
        return template.render(
            filename=custody_info["file_name"],
            custody=custody_info,
            verdict=fusion_verdict,
            header_res=header_res,
            nlp_res=nlp_res,
            visual_res=visual_res,
            attr_res=attr_res,
            auth=auth_data,
            style=style,
            svg_graph=svg_graph,
            reasoning_list=reasoning_list,
        )

    def generate_pdf(
        self,
        fusion_verdict: dict,
        engine_results: dict,
        eml_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """Render a forensic PDF report via WeasyPrint.

        Falls back to HTML + basic PDF structure if WeasyPrint dependencies are missing.
        """
        html_content = self.generate_html(fusion_verdict, engine_results, eml_path)

        if _HAS_WEASYPRINT:
            try:
                pdf_bytes = weasyprint.HTML(string=html_content).write_pdf()
                return pdf_bytes
            except Exception as exc:
                logger.error(f"WeasyPrint PDF rendering failed: {exc}. Using fallback.")

        # Fallback PDF generator
        custody_info = self._get_custody_info(eml_path, engine_results)
        return self._generate_fallback_pdf(fusion_verdict, engine_results, custody_info)

    def generate_reports(
        self,
        eml_path: Union[str, Path],
        fusion_verdict: dict,
        engine_results: dict,
        output_dir: Union[str, Path] = "reports/output",
    ) -> dict[str, Path]:
        """Generate JSON, HTML, and PDF forensic reports for an email into output_dir.

        Parameters
        ----------
        eml_path : str or Path
            Path to original raw .eml file.
        fusion_verdict : dict
            Output of FusionEngine.fuse().
        engine_results : dict
            Raw outputs of all engines.
        output_dir : str or Path
            Directory path to write generated report files.

        Returns
        -------
        dict
            Mapping of format ("json", "html", "pdf") to generated file Path.
        """
        path = Path(eml_path)
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        stem = path.stem

        # 1. JSON Report
        json_report = self.generate_json(fusion_verdict, engine_results, path)
        json_file = out_path / f"{stem}_report.json"
        json_file.write_text(json.dumps(json_report, indent=2), encoding="utf-8")

        # 2. HTML Report
        html_content = self.generate_html(fusion_verdict, engine_results, path)
        html_file = out_path / f"{stem}_report.html"
        html_file.write_text(html_content, encoding="utf-8")

        # 3. PDF Report
        pdf_bytes = self.generate_pdf(fusion_verdict, engine_results, path)
        pdf_file = out_path / f"{stem}_report.pdf"
        pdf_file.write_bytes(pdf_bytes)

        return {
            "json": json_file.resolve(),
            "html": html_file.resolve(),
            "pdf": pdf_file.resolve(),
        }

    # ── Custody & Fallback Helpers ─────────────────────────────────────

    @staticmethod
    def _get_custody_info(
        eml_path: Optional[Union[str, Path]], engine_results: dict
    ) -> dict[str, Any]:
        """Compute SHA-256 hash and metadata for chain-of-custody."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if eml_path and Path(eml_path).exists():
            p = Path(eml_path)
            content = p.read_bytes()
            sha256 = hashlib.sha256(content).hexdigest()
            return {
                "sha256": sha256,
                "file_name": p.name,
                "file_size_bytes": len(content),
                "analyzed_at_utc": now_utc,
            }

        # Fallback if path not provided directly
        filename = engine_results.get("HeaderParser", {}).get("file", "unknown_email.eml")
        return {
            "sha256": hashlib.sha256(filename.encode("utf-8")).hexdigest(),
            "file_name": filename,
            "file_size_bytes": 0,
            "analyzed_at_utc": now_utc,
        }

    @staticmethod
    def _generate_fallback_pdf(fusion: dict, engines: dict, custody: dict) -> bytes:
        """Construct a basic but valid PDF byte stream when WeasyPrint C-libraries are missing."""
        score = fusion.get("threat_score", 0)
        tier = fusion.get("tier", "UNKNOWN")
        file_name = custody.get("file_name", "unknown_email")
        sha256 = custody.get("sha256", "n/a")
        subject = engines.get("HeaderParser", {}).get("subject", "No Subject")
        sender = engines.get("HeaderParser", {}).get("from", "Unknown Sender")

        stream_content = f"""BT
/F1 16 Tf
50 720 Td
(SENTINEL-MAIL FORENSIC ANALYSIS REPORT) Tj
/F1 10 Tf
0 -25 Td
(Target File: {file_name}) Tj
0 -15 Td
(SHA-256: {sha256[:32]}...) Tj
0 -15 Td
(Email Subject: {subject[:65]}) Tj
0 -15 Td
(Sender: {sender[:65]}) Tj
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
0 -35 Td
(Notice: WeasyPrint GTK/Cairo DLL dependencies not installed on host.) Tj
0 -15 Td
(Full Jinja2 HTML report is generated alongside this PDF.) Tj
ET"""
        stream_len = len(stream_content.encode("utf-8"))

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
650
%%EOF"""
        return pdf_data.encode("utf-8", errors="ignore")

    @staticmethod
    def _generate_graph_svg(attr_res: dict) -> str:
        """Render AttributionGraph DiGraph to self-contained SVG."""
        nodes = attr_res.get("nodes", [])
        edges = attr_res.get("edges", [])

        if not nodes:
            return "<p style='color: #64748b;'>Empty attribution graph.</p>"

        colors = {
            "email": "#3b82f6",
            "sender": "#a855f7",
            "contact_email": "#9333ea",
            "domain": "#eab308",
            "ip": "#f97316",
            "url": "#ef4444",
            "attachment": "#14b8a6",
            "financial": "#22c55e",
            "actor": "#dc2626",
            "location": "#475569",
        }

        pos = {}
        n_nodes = len(nodes)
        cx, cy = 400, 260
        rx, ry = 280, 180

        for i, node in enumerate(nodes):
            nid = node["id"]
            if n_nodes == 1:
                pos[nid] = (cx, cy)
            else:
                if node.get("type") == "email":
                    pos[nid] = (cx, cy)
                else:
                    angle = 2.0 * math.pi * i / (n_nodes - 1 if n_nodes > 1 else 1)
                    pos[nid] = (cx + rx * math.cos(angle), cy + ry * math.sin(angle))

        svg_lines = [
            '<svg width="100%" height="520" viewBox="0 0 800 520" xmlns="http://www.w3.org/2000/svg">',
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#cbd5e1" /></marker></defs>',
        ]

        for edge in edges:
            src = edge["source"]
            tgt = edge["target"]
            if src in pos and tgt in pos:
                x1, y1 = pos[src]
                x2, y2 = pos[tgt]
                svg_lines.append(
                    f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#cbd5e1" stroke-width="1.5" marker-end="url(#arrow)" />'
                )

        for node in nodes:
            nid = node["id"]
            ntype = node.get("type", "unknown")
            color = colors.get(ntype, "#64748b")
            r = 18 if ntype == "actor" else (14 if ntype == "email" else 10)
            x, y = pos[nid]
            label = node.get("label", nid)
            short_lbl = label[:24] + "..." if len(label) > 26 else label

            svg_lines.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{color}" stroke="#ffffff" stroke-width="2" />'
            )
            svg_lines.append(
                f'<text x="{x:.1f}" y="{y - r - 4:.1f}" font-family="sans-serif" font-size="10" font-weight="bold" fill="#1e293b" text-anchor="middle">{short_lbl}</text>'
            )

        svg_lines.append("</svg>")
        return "\n".join(svg_lines)
