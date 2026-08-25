"""
main.py — FastAPI application for Sentinel-Mail

Exposes REST API endpoints to:
  - POST /analyze — upload .eml file, run full pipeline, return JSON forensic report
  - GET /reports/{id} — retrieve stored HTML, PDF, or JSON forensic report
  - GET /campaigns — retrieve current attribution graph in node-link JSON and campaign clusters
  - POST /query — simple keyword-based natural language querying over stored analysis results
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from engines.header_parser import HeaderParser
from engines.nlp_engine import NLPEngine
from engines.visual_engine import VisualEngine
from engines.attribution_graph import AttributionGraph
from fusion.fusion_engine import FusionEngine
from reports.report_generator import ReportGenerator

app = FastAPI(
    title="Sentinel-Mail API",
    description="AI-powered email threat detection and forensic analysis REST API.",
    version="0.2.0",
)

# ── Add CORS Middleware for local frontend access ───────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Paths ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "data" / "temp_uploads"
REPORT_DIR = BASE_DIR / "data" / "reports"
SAMPLE_DIR = BASE_DIR / "data" / "sample_emails"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ── Pydantic Request Models ────────────────────────────────────────────
class QueryRequest(BaseModel):
    question: Optional[str] = Field(None, description="Natural language query string")
    query: Optional[str] = Field(None, description="Alternative field for query string")


# ── Endpoints ──────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "service": "Sentinel-Mail"}


@app.post("/analyze")
@app.post("/analyse")
async def analyze_email(
    file: UploadFile = File(...),
    offline: bool = Query(True, description="When True, skip outbound live DNS & geo-IP requests."),
    lightweight: bool = Query(True, description="When True, skip heavy HuggingFace/spaCy downloads."),
) -> dict[str, Any]:
    """Accept an uploaded .eml file, run the full forensic pipeline, and return the JSON forensic report.

    Pipeline steps:
      1. Save uploaded .eml payload to temp file.
      2. Run 4 analysis engines (HeaderParser, NLPEngine, VisualEngine, AttributionGraph).
      3. Fuse evidence using Dempster-Shafer FusionEngine (0-100 score + tier).
      4. Generate JSON (with SHA-256 chain-of-custody), Jinja2 HTML, and PDF reports.
      5. Return full JSON forensic report with report download URLs.
    """
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted.")

    temp_id = str(uuid.uuid4())
    temp_path = UPLOAD_DIR / f"{temp_id}_{file.filename}"

    try:
        with temp_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save upload payload: {exc}")

    try:
        hp = HeaderParser(offline_mode=offline)
        nlp = NLPEngine(lightweight=lightweight)
        visual = VisualEngine()
        attribution = AttributionGraph()
        fusion = FusionEngine()
        reports = ReportGenerator()

        # Engine 1: Header Parser
        header_res = hp.analyse(str(temp_path))

        # Engine 2: NLP Engine
        subject, body, urls = NLPEngine.extract_email_text(str(temp_path))
        nlp_res = nlp.analyse(subject, body, urls)

        # Engine 3: Visual Engine
        visual_res = visual.analyse_eml(str(temp_path))

        # Engine 4: Attribution Graph
        attr_res = attribution.build(header_res, nlp_res, visual_res)

        # Fusion Engine
        verdict = fusion.fuse(header_res, nlp_res, visual_res, attr_res)

        engines = {
            "HeaderParser": header_res,
            "NLPEngine": nlp_res,
            "VisualEngine": visual_res,
            "AttributionGraph": attr_res,
        }

        # Generate and save all 3 report formats into REPORT_DIR using report_id stem
        json_report = reports.generate_json(verdict, engines, temp_path)
        json_report["report_id"] = temp_id
        json_report["report_urls"] = {
            "json": f"/reports/{temp_id}?format=json",
            "html": f"/reports/{temp_id}?format=html",
            "pdf": f"/reports/{temp_id}?format=pdf",
        }

        # Write files
        (REPORT_DIR / f"{temp_id}.json").write_text(json.dumps(json_report, indent=2), encoding="utf-8")
        
        html_content = reports.generate_html(verdict, engines, temp_path)
        (REPORT_DIR / f"{temp_id}.html").write_text(html_content, encoding="utf-8")

        pdf_bytes = reports.generate_pdf(verdict, engines, temp_path)
        (REPORT_DIR / f"{temp_id}.pdf").write_bytes(pdf_bytes)

        return json_report

    except Exception as exc:
        logger_err = f"Pipeline execution failed: {exc}"
        raise HTTPException(status_code=500, detail=logger_err)

    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


@app.get("/sample_emails/{filename}")
async def get_sample_email(filename: str):
    """Retrieve raw sample .eml file."""
    sample_path = SAMPLE_DIR / filename
    if not sample_path.exists():
        raise HTTPException(status_code=404, detail=f"Sample email '{filename}' not found.")
    return FileResponse(sample_path, media_type="message/rfc822", filename=filename)


@app.get("/reports/{report_id}")
@app.get("/report/{report_id}")
async def get_report(
    report_id: str,
    format: str = Query("pdf", regex="^(pdf|html|json)$", description="Format to retrieve: 'pdf', 'html', or 'json'"),
):
    """Retrieve a stored HTML, PDF, or JSON forensic report by unique ID."""
    target_format = format.lower()
    file_path = REPORT_DIR / f"{report_id}.{target_format}"

    if not file_path.exists():
        # Try matching by filename stem
        matching = list(REPORT_DIR.glob(f"*{report_id}*.{target_format}"))
        if matching:
            file_path = matching[0]
        else:
            raise HTTPException(status_code=404, detail=f"Report ID '{report_id}' in format '{format}' not found.")

    media_types = {
        "json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf",
    }
    return FileResponse(file_path, media_type=media_types[target_format], filename=file_path.name)


@app.get("/campaigns")
async def get_campaigns() -> dict[str, Any]:
    """Return the current attribution graph in node-link JSON along with campaign clusters."""
    eml_files = sorted(SAMPLE_DIR.glob("*.eml"))
    if not eml_files:
        raise HTTPException(status_code=404, detail="No sample email datasets found.")

    hp = HeaderParser(offline_mode=True)
    nlp = NLPEngine(lightweight=True)
    visual = VisualEngine()
    attribution = AttributionGraph()

    email_results = []
    for path in eml_files:
        header_res = hp.analyse(str(path))
        subject, body, urls = NLPEngine.extract_email_text(str(path))
        nlp_res = nlp.analyse(subject, body, urls)
        visual_res = visual.analyse_eml(str(path))
        email_results.append((header_res, nlp_res, visual_res))

    batch_res = attribution.build_batch(email_results)

    return {
        "node_link_graph": batch_res["json_data"],
        "campaigns": batch_res["campaigns"],
        "attributions": batch_res["attributions"],
        "indicators": batch_res["indicators"],
        "summary": batch_res["summary"],
    }


@app.post("/query")
async def query_forensics(req: QueryRequest) -> dict[str, Any]:
    """Accept a natural-language question and execute keyword-based filtering over stored reports and campaigns."""
    q_str = (req.question or req.query or "").strip()
    if not q_str:
        raise HTTPException(status_code=400, detail="Query string ('question' or 'query') is required.")

    q_lower = q_str.lower()
    matches: list[dict[str, Any]] = []

    # 1. Read all stored JSON reports
    report_dirs = [REPORT_DIR, BASE_DIR / "reports" / "output"]
    seen_ids: set[str] = set()

    is_campaign_query = "campaign" in q_lower or "cluster" in q_lower
    is_phish_query = any(w in q_lower for w in ("phish", "threat", "malicious", "attack", "suspicious"))
    is_safe_query = any(w in q_lower for w in ("safe", "clean", "legit", "legitimate"))

    kw_tokens = [
        t for t in q_lower.split()
        if len(t) > 2 and t not in ("show", "me", "all", "the", "from", "this", "that", "emails", "mail", "what", "which", "are", "have")
    ]

    for rdir in report_dirs:
        if not rdir.exists():
            continue
        for jfile in rdir.glob("*.json"):
            if jfile.name in seen_ids:
                continue
            seen_ids.add(jfile.name)
            try:
                data = json.loads(jfile.read_text(encoding="utf-8"))
                custody = data.get("chain_of_custody", {})
                verdict = data.get("verdict", {})
                engines = data.get("engine_results", {})
                header_res = engines.get("HeaderParser", {})

                fname = custody.get("file_name", jfile.name).lower()
                subject = header_res.get("subject", "").lower()
                sender = header_res.get("from", "").lower()
                
                score = verdict.get("threat_score") if isinstance(verdict, dict) and "threat_score" in verdict else data.get("threat_score", 0)
                tier = verdict.get("tier") if isinstance(verdict, dict) and "tier" in verdict else data.get("tier", "SAFE")
                reasoning = str(verdict.get("reasoning") if isinstance(verdict, dict) else data.get("reasoning", "")).lower()

                matched = False
                if is_campaign_query and ("phish" in fname or score >= 50 or "campaign" in reasoning or "storm" in reasoning or "ta505" in reasoning):
                    matched = True
                elif is_phish_query and score >= 50:
                    matched = True
                elif is_safe_query and score < 20:
                    matched = True
                elif any(t in fname or t in subject or t in sender or t in str(tier).lower() or t in reasoning for t in kw_tokens):
                    matched = True

                if matched:
                    matches.append({
                        "file_name": custody.get("file_name", jfile.name),
                        "threat_score": score,
                        "tier": tier,
                        "subject": header_res.get("subject"),
                        "sender": header_res.get("from"),
                        "sha256": custody.get("sha256"),
                        "reasoning": reasoning[:120] + "..." if len(reasoning) > 120 else reasoning,
                    })
            except Exception:
                pass

    return {
        "query": q_str,
        "results_count": len(matches),
        "matches": matches,
        "message": f"Found {len(matches)} stored report(s) matching your query.",
    }
