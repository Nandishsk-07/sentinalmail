"""
main.py — FastAPI application for Sentinel-Mail

Exposes endpoints to upload email files (.eml), run the threat detection pipeline,
persist forensic reports, and retrieve generated reports.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from engines.header_parser import HeaderParser
from engines.nlp_engine import NLPEngine
from engines.visual_engine import VisualEngine
from engines.attribution_graph import AttributionGraph
from fusion.fusion_engine import FusionEngine
from reports.report_generator import ReportGenerator

app = FastAPI(
    title="Sentinel-Mail",
    description="AI-powered email threat detection and forensic analysis API.",
    version="0.1.0",
)

# ── Paths ──────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "data" / "temp_uploads"
REPORT_DIR = BASE_DIR / "data" / "reports"

# Ensure directories exist
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/health")
async def health():
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/analyse")
async def analyse_email(
    file: UploadFile = File(...),
    offline: bool = Query(True, description="When True, skip outbound live DNS and geo-IP requests."),
    lightweight: bool = Query(True, description="When True, skip heavy HuggingFace/spaCy model loading."),
):
    """Accept a .eml file and run the full forensic threat analysis pipeline.

    Steps:
        1. Save uploaded .eml payload to temporary storage.
        2. Run 4 analysis engines (Header, NLP, Visual, Attribution).
        3. Combine evidence using the Dempster-Shafer Fusion Engine.
        4. Generate and persist JSON and PDF forensic reports.
        5. Return the unified verdict with a link to download the PDF.
    """
    if not file.filename or not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted.")

    # 1. Save upload to temp file
    temp_id = str(uuid.uuid4())
    temp_path = UPLOAD_DIR / f"{temp_id}_{file.filename}"

    try:
        with temp_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save upload payload: {exc}")

    # 2. Run analysis pipeline
    try:
        # Initialize engines with request-level parameters
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

        # Step 3: Fusion Engine
        verdict = fusion.fuse(header_res, nlp_res, visual_res, attr_res)

        # Step 4: Report Generation
        engines = {
            "HeaderParser": header_res,
            "NLPEngine": nlp_res,
            "VisualEngine": visual_res,
            "AttributionGraph": attr_res,
        }

        # Generate & write JSON report
        json_report = reports.generate_json(verdict, engines)
        json_path = REPORT_DIR / f"{temp_id}.json"
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2)

        # Generate & write PDF report (or fallback HTML/PDF)
        pdf_bytes = reports.generate_pdf(verdict, engines)
        pdf_path = REPORT_DIR / f"{temp_id}.pdf"
        pdf_path.write_bytes(pdf_bytes)

        # 5. Build response dict
        return {
            "report_id": temp_id,
            "filename": file.filename,
            "verdict": {
                "threat_score": verdict["threat_score"],
                "tier": verdict["tier"],
                "reasoning": verdict["reasoning"],
                "raw_belief": verdict["raw_belief"],
                "signal_contributions": verdict["signal_contributions"],
            },
            "reports": {
                "pdf_url": f"/report/{temp_id}?format=pdf",
                "json_url": f"/report/{temp_id}?format=json",
            },
        }

    except Exception as exc:
        logger_err = f"Pipeline execution failed: {exc}"
        os.environ["SENTINEL_ERR"] = logger_err
        raise HTTPException(status_code=500, detail=logger_err)

    finally:
        # Clean up temporary uploaded file
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


@app.get("/report/{report_id}")
async def get_report(
    report_id: str,
    format: str = Query("pdf", regex="^(pdf|json)$", description="Format to retrieve: 'pdf' or 'json'"),
):
    """Retrieve a previously generated forensic report by its unique ID."""
    if format == "json":
        json_path = REPORT_DIR / f"{report_id}.json"
        if not json_path.exists():
            raise HTTPException(status_code=404, detail="JSON report not found.")
        return FileResponse(json_path, media_type="application/json", filename=f"report_{report_id}.json")
    
    # Return PDF by default
    pdf_path = REPORT_DIR / f"{report_id}.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF report not found.")
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"report_{report_id}.pdf")
