"""
main.py — FastAPI application for Sentinel-Mail

Endpoints:
  POST /analyse         Upload a .eml file → run full pipeline → return JSON verdict.
  GET  /report/{id}     Retrieve a previously generated forensic PDF.
  GET  /health          Liveness / readiness probe.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException

app = FastAPI(
    title="Sentinel-Mail",
    description="AI-powered email threat detection and forensic analysis API.",
    version="0.1.0",
)


@app.get("/health")
async def health():
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/analyse")
async def analyse_email(file: UploadFile = File(...)):
    """Accept a .eml file and return a threat analysis verdict.

    The full pipeline is:
        1. Parse raw email.
        2. Run 4 engines in parallel (header, NLP, visual, attribution).
        3. Fuse results into a unified verdict.
        4. Persist a forensic report.
        5. Return the JSON verdict.
    """
    if not file.filename or not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted.")

    _raw = await file.read()  # noqa: F841 — will be used once engines are wired

    # TODO: wire up engines → fusion → report
    raise HTTPException(status_code=501, detail="Pipeline not yet implemented.")


@app.get("/report/{report_id}")
async def get_report(report_id: str):
    """Retrieve a previously generated forensic report by ID."""
    # TODO: look up report from storage
    raise HTTPException(status_code=501, detail="Report retrieval not yet implemented.")
