# 🛡️ Sentinel-Mail

**AI-powered email threat detection and forensic analysis prototype.**

Sentinel-Mail ingests raw `.eml` files, runs them through four specialised
analysis engines in parallel, fuses the results into a single threat verdict,
and produces a rich forensic report — all exposed via a FastAPI REST API.

---

## Architecture

```
                         ┌──────────────────┐
                         │   Raw .eml File  │
                         └────────┬─────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │              │
              ┌─────▼─────┐ ┌────▼────┐  ┌──────▼──────┐
              │  Header    │ │  NLP    │  │   Visual    │
              │  Parser    │ │  Engine │  │   Engine    │
              └─────┬──────┘ └────┬────┘  └──────┬──────┘
                    │             │              │
                    │      ┌──────▼──────┐       │
                    │      │ Attribution │       │
                    │      │   Graph     │       │
                    │      └──────┬──────┘       │
                    │             │              │
                    └─────────────┼──────────────┘
                                  │
                         ┌────────▼─────────┐
                         │  Fusion Engine   │
                         │  (Dempster–Shafer│
                         │   combination)   │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │ Report Generator │
                         │  (PDF + JSON)    │
                         └──────────────────┘
```

### Engine Descriptions

| Engine | Module | Purpose |
|---|---|---|
| **Header Parser** | `engines/header_parser.py` | SPF / DKIM / DMARC validation, Received-chain tracing, IP geolocation, reverse-DNS |
| **NLP Engine** | `engines/nlp_engine.py` | Transformer-based phishing-intent classification, urgency detection, URL risk scoring |
| **Visual Engine** | `engines/visual_engine.py` | QR-code extraction (quishing), brand-logo spoofing detection, macro scanning |
| **Attribution Graph** | `engines/attribution_graph.py` | NetworkX knowledge graph linking IPs, domains, and threat-actor indicators |
| **Fusion Engine** | `fusion/fusion_engine.py` | Weighted Dempster–Shafer evidence combination → unified threat tier |
| **Report Generator** | `reports/report_generator.py` | WeasyPrint PDF forensic report + machine-readable JSON for SIEM/SOAR |

### Pipeline Flow

1. **Ingest** — A `.eml` file is uploaded via `POST /analyse`.
2. **Parallel Analysis** — The four engines run concurrently on the parsed email.
3. **Fusion** — Engine outputs are combined into a single `FusionVerdict` with a
   0–100 threat score and a tier (`SAFE`, `SUSPICIOUS`, `LIKELY_PHISH`,
   `CONFIRMED_THREAT`).
4. **Report** — A forensic PDF and JSON report are generated and persisted.
5. **Response** — The JSON verdict is returned to the caller; the PDF is
   retrievable via `GET /report/{id}`.

---

## Project Structure

```
sentinel-mail/
├── api/
│   ├── __init__.py
│   └── main.py              # FastAPI application
├── engines/
│   ├── __init__.py
│   ├── header_parser.py     # Email header analysis
│   ├── nlp_engine.py        # NLP / phishing classification
│   ├── visual_engine.py     # Attachment & image analysis
│   └── attribution_graph.py # Threat-actor attribution graph
├── fusion/
│   ├── __init__.py
│   └── fusion_engine.py     # Multi-engine score fusion
├── reports/
│   ├── __init__.py
│   └── report_generator.py  # PDF & JSON forensic reports
├── data/
│   └── sample_emails/       # Test .eml files go here
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
# 1. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the API server
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# 4. Test the health endpoint
curl http://localhost:8000/health
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness / readiness probe |
| `POST` | `/analyse` | Upload a `.eml` file → full pipeline → JSON verdict |
| `GET` | `/report/{id}` | Retrieve a forensic PDF report by ID |

---

## Tech Stack

- **FastAPI + Uvicorn** — async API layer
- **Transformers + PyTorch** — phishing-intent NLP models
- **NLTK** — tokenisation and linguistic feature extraction
- **OpenCV + pyzbar** — image analysis and QR-code decoding
- **NetworkX** — threat-attribution graph construction
- **dnspython** — DNS record lookups (SPF, MX, PTR)
- **WeasyPrint** — PDF report rendering
- **python-magic** — MIME-type detection for attachments
- **email-validator** — address syntax and deliverability checks

---

## License

This project is a prototype for research and educational purposes.
