# 🛡️ Sentinel-Mail

**Next-Generation AI Email Threat Detection, Deep Forensics & Threat Attribution Platform**

Sentinel-Mail is an enterprise-grade forensic analysis system for emails (`.eml`). It orchestrates multiple specialized inspection engines concurrently, combines heterogeneous forensic evidence using Dempster–Shafer mathematical evidential reasoning, attributes indicators to threat actor campaigns via graph intelligence, and presents comprehensive forensic intelligence through an interactive React dashboard and multi-format forensic reports (JSON / HTML / PDF).

---

## 🏛️ System Architecture

```
                                 ┌──────────────────┐
                                 │   Raw .eml File  │
                                 └────────┬─────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
              ┌─────▼─────┐         ┌────▼────┐           ┌──────▼──────┐
              │  Header    │         │  NLP    │           │   Visual    │
              │  Parser    │         │  Engine │           │   Engine    │
              └─────┬──────┘         └────┬────┘           └──────┬──────┘
                    │                     │                     │
                    │              ┌──────▼──────┐              │
                    │              │ Attribution │              │
                    │              │    Graph    │              │
                    │              └──────┬──────┘              │
                    │                     │                     │
                    └─────────────────────┼─────────────────────┘
                                          │
                                 ┌────────▼─────────┐
                                 │  Fusion Engine   │
                                 │ (Dempster–Shafer │
                                 │   combination)   │
                                 └────────┬─────────┘
                                          │
                                 ┌────────▼─────────┐
                                 │ Report Generator │
                                 │(PDF, HTML, JSON) │
                                 └────────┬─────────┘
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    │                                           │
             ┌──────▼───────┐                            ┌──────▼───────┐
             │ FastAPI REST │                            │ React + Vite │
             │   Backend    │                            │  Dashboard   │
             └──────────────┘                            └──────────────┘
```

---

## 🔬 Specialized Forensic Engines

| Engine | Module | Capabilities & Detection Mechanics |
|---|---|---|
| **Header Parser** | `engines/header_parser.py` | RFC 5322 parsing, SPF / DKIM / DMARC authentication verification, Received-chain hop route tracing, envelope vs. header From spoofing detection, reverse DNS resolution. |
| **NLP Phishing Engine** | `engines/nlp_engine.py` | Transformer-based sequence classification, conversational intent analysis, linguistic urgency & coercion scoring, high-risk URL extraction, homoglyph & credential harvesting detection. |
| **Visual & Attachment Engine** | `engines/visual_engine.py` | OpenCV & PyZBar QR-code extraction (Quishing detection), attachment MIME-type validation, weaponized Office macro & executable scanning, logo brand impersonation analysis. |
| **Attribution Graph** | `engines/attribution_graph.py` | NetworkX bipartite knowledge graph linking sending IPs, ASN details, target domains, and threat indicators to known Advanced Persistent Threat (APT) campaign clusters. |
| **Fusion Engine** | `fusion/fusion_engine.py` | Weighted Dempster–Shafer theory of evidence combination to resolve conflicting engine signals into a calibrated 0–100 threat score and definitive threat tier. |
| **IP Intelligence Engine** | `engines/ip_intelligence.py` | GeoIP lookup, ASN reputation scoring, proxy/VPN/Tor node identification, and visual coordinate mapping for global relay visualization. |
| **Forensic Report Generator** | `reports/report_generator.py` | Automated report compilation producing SIEM/SOAR-ready JSON verdicts, styled responsive HTML reports, and print-ready PDF forensic audit documents via WeasyPrint. |

### Threat Classification Tiers
* `SAFE` (Score: 0 – 29) — Passed authentication, benign body heuristics, clean attachments.
* `SUSPICIOUS` (Score: 30 – 59) — Minor header anomalies or moderate urgency phrasing detected.
* `LIKELY_PHISH` (Score: 60 – 84) — Failed authentication, impersonation cues, or suspicious URLs.
* `CONFIRMED_THREAT` (Score: 85 – 100) — Direct spoofing, malicious attachments, weaponized QR code, or high-confidence APT IOC match.

---

## 📂 Project Structure

```
sentinel-mail/
├── api/
│   ├── __init__.py
│   └── main.py                  # FastAPI REST endpoints & WebSocket server
├── engines/
│   ├── __init__.py
│   ├── header_parser.py         # Email header & authentication analysis
│   ├── nlp_engine.py            # Deep-learning phishing & intent detection
│   ├── visual_engine.py         # Quishing (QR) & attachment macro scanner
│   ├── attribution_graph.py     # NetworkX knowledge graph & threat clustering
│   └── ip_intelligence.py       # Geolocation & ASN intelligence
├── fusion/
│   ├── __init__.py
│   └── fusion_engine.py         # Dempster–Shafer mathematical evidence fusion
├── reports/
│   ├── __init__.py
│   └── report_generator.py      # PDF, HTML, and JSON report generator
├── frontend/                    # Vite + React + Tailwind interactive dashboard
│   ├── src/
│   │   ├── components/          # Reusable UI components (ThreatMap, Headers, etc.)
│   │   ├── App.jsx              # Main application view & preset runner
│   │   └── index.css            # Tailwind & handcrafted theme styles
│   ├── package.json
│   └── vite.config.js
├── data/
│   ├── sample_emails/           # Pre-built realistic test threat payloads (.eml)
│   └── sample_ip_intel.json     # Geolocation & IP reputation fixtures
├── run_demo.py                  # One-command full-stack environment launcher
├── run_demo.bat                 # Windows one-click batch launcher
├── run_demo.sh                  # Linux/macOS launcher script
├── DEMO_SCRIPT.md               # Click-by-click presenter guide & scenarios
├── test_all_endpoints.py        # End-to-end integration test suite
├── requirements.txt             # Python dependencies
└── README.md
```

---

## ⚡ Quick Start

### 1. Automated One-Command Launcher (Recommended)

Starts the FastAPI server (`:8000`), boots the Vite frontend (`:3000`), pre-loads the 5 sample threat payloads, and opens the dashboard in your default browser:

**Windows (PowerShell / CMD):**
```powershell
.\venv\Scripts\activate
python run_demo.py
# (or double-click run_demo.bat)
```

**Linux / macOS:**
```bash
source .venv/bin/activate
chmod +x run_demo.sh
./run_demo.sh
```

---

### 2. Manual Setup & Development Mode

#### Backend Setup (FastAPI)
```powershell
# 1. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\activate          # Windows
# source venv/bin/activate       # Linux / macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the API server
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

#### Frontend Setup (React + Vite)
In a separate terminal:
```powershell
cd frontend
npm install
npm run dev
```

---

## 🌐 Endpoints & API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness and readiness health probe. |
| `POST` | `/analyze` | Ingests a raw `.eml` file via `multipart/form-data`, triggers the full forensic pipeline, and returns a detailed JSON report. |
| `GET` | `/reports/{id}?format=json\|html\|pdf` | Downloads or previews an existing forensic report in JSON, HTML, or PDF format. |
| `GET` | `/campaigns` | Returns the active knowledge graph and threat campaign clusters in node-link JSON format. |
| `POST` | `/query` | Natural-language query interface returning filtered threat reports and matched indicators. |

### Example: Analyze an Email via `curl`

```bash
curl -X POST "http://127.0.0.1:8000/analyze?offline=true" \
  -F "file=@data/sample_emails/phish_ceo_wire_fraud.eml"
```

---

## 🧪 Testing & Verification

Sentinel-Mail includes automated end-to-end integration and engine test suites:

```powershell
# Run the complete API integration test
python test_all_endpoints.py

# Test individual engines
python test_header_parser.py
python test_nlp_engine.py
python test_visual_engine.py
python test_attribution_graph.py
python test_fusion_engine.py
python test_report_generator.py
```

---

## 🎯 Pre-Loaded Demo Scenarios

Located in `data/sample_emails/`:

1. **`phish_ceo_wire_fraud.eml`** — Business Email Compromise (BEC): Urgent \$48,500 wire transfer request with failed SPF/DKIM/DMARC and display name spoofing.
2. **`quish_mfa_reset.eml`** — QR Code Phishing (Quishing): QR image decoded to reveal a credential phishing credential harvesting page.
3. **`malware_fake_invoice.eml`** — Weaponized Attachment: Malicious invoice macro targeting endpoint finance personnel.
4. **`phish_cred_harvest.eml`** — Security Alert Impersonation: Microsoft 365 lookalike landing page with homoglyphic URL redirection.
5. **`benign_project_update.eml`** — Normal Legitimate Email: Clean SPF/DKIM baseline proving low false-positive rate.

---

## 🛠️ Tech Stack

* **Backend Framework:** FastAPI, Uvicorn, Pydantic v2
* **Machine Learning & NLP:** PyTorch, Hugging Face Transformers, NLTK
* **Image & Attachment Forensics:** OpenCV, PyZBar, python-magic
* **Graph Intelligence:** NetworkX
* **Forensic Document Rendering:** WeasyPrint, Jinja2, Matplotlib
* **Frontend:** React, Vite, Tailwind CSS, Lucide Icons

---

## 🔒 Security & Privacy

Sentinel-Mail does not transmit private email payload contents to third-party public cloud APIs. All model inference and heuristic parsing can be executed completely locally in `offline=true` mode.
