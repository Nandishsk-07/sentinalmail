# Sentinel-Mail: Judge Presentation & Live Demo Script

Welcome to the **Sentinel-Mail** live demonstration script. This document provides step-by-step click instructions, key visual highlights, and exact verbal commentary ("what to say") for presenting Sentinel-Mail to competition judges.

---

## 🚀 Quick Start: Launching the Demo

To launch the full stack environment (FastAPI Backend + React Frontend + 5 Pre-loaded Email Datasets), run the single command below in your terminal:

```bash
# On Linux / macOS / Git Bash:
./run_demo.sh

# On Windows PowerShell / CMD:
python run_demo.py
# (or double-click run_demo.bat)
```

The script will automatically:
1. Boot the FastAPI backend server on `http://127.0.0.1:8000`.
2. Boot the React + Tailwind frontend on `http://127.0.0.1:3000`.
3. Pre-load and analyze all 5 sample email payloads through the threat detection pipeline.
4. Launch `http://127.0.0.1:3000` in your default browser.

---

## 🎬 Scenario 1: Business Email Compromise (BEC) & Relay Hop Tracing

### 📌 Target Payload
`phish_ceo_wire_fraud.eml` (*CEO Executive Impersonation & Wire Fraud*)

### 👆 Click-by-Click Steps
1. Navigate to the **EML Analysis** tab on the top navigation bar.
2. In the **Judge Demo Presets** section, click the **`CEO Wire Fraud (BEC)`** preset button (or drag and drop `data/sample_emails/phish_ceo_wire_fraud.eml`).
3. Watch the live analysis panel render the **Executive Verdict Banner**.

---

### 🎙️ Presenter Script & What to Say

> **[Presenter]**: 
> *"Judges, let's start with one of the most financially devastating email attacks targeting enterprises today: **Business Email Compromise (BEC)**. In this scenario, an attacker impersonates our CEO, Sarah Jenkins, attempting to authorize an urgent \$48,500 wire transfer."*
>
> *(Point to the Verdict Banner)*
> *"Notice how Sentinel-Mail immediately flags this email with a **Risk Score of 100/100** and a verdict of **CONFIRMED_THREAT**."*
>
> *(Point to the Authentication & Header Cards)*
> *"If we look at the Header Analysis: The email display name claims to be 'Sarah Jenkins <ceo@acme-corp.com>', but our HeaderParser discovered that the actual envelope sender is `attacker@wire-transfer-scam.com`. Furthermore, **SPF, DKIM, and DMARC checks all FAIL hard**."*
>
> *(Point to the Relay Hop Routing Chain)*
> *"Sentinel-Mail traces the full MIME header hop chain across 3 relays. Hop 1 originated from IP `185.220.101.5` in Russia via `mail.wire-transfer-scam.com` with a suspicious routing delay before reaching our corporate gateway. Our NLP engine flagged high-urgency phrases such as **'Confidential - Wire Transfer Required Today'**."*
>
> *(Point to the Download PDF Button)*
> *"With one click on **'Download Forensic Report (PDF)'**, incident responders generate an audit-ready, tamper-evident forensic document complete with a SHA-256 chain-of-custody cryptographic hash."*

---

## 🎬 Scenario 2: Quishing (QR Code Phishing Extraction)

### 📌 Target Payload
`phish_qr_mfa.eml` (*Image Attachment & QR Code MFA Bypass*)

### 👆 Click-by-Click Steps
1. Remain on the **EML Analysis** tab.
2. In the **Judge Demo Presets** section, click the **`Quishing (QR Code MFA)`** preset button (or upload `data/sample_emails/phish_qr_mfa.eml`).
3. Scroll down to the **Visual & QR Code Findings** section.

---

### 🎙️ Presenter Script & What to Say

> **[Presenter]**: 
> *"Next, let's look at **Quishing** — QR code phishing. Traditional Secure Email Gateways (SEGs) inspect text bodies, so cybercriminals hide malicious login portals inside embedded image attachments to bypass text scanners."*
>
> *(Point to the Visual Scan Findings Card)*
> *"Watch how Sentinel-Mail's **Visual Engine** kicks in. It automatically extracts embedded PNG and JPEG attachments, decodes the image matrices using OpenCV and PyZbar, and reconstructs the hidden QR code payload."*
>
> *(Point to the Decoded QR URL Warning Box)*
> *"The visual scan decoded the URL: `https://mfa-update-login-verification.com/auth`. Our domain risk engine evaluated this URL and flagged it as a **lookalike domain** leveraging typosquatting against Microsoft MFA."*
>
> *(Point to the Verdict)*
> *"By fusing visual evidence with NLP urgency analysis, Sentinel-Mail catches threats that traditional email filters completely miss, assigning a **100/100 Risk Score**."*

---

## 🎬 Scenario 3: Knowledge Graph Threat Attribution & AI Query Console

### 📌 Target Payload & View
`GET /campaigns` + `POST /query` (*Microsoft 365 Impersonation & Campaign Clustering*)

### 👆 Click-by-Click Steps
1. Click on the **Attribution Graph** tab in the top navigation bar.
2. Observe the interactive Network Topology graph rendered on the canvas.
3. Click on the **AI Query Console** tab in the top navigation bar.
4. Click on the quick query chip: **`"Show me all emails from this campaign"`** (or type your own natural language query) and press **Search**.

---

### 🎙️ Presenter Script & What to Say

> **[Presenter]**: 
> *"So far, we've analyzed isolated emails. But real cyberattacks are multi-vector campaigns launched by coordinated threat actors. Let's switch to our **Attribution Graph** tab."*
>
> *(Point to the Network Topology Graph)*
> *"Sentinel-Mail uses NetworkX graph analytics to correlate indicators across all ingested emails. The red stars represent threat actors, blue nodes represent emails, orange nodes represent IPs, and yellow nodes represent domains."*
>
> *(Point to Campaign Clusters & Threat Actor Match)*
> *"Using connected components algorithms, Sentinel-Mail automatically grouped `phish_ceo_wire_fraud.eml`, `phish_qr_mfa.eml`, and `phish_microsoft_security.eml` into **Campaign Cluster 3**. Furthermore, our threat intelligence engine matched these shared IPs and lookalike domains to **Storm-0982 (Scattered Spider subgroup)** with 100% confidence!"*
>
> *(Switch to AI Query Console tab)*
> *"Finally, let's open the **AI Query Console**. Security Analysts can query the entire forensic database using natural language. When I ask **'Show me all emails from this campaign'**, Sentinel-Mail filters our database, identifies all 3 malicious emails in the cluster, and provides instant PDF report download links."*
>
> *(Concluding Statement)*
> *"In summary: Sentinel-Mail combines header analysis, NLP intent, computer vision, Dempster-Shafer decision fusion, and graph analytics into a unified, audit-ready email threat detection system. Thank you!"*

---

## 📊 Summary Checklist for Presenters

| Scenario | Primary Engine Highlighted | Key Artifact / Visual Indicator | Target Email Payload |
|---|---|---|---|
| **Scenario 1** | HeaderParser + Relay Hop Tracer | SPF/DKIM/DMARC Failures & ரஷ்ய IP Relay Chain | `phish_ceo_wire_fraud.eml` |
| **Scenario 2** | VisualEngine (OpenCV/PyZbar) | Decoded QR Code URL (`mfa-update-login...`) | `phish_qr_mfa.eml` |
| **Scenario 3** | Attribution Graph + AI Query | Connected Network Graph & Threat Actor (`Storm-0982`) | `phish_microsoft_security.eml` |
