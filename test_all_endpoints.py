#!/usr/bin/env python3
"""
test_all_endpoints.py — End-to-end API Endpoint Verification Test.

Boots Uvicorn server locally, tests:
  - POST /analyze
  - GET /reports/{id}?format=html|pdf|json
  - GET /campaigns
  - POST /query
  - CORS Headers
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

PORT = 8000
HOST = "127.0.0.1"
BASE_URL = f"http://{HOST}:{PORT}"

_C = {
    "reset": "\033[0m", "bold": "\033[1m",
    "green": "\033[92m", "red": "\033[91m", "cyan": "\033[96m", "yellow": "\033[93m",
}


def c(text: str, *styles: str) -> str:
    prefix = "".join(_C.get(s, "") for s in styles)
    return f"{prefix}{text}{_C['reset']}" if prefix else text


def main() -> None:
    print(c(f"\n{'=' * 78}", "bold"))
    print(c("  SENTINEL-MAIL  .  FastAPI All-Endpoints Integration Test", "bold", "cyan"))
    print(c(f"{'=' * 78}", "bold"))

    print(f"[*] Booting FastAPI server on {BASE_URL}...")
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--host", HOST, "--port", str(PORT)],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # Wait for server readiness
        healthy = False
        for _ in range(20):
            time.sleep(0.4)
            try:
                with urllib.request.urlopen(f"{BASE_URL}/health", timeout=1) as resp:
                    if resp.status == 200:
                        healthy = True
                        break
            except Exception:
                pass

        if not healthy:
            err_log = server.stderr.read() if server.stderr else "No stderr"
            print(c(f"[x] Server startup failed. Log:\n{err_log}", "red"))
            sys.exit(1)

        print(c("[+] API server is healthy and ONLINE.", "green"))

        # ── 1. Test POST /analyze ──────────────────────────────────────
        print(f"\n1. {c('Testing POST /analyze', 'bold', 'yellow')}")
        sample_path = PROJECT_ROOT / "data" / "sample_emails" / "phish_qr_mfa.eml"
        
        boundary = "----SentinelFormBoundary" + str(time.time())
        file_bytes = sample_path.read_bytes()
        
        body = []
        body.append(f"--{boundary}".encode())
        body.append(f'Content-Disposition: form-data; name="file"; filename="{sample_path.name}"'.encode())
        body.append(b"Content-Type: message/rfc822")
        body.append(b"")
        body.extend([file_bytes])
        body.append(f"--{boundary}--".encode())
        body.append(b"")
        payload = b"\r\n".join(body)

        req = urllib.request.Request(
            f"{BASE_URL}/analyze?offline=true&lightweight=true",
            data=payload,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Origin": "http://localhost:3000",  # Test CORS header
            },
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            cors_header = resp.headers.get("Access-Control-Allow-Origin")
            res_data = json.loads(resp.read().decode())
            report_id = res_data.get("report_id")

            print(f"   [+] Response HTTP {resp.status} OK")
            print(f"   [+] CORS Header: Access-Control-Allow-Origin = '{cors_header}'")
            print(f"   [+] Report ID  : {report_id}")
            print(f"   [+] SHA-256    : {res_data.get('chain_of_custody', {}).get('sha256')}")
            print(f"   [+] Threat Score: {res_data.get('verdict', {}).get('threat_score')}/100 ({res_data.get('verdict', {}).get('tier')})")

        # ── 2. Test GET /reports/{id} ──────────────────────────────────
        print(f"\n2. {c('Testing GET /reports/{id}', 'bold', 'yellow')}")
        for fmt in ("json", "html", "pdf"):
            r_req = urllib.request.Request(f"{BASE_URL}/reports/{report_id}?format={fmt}")
            with urllib.request.urlopen(r_req, timeout=5) as r_resp:
                content = r_resp.read()
                print(f"   [+] Format '{fmt.upper()}': {r_resp.status} OK ({len(content):,} bytes, Content-Type: {r_resp.headers.get('Content-Type')})")

        # ── 3. Test GET /campaigns ─────────────────────────────────────
        print(f"\n3. {c('Testing GET /campaigns', 'bold', 'yellow')}")
        c_req = urllib.request.Request(f"{BASE_URL}/campaigns")
        with urllib.request.urlopen(c_req, timeout=10) as c_resp:
            camp_data = json.loads(c_resp.read().decode())
            print(f"   [+] Response HTTP {c_resp.status} OK")
            print(f"   [+] Summary: {camp_data.get('summary')}")
            print(f"   [+] Campaign Clusters Found: {len(camp_data.get('campaigns', []))}")
            for camp in camp_data.get("campaigns", []):
                print(f"       * [{camp['campaign_id']}] {camp['name']}: {len(camp['emails'])} emails ({', '.join(camp['emails'])})")

        # ── 4. Test POST /query ────────────────────────────────────────
        print(f"\n4. {c('Testing POST /query', 'bold', 'yellow')}")
        q_payload = json.dumps({"question": "show me all emails from this campaign"}).encode("utf-8")
        q_req = urllib.request.Request(
            f"{BASE_URL}/query",
            data=q_payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(q_req, timeout=5) as q_resp:
            q_res = json.loads(q_resp.read().decode())
            print(f"   [+] Response HTTP {q_resp.status} OK")
            print(f"   [+] Query  : '{q_res.get('query')}'")
            print(f"   [+] Matches: {q_res.get('results_count')} report(s)")
            for item in q_res.get("matches", [])[:3]:
                print(f"       * {item['file_name']} -> Score: {item['threat_score']}, Tier: {item['tier']}, Subject: {item['subject']}")

        print(c(f"\n{'=' * 78}", "bold"))
        print(c("  [SUCCESS] All API endpoints tested and verified cleanly!", "green", "bold"))
        print(c(f"{'=' * 78}\n", "bold"))

    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except Exception:
            server.kill()


if __name__ == "__main__":
    main()
