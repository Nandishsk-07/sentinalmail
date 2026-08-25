#!/usr/bin/env python3
"""
test_api.py — Smoke-test for the FastAPI layer.

Starts Uvicorn locally on a random/fixed port, queries health, uploads
a phishing .eml file to POST /analyse, prints the verdict, and downloads
the PDF report from GET /report/{id} to verify the entire system.
"""

from __future__ import annotations

import json
import os
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
    "green": "\033[92m", "red": "\033[91m", "cyan": "\033[96m",
}


def c(text: str, *styles: str) -> str:
    prefix = "".join(_C.get(s, "") for s in styles)
    return f"{prefix}{text}{_C['reset']}" if prefix else text


def main() -> None:
    print(c("\n  SENTINEL-MAIL  .  FastAPI Service End-to-End Test", "bold", "cyan"))
    print(f"  ──────────────────────────────────────────────────")

    # Start Uvicorn process in background
    print(f"  [*] Starting API server on {BASE_URL}...")
    server_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--host", HOST, "--port", str(PORT)],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        # Wait for server to boot (up to 8 seconds)
        healthy = False
        for i in range(16):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"{BASE_URL}/health", timeout=1) as response:
                    if response.status == 200:
                        healthy = True
                        break
            except Exception:
                pass

        if not healthy:
            # Dump stderr for debugging
            stderr_out = server_process.stderr.read() if server_process.stderr else "No stderr output"
            print(c(f"  [x] API server failed to start or did not become healthy in time.", "red"))
            print(f"  Stderr output:\n{stderr_out}")
            sys.exit(1)

        print(c("  [+] API server is ONLINE and healthy.", "green"))

        # Test POST /analyse with a sample EML
        sample_path = PROJECT_ROOT / "data" / "sample_emails" / "phish_qr_mfa.eml"
        print(f"  [*] Uploading sample: {sample_path.name}...")

        # Construct multipart/form-data payload manually to keep test script dependency-free
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
        
        payload_bytes = b"\r\n".join(body)

        req = urllib.request.Request(
            f"{BASE_URL}/analyse?offline=true&lightweight=true",
            data=payload_bytes,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(payload_bytes))
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                print(c("  [+] Successfully analyzed email. Verdict response:", "green"))
                print(json.dumps(result, indent=4))
                
                report_id = result.get("report_id")
                pdf_url = result.get("reports", {}).get("pdf_url")
                
                if report_id and pdf_url:
                    # Test GET /report/{id}
                    print(f"  [*] Downloading PDF report from {pdf_url}...")
                    with urllib.request.urlopen(f"{BASE_URL}{pdf_url}", timeout=5) as pdf_resp:
                        pdf_data = pdf_resp.read()
                        print(c(f"  [+] Downloaded PDF report successfully ({len(pdf_data):,} bytes).", "green"))
                        
                    # Test GET /report/{id}?format=json
                    json_url = result.get("reports", {}).get("json_url")
                    print(f"  [*] Downloading JSON report from {json_url}...")
                    with urllib.request.urlopen(f"{BASE_URL}{json_url}", timeout=5) as json_resp:
                        json_data = json_resp.read()
                        print(c(f"  [+] Downloaded JSON report successfully ({len(json_data):,} bytes).", "green"))
                else:
                    print(c("  [x] Response is missing report_id or PDF URL keys.", "red"))

        except urllib.error.HTTPError as err:
            err_body = err.read().decode()
            print(c(f"  [x] POST /analyse failed with HTTP code {err.code}: {err.reason}", "red"))
            print(f"      Response details: {err_body}")
        except Exception as exc:
            print(c(f"  [x] Pipeline query encountered an error: {exc}", "red"))

    finally:
        # Clean up background process
        print("  [*] Stopping background API server...")
        server_process.terminate()
        try:
            server_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server_process.kill()
        print("  [+] API server shut down.")


if __name__ == "__main__":
    main()
