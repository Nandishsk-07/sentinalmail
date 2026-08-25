#!/usr/bin/env python3
"""
run_demo.py — One-Command Sentinel-Mail Demo Environment Launcher.

1. Boots FastAPI backend server (http://127.0.0.1:8000).
2. Boots Vite React frontend (http://127.0.0.1:3000).
3. Pre-loads all 5 sample emails through the forensic pipeline (POST /analyze).
4. Opens http://127.0.0.1:3000 in your browser for judge presentation.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
SAMPLE_DIR = BASE_DIR / "data" / "sample_emails"

API_PORT = 8000
FRONTEND_PORT = 3000
API_URL = f"http://127.0.0.1:{API_PORT}"
FRONTEND_URL = f"http://127.0.0.1:{FRONTEND_PORT}"


def log(msg: str, level: str = "info") -> None:
    colors = {
        "info": "\033[94m[*]\033[0m",
        "success": "\033[92m[+]\033[0m",
        "warning": "\033[93m[!]\033[0m",
        "error": "\033[91m[x]\033[0m",
        "banner": "\033[96m\033[1m",
    }
    prefix = colors.get(level, "[*]")
    print(f"{prefix} {msg}")


def wait_for_service(url: str, name: str, timeout: int = 30) -> bool:
    log(f"Waiting for {name} to become ready at {url}...", "info")
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    log(f"{name} is ONLINE and healthy!", "success")
                    return True
        except Exception:
            time.sleep(0.5)
    log(f"Timed out waiting for {name} at {url}", "error")
    return False


def preload_sample_emails() -> None:
    log("Pre-loading sample emails through full forensic threat pipeline...", "info")
    sample_files = sorted(SAMPLE_DIR.glob("*.eml"))
    if not sample_files:
        log("No sample email payloads found in data/sample_emails/", "warning")
        return

    boundary = "----SentinelDemoBoundary" + str(int(time.time()))
    
    for eml_path in sample_files:
        try:
            file_bytes = eml_path.read_bytes()
            body = []
            body.append(f"--{boundary}".encode())
            body.append(f'Content-Disposition: form-data; name="file"; filename="{eml_path.name}"'.encode())
            body.append(b"Content-Type: message/rfc822")
            body.append(b"")
            body.append(file_bytes)
            body.append(f"--{boundary}--".encode())
            body.append(b"")
            payload = b"\r\n".join(body)

            req = urllib.request.Request(
                f"{API_URL}/analyze?offline=true&lightweight=true",
                data=payload,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                res_data = json.loads(resp.read().decode())
                verdict = res_data.get("verdict", {})
                score = verdict.get("threat_score")
                tier = verdict.get("tier")
                log(f"Pre-loaded '{eml_path.name}' -> Score: {score}/100 ({tier})", "success")
        except Exception as exc:
            log(f"Failed to pre-load '{eml_path.name}': {exc}", "warning")


def main() -> None:
    print("\n" + "=" * 78)
    log("SENTINEL-MAIL  .  ONE-COMMAND DEMO ENVIRONMENT LAUNCHER", "banner")
    print("=" * 78 + "\n")

    # 1. Start FastAPI Backend
    log("Starting FastAPI Backend Server...", "info")
    api_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", str(API_PORT)],
        cwd=str(BASE_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if not wait_for_service(f"{API_URL}/health", "FastAPI Backend"):
        api_process.terminate()
        sys.exit(1)

    # 2. Pre-load 5 Sample Emails
    preload_sample_emails()

    # 3. Start Vite Frontend Server
    log("Starting Vite Frontend Server...", "info")
    frontend_cmd = ["npm", "run", "dev", "--", "--port", str(FRONTEND_PORT), "--host", "127.0.0.1"]
    if sys.platform == "win32":
        frontend_cmd[0] = "npm.cmd"

    frontend_process = subprocess.Popen(
        frontend_cmd,
        cwd=str(FRONTEND_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if not wait_for_service(FRONTEND_URL, "Vite Frontend"):
        api_process.terminate()
        frontend_process.terminate()
        sys.exit(1)

    # 4. Open Dashboard in Browser
    log(f"Opening Sentinel-Mail Dashboard in browser ({FRONTEND_URL})...", "success")
    time.sleep(1)
    webbrowser.open(FRONTEND_URL)

    print("\n" + "=" * 78)
    log("DEMO ENVIRONMENT IS LIVE AND READY FOR JUDGES!", "success")
    log(f"  * Dashboard UI : {FRONTEND_URL}", "info")
    log(f"  * REST API Docs: {API_URL}/docs", "info")
    log("Press Ctrl+C at any time to shut down the demo processes cleanly.", "warning")
    print("=" * 78 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Shutting down demo environment...", "info")
        api_process.terminate()
        frontend_process.terminate()
        log("Sentinel-Mail Demo Environment stopped cleanly. Goodbye!", "success")


if __name__ == "__main__":
    main()
