#!/usr/bin/env bash
# run_demo.sh — One-Command Sentinel-Mail Demo Launcher for Linux/macOS/Bash

export PYTHONIOENCODING="utf-8"

echo "=============================================================================="
echo "  Starting Sentinel-Mail Demo Environment..."
echo "=============================================================================="

if command -v python3 &>/dev/null; then
    python3 run_demo.py
elif command -v python &>/dev/null; then
    python run_demo.py
else
    echo "[x] Error: Python is not installed or not in PATH."
    exit 1
fi
