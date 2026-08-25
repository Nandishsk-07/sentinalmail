@echo off
set PYTHONIOENCODING=utf-8
echo ==============================================================================
echo   Starting Sentinel-Mail Demo Environment...
echo ==============================================================================

python run_demo.py
if %errorlevel% neq 0 (
    echo [x] Error executing run_demo.py
    pause
)
