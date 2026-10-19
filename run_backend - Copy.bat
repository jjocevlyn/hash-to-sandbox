@echo off
cd /d C:\backend_hasht
call venv\Scripts\activate

REM --- CAPEv2 host (Laptop C) via Tailscale ---
set CAPE_URL=http://YOUR_CAPEV2_IP:8000
set CAPE_TOKEN=YOUR_CAPEV2_API_TOKEN

REM --- Mode: A = all files to sandbox, B = check hash first ---
set MODE=B

REM --- Secret key for extension (empty = unused) ---
set API_KEY=

set MAX_WAIT=600
set LOG_PATH=logs\events.csv

echo.
echo Starting backend on port 5000 (mode %MODE%)...
echo CAPE_URL = %CAPE_URL%
echo.
uvicorn main:app --host 0.0.0.0 --port 5000 --workers 1

pause