@echo off
cd /d C:\backend_hasht
call venv\Scripts\activate

set CAPE_URL=http://100.98.98.28:8000
set CAPE_TOKEN=3fa8fdbd38e285b1d4b108cae356530eabf44c4a

set MODE=B

set API_KEY=

set MAX_WAIT=600
set LOG_PATH=logs\events.csv

echo.
echo Starting backend on port 5000 (mode %MODE%)...
echo CAPE_URL = %CAPE_URL%
echo.
uvicorn main:app --host 0.0.0.0 --port 5000 --workers 1

pause