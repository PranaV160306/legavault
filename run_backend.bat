@echo off
REM Windows script to start LegaVault Objective 1 Backend
echo ==========================================================
echo  Starting LegaVault Objective 1 Backend Engine (Windows)
echo  Host: http://127.0.0.1:8000
echo  API Docs: http://127.0.0.1:8000/docs
echo  Interactive Web App: http://127.0.0.1:8000/app
echo ==========================================================

cd /d "%~dp0"

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
    python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
) else (
    python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
)
pause
