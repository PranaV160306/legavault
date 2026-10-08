@echo off
REM Windows script to start LegaVault Objective 1 React Frontend
echo ==========================================================
echo  Starting LegaVault React Frontend (Windows)
echo  Local URL: http://localhost:5173
echo ==========================================================

cd /d "%~dp0frontend"
npm run dev
pause
