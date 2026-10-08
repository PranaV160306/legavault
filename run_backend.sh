#!/usr/bin/env bash
# Script to launch LegaVault Objective 1 Secure Backend
set -e

cd "$(dirname "$0")"

# Detect virtual environment
if [ -d "venv" ]; then
    PYTHON_BIN="venv/bin/python"
    UVICORN_BIN="venv/bin/uvicorn"
elif [ -d "../venv" ]; then
    PYTHON_BIN="../venv/bin/python"
    UVICORN_BIN="../venv/bin/uvicorn"
else
    PYTHON_BIN="python3"
    UVICORN_BIN="uvicorn"
fi

echo "=========================================================="
echo " Starting LegaVault Objective 1 Backend Engine"
echo " Host: http://127.0.0.1:8000"
echo " API Docs (Swagger): http://127.0.0.1:8000/docs"
echo " Interactive Web App: http://127.0.0.1:8000/app"
echo "=========================================================="

$UVICORN_BIN backend.app.main:app --host 127.0.0.1 --port 8000 --reload
