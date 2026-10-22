#!/usr/bin/env bash
# Script to launch LegaVault Objective 1 Secure Backend
set -e

cd "$(dirname "$0")"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"

# Detect virtual environment
if [ -d "venv" ]; then
    PYTHON_BIN="venv/bin/python"
elif [ -d "../venv" ]; then
    PYTHON_BIN="../venv/bin/python"
else
    PYTHON_BIN="python3"
fi

echo "=========================================================="
echo " Starting LegaVault Objective 1 Backend Engine"
echo " Host: http://${HOST}:${PORT}"
echo " API Docs (Swagger): http://${HOST}:${PORT}/docs"
echo " Interactive Web App: http://${HOST}:${PORT}/app"
echo "=========================================================="

"$PYTHON_BIN" -m uvicorn backend.app.main:app --host "$HOST" --port "$PORT" --reload
