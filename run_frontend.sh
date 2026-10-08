#!/usr/bin/env bash
# Script to launch LegaVault Objective 1 React Frontend (Vite dev server)
set -e

cd "$(dirname "$0")/frontend"

echo "=========================================================="
echo " Starting LegaVault React Frontend (Vite Dev Server)"
echo " Local URL: http://localhost:5173"
echo " Proxying API calls to backend: http://127.0.0.1:8000"
echo "=========================================================="

npm run dev
