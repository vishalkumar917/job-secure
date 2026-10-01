#!/usr/bin/env bash
# Start backend (http://localhost:8000) and frontend (http://localhost:5173). Ctrl+C stops both.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$ROOT/backend" && .venv/bin/uvicorn app.main:app --reload --port 8000) &
BACK=$!
trap 'kill $BACK' EXIT
cd "$ROOT/frontend" && npm run dev
