#!/usr/bin/env bash

# Resolve project root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Locate Python executable
if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PYTHON="$ROOT_DIR/.venv/bin/python"
elif [ -x "$ROOT_DIR/backend/.venv/bin/python" ]; then
  PYTHON="$ROOT_DIR/backend/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
else
  echo "[MailFlow Error] No suitable Python 3 found. Please install Python 3 or create a virtual environment."
  exit 1
fi

echo "========================================================"
echo "  MailFlow Shield — Backend API Server"
echo "  Host: http://127.0.0.1:8000"
echo "  Python: $PYTHON"
echo "  Press [Ctrl+C] to cleanly stop the server"
echo "========================================================"

# Replace shell with python process for instant, clean signal handling (Ctrl+C / SIGINT)
exec "$PYTHON" -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
