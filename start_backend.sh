#!/usr/bin/env bash

# Resolve project root and backend directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
cd "$ROOT_DIR"

# Auto-detect and activate the best available Python virtual environment
VENV_DIR=""

if [ -n "$VIRTUAL_ENV" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
  VENV_DIR="$VIRTUAL_ENV"
elif [ -d "/home/winters/CTFs/InCTF/venv" ] && [ -x "/home/winters/CTFs/InCTF/venv/bin/python" ]; then
  VENV_DIR="/home/winters/CTFs/InCTF/venv"
elif [ -d "$ROOT_DIR/.venv" ] && [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  VENV_DIR="$ROOT_DIR/.venv"
elif [ -d "$ROOT_DIR/backend/.venv" ] && [ -x "$ROOT_DIR/backend/.venv/bin/python" ]; then
  VENV_DIR="$ROOT_DIR/backend/.venv"
fi

if [ -n "$VENV_DIR" ]; then
  # Activate virtual environment
  source "$VENV_DIR/bin/activate"
  PYTHON="$VENV_DIR/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
else
  echo "[MailFlow Error] No suitable Python 3 found. Please create a virtual environment."
  exit 1
fi

# Ensure PYTHONPATH contains backend directory for all imports
export PYTHONPATH="$BACKEND_DIR:$ROOT_DIR:$PYTHONPATH"

echo "========================================================"
echo "  MailFlow Shield — Backend API Server"
echo "  Host: http://127.0.0.1:8000"
echo "  VirtualEnv: ${VENV_DIR:-system}"
echo "  Python: $PYTHON"
echo "  Press [Ctrl+C] to cleanly stop the server"
echo "========================================================"

# Replace shell with python process for instant, clean signal handling (Ctrl+C / SIGINT)
exec "$PYTHON" -m uvicorn main:app --app-dir "$BACKEND_DIR" --host 0.0.0.0 --port 8000 --reload
