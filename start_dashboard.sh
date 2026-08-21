#!/usr/bin/env bash
# ==============================================================================
# MailFlow Fleet Command — SME Admin Dashboard Runner
# Binds to 0.0.0.0:8500 for local & LAN multi-device accessibility.
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=8500

echo "=================================================================="
echo "  Starting MailFlow Fleet Command — SME Admin Dashboard"
echo "=================================================================="

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is not installed or not in PATH."
    exit 1
fi

# Detect Local IP for LAN access
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "0.0.0.0")

echo "[+] Serving Dashboard on port ${PORT} bound to 0.0.0.0"
echo "[+] Local Access:   http://127.0.0.1:${PORT}"
echo "[+] Network Access: http://${LOCAL_IP}:${PORT}"
echo "[+] Press [Ctrl+C] to stop the server cleanly"
echo "=================================================================="

exec python3 "${DIR}/dashboard/server.py"
