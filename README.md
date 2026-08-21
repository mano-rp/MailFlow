# MailFlow — SME Email Shield

> Real-time email security shield for Gmail — featuring native Gmail DOM UI injections, inline threat scanning, quarantine triage hub, and zero-trust link defanging.

---

## Architecture Overview

```
MailFlow/
├── start_backend.sh          # One-click start script with clean Ctrl+C shutdown
├── backend/                  # Minimal FastAPI Health-Check & Ping Server
│   ├── main.py               # REST endpoints (/api/ping, /api/scan-ping)
│   └── requirements.txt      # fastapi, uvicorn, pydantic
├── extension/                # Chrome Extension Manifest V3
│   ├── manifest.json         # Extension configuration & content script rules
│   ├── popup.html            # Minimalist Settings & Live Connection Status UI
│   ├── popup.css             # Clean, modern styling & glowing status dot
│   ├── popup.js              # Real-time backend connectivity heartbeat & storage
│   ├── content.js            # Native DOM injections & backend dependency gate
│   ├── styles.css            # Gmail Material 3 design tokens & offline states
│   └── icons/                # Extension badge icons (16x16, 48x48, 128x128)
└── .gitignore
```

---

## Quickstart Guide

### 1. Start the Backend Server

Start the local FastAPI server with the provided script (handles clean shutdown on `Ctrl+C`):

```bash
./start_backend.sh
```

- Server URL: `http://127.0.0.1:8000`
- Health check: `GET http://localhost:8000/api/ping`
- Scan test: `POST http://localhost:8000/api/scan-ping`

> **Note:** The extension requires the backend to be running. If the backend is stopped, the extension gracefully pauses scanning and indicates offline status across all UI components.

---

### 2. Load the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top right corner.
3. Click **Load unpacked** in the top left.
4. Select the `/home/winters/MailFlow/extension` directory.
5. Pin the **MailFlow** extension icon to your Chrome toolbar.

---

### 3. Native Gmail Injections & Features

1. **Popup Settings & Live Connectivity Indicator:**
   - Click the extension icon in Chrome's toolbar.
   - Shows a glowing `● Connected` status card with real-time latency when the backend is active, or `○ Disconnected` if offline.
2. **Left Sidebar `🛡️ MailFlow` Tab:**
   - Injected under standard Gmail folders (Inbox, Drafts).
   - Shows `0` or `Offline` badge depending on backend status.
   - Clicking opens the **MailFlow Quarantine & Triage Hub**.
3. **Per-Row Inline `[ 🛡️ Scan ]` Button:**
   - Hover over any email row (`tr.zA`).
   - Clicking **Scan** triggers a real-time safety scan (`POST /api/scan-ping`) and displays a native Gmail floating toast.
