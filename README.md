# MailFlow — SME Email Shield

> Real-time email security shield for Gmail — featuring native Gmail DOM UI injections, inline threat scanning, quarantine triage hub, and zero-trust link defanging.

---

## Architecture Overview

```
MailFlow/
├── backend/                  # Minimal FastAPI Health-Check & Ping Server
│   ├── main.py               # REST endpoints (/api/ping, /api/scan-ping)
│   └── requirements.txt      # fastapi, uvicorn, pydantic
├── extension/                # Chrome Extension Manifest V3
│   ├── manifest.json         # Extension configuration & content script rules
│   ├── popup.html            # Settings & Health Check UI Dropdown
│   ├── popup.css             # Scholarcy & M3 inspired design styling
│   ├── popup.js              # Popup controller with real-time ping benchmark
│   ├── content.js            # Native Gmail DOM injections & MutationObserver
│   ├── styles.css            # Native Material 3 Gmail UI injection stylesheet
│   └── icons/                # Extension badge icons (16x16, 48x48, 128x128)
└── .gitignore
```

---

## Quickstart Guide

### 1. Run the Local Backend Server

In a terminal, start the FastAPI ping server:

```bash
cd backend
python3 -m pip install -r requirements.txt
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Verify backend health:
- `GET http://localhost:8000/api/ping` -> `{"status": "online", "version": "0.1.0", ...}`
- `POST http://localhost:8000/api/scan-ping` -> `{"status": "received", "mock_verdict": "safe", "latency_ms": 12}`

---

### 2. Load the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top right corner.
3. Click **Load unpacked** in the top left.
4. Select the `/home/winters/MailFlow/extension` directory.
5. Pin the **MailFlow** extension icon to your Chrome toolbar.

---

### 3. Test Native Gmail DOM Injections

1. Navigate to [Gmail](https://mail.google.com/).
2. **Sidebar Navigation Tab:**
   - Notice the injected `🛡️ MailFlow` navigation item in the left sidebar under Inbox / Drafts.
   - Click it to swap into the **MailFlow Quarantine & Triage Hub**.
   - Click Inbox or any native folder to restore your inbox view.
3. **Per-Row Scan Action Button:**
   - Hover over any email row (`tr.zA`).
   - Notice the injected `[ 🛡️ Scan ]` button next to Archive / Delete / Mark as read.
   - Click **Scan** to trigger a real-time health handshake (`POST /api/scan-ping`), view the spinning progress indicator, and inspect the native Gmail floating toast notification.
4. **Popup Settings & Live Ping Tester:**
   - Click the extension icon in Chrome's toolbar to open the **MailFlow Shield** popup.
   - Click **Test Backend Ping** to run a live latency check against `localhost:8000`.
   - Toggle settings (e.g. *Show inline action buttons*) to observe real-time UI updates without page reloads.
