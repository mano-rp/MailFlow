# MailFlow — SME Email Shield

> **Native Gmail Threat Detection & Heuristic Defense Engine**  
> Real-time email threat evaluation protecting businesses from Business Email Compromise (BEC), credential harvesting, invoice tampering, and lookalike domain attacks.

---

## ⚡ Detection Pipeline

```
[ Gmail Email Row ] ──( Click 🛡️ )──► [ Content Script Interceptor ]
                                                │
                                                ▼ (POST /api/scan)
                                    [ Heuristic Detection Core ]
                                                │
             ┌──────────────────────────────────┼──────────────────────────────────┐
             ▼                                  ▼                                  ▼
    🟢 Low Risk (0–35)                🟡 Moderate (36–74)                🔴 High Risk (75–100)
    • Verified Safe (✓)               • Watchlist Warning (⚠)            • Quarantined Alert (✕)
    • Stays in Active Inbox           • Retained Across Refreshes        • Slide-Off Animation
    • No Threats Detected             • Indexed in MailFlow Tab          • Isolated in MailFlow Tab
```

---

## 🔬 Technical Detection Logic

When an email is scanned, its sender, subject, and preview snippet are evaluated through a sub-50ms multi-vector heuristic engine across four security vectors:

### 1. Urgency & Psychological Coercion
* **Mechanism:** Regex pattern matching evaluating coercive psychological triggers.
* **Signals:** Time-pressure countdowns (`"within 24 hours"`, `"expires today"`), account suspension threats (`"account disabled"`, `"access revoked"`), and legal intimidation (`"final notice"`, `"lawsuit"`).

### 2. Financial Vector & BEC Invoice Tampering
* **Mechanism:** Identifies payment redirection vectors and wire transfer manipulation.
* **Signals:** Banking detail updates (`"updated bank details"`, `"new IBAN"`, `"routing number"`), invoice tampering (`"invoice #..."`, `"remittance advice"`), and untraceable payment demands (cryptocurrency, gift cards).

### 3. Credential Harvesting & Auth Manipulation
* **Mechanism:** Detects session hijacking, fake authentication lures, and signature phishing.
* **Signals:** Password reset traps (`"reset password"`, `"password expired"`), identity verification prompts (`"verify credentials"`, `"re-authenticate"`), fake 2FA alerts, and DocuSign/AdobeSign document lures.

### 4. Sender Identity & Homoglyph Anomalies
* **Mechanism:** Typosquatting and domain spoofing analysis.
* **Signals:** Alphanumeric substitutions and brand homoglyphs (`paypa1`, `micros0ft`, `g00gle`), deceptive keyword subdomains (`*-security.*`, `*-verify.*`), and high-risk Top-Level Domains (`.xyz`, `.top`, `.click`, `.work`).

### 🧮 Composite Scoring Model
```
Composite Score = Primary_Vector_Score + (Σ Secondary_Vector_Scores × 0.35)
Final Score = min(max(round(Composite Score), 0), 100)
```
The highest severity vector establishes the baseline score, while secondary triggered indicators compound the total risk value into one of three risk tiers (🟢 Low, 🟡 Moderate, 🔴 High).

---

## 🧩 Chrome Extension & DOM Engine

The MailFlow extension operates seamlessly inside the native Gmail interface:

* **Capture-Phase Event Handling:** Intercepts scan clicks at the capture phase (`{ capture: true }`), preventing Gmail's row-selection scripts from opening the email thread during scanning.
* **Quarantine Animation:** High-risk threats execute a smooth CSS slide-out transition (`transform: translateX(110%); opacity: 0;`), unmounting from the inbox and incrementing the sidebar counter.
* **Gmail-Native Triage Tab:** A dedicated **MailFlow** view styled to match Gmail's table rows. Clicking any flagged email expands an inline drawer showing the heuristic breakdown, matched rules, and a **`[ Restore to Inbox ]`** action.
* **State Retention:** Uses `localStorage` to persist flagged moderate (`⚠`) and quarantined (`🔴`) states across page refreshes and folder navigation.

---

## 🚀 Quickstart

### 1. Start the Backend Server
```bash
./start_backend.sh
```
*API runs locally at `http://127.0.0.1:8000`.*

### 2. Load the Chrome Extension
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select the `/home/winters/MailFlow/extension` folder.
4. Open [Gmail](https://mail.google.com/) and hover over any email row to scan.
