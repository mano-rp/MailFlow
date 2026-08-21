# MailFlow — SME Email Shield

> **Native Gmail Threat Detection & Heuristic Defense Engine**  
> Real-time email threat evaluation protecting businesses from Business Email Compromise (BEC), credential harvesting, invoice tampering, and lookalike domain attacks.

---

## Detection Pipeline

```
[ Gmail Email Row ] ──► ( Click Shield ) ──► [ Content Script Interceptor ]
                                                       │
                                                       ▼ (POST /api/scan)
                                           [ Heuristic Detection Core ]
                                                       │
                ┌──────────────────────────────────────┼──────────────────────────────────────┐
                ▼                                      ▼                                      ▼
       Low Risk (0–35)                        Moderate Risk (36–74)                  High Risk (75–100)
       • Verified Safe                        • Watchlist Flagged                    • Quarantined Alert
       • Stays in Active Inbox                • Retained in Inbox & Tab              • Slide-Off Animation
       • Clean Checkmark Indicator            • Warning Status Indicator             • Isolated in MailFlow Tab
```

---

## Technical Detection Logic

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

---

## Composite Scoring Model

$$\text{Composite Score} = \text{Primary Vector Score} + \left( \sum \text{Secondary Vector Scores} \times 0.35 \right)$$

$$\text{Final Score} = \min(\max(\text{round}(\text{Composite Score}), 0), 100)$$

| Risk Tier | Score Range | Default Action | Interface Treatment |
| :--- | :---: | :--- | :--- |
| **Low Risk** | 0 – 35 | Mark Safe | Clean checkmark indicator; thread remains in inbox |
| **Moderate Risk** | 36 – 74 | Flag Watchlist | Warning indicator; state retained; indexed in MailFlow tab |
| **High Risk** | 75 – 100 | Quarantine | Slide-out quarantine transition; isolated in MailFlow tab |

---

## Chrome Extension & DOM Integration

* **Capture-Phase Event Handling:** Intercepts scan clicks at the capture phase (`{ capture: true }`), preventing Gmail's row-selection scripts from navigating into email threads during scanning.
* **Quarantine Animation:** High-risk threats execute a smooth CSS slide-out transition (`transform: translateX(110%); opacity: 0;`), unmounting from the inbox and incrementing the sidebar counter.
* **Gmail-Native Triage Tab:** A dedicated **MailFlow** view styled to match Gmail's table rows. Clicking any flagged email expands an inline drawer showing the heuristic breakdown, matched rules, and a **`[ Restore to Inbox ]`** action.
* **State Retention:** Uses browser `localStorage` to persist flagged moderate and quarantined states across page refreshes and folder navigation.

---

## Quickstart Guide

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
