# MailFlow — SME Email Shield

> **Native Gmail Threat Detection & Heuristic Defense Engine**  
> Real-time email threat evaluation protecting businesses from Business Email Compromise (BEC), credential harvesting, invoice tampering, quishing, and lookalike domain attacks.

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
* **Mechanism:** Regex pattern matching evaluating coercive psychological triggers and executive pretexts.
* **Signals:** Time-pressure countdowns (`"within 24 hours"`, `"expires today"`), account suspension threats (`"account disabled"`, `"access revoked"`), executive availability baits (`"are you at your desk?"`, `"need a quick favor"`), and secrecy demands (`"strictly confidential - do not discuss with anyone"`).

### 2. Financial Vector & BEC Invoice Tampering
* **Mechanism:** Identifies payment redirection vectors, payroll changes, and wire transfer manipulation.
* **Signals:** Banking detail updates (`"updated bank details"`, `"new IBAN"`, `"routing number"`), audit account migration pretexts, invoice tampering (`"invoice #..."`, `"remittance advice"`), payroll direct deposit fraud, and untraceable payment demands (gift cards, cryptocurrency).

### 3. Credential Harvesting & Auth Manipulation
* **Mechanism:** Detects session hijacking, quishing (QR code phishing), OAuth grant traps, and malicious attachments.
* **Signals:** Password reset traps (`"reset password"`, `"password expired"`), identity verification prompts (`"verify credentials"`, `"re-authenticate"`), quishing prompts (`"scan the qr code to verify"`), OAuth consent lures (`"grant permissions"`), and macro/executable attachments (`".html attachment"`, `"enable macros"`).

### 4. Sender Identity & Homoglyph Anomalies
* **Mechanism:** Strict brand typosquatting and domain spoofing analysis with trusted root allowlisting.
* **Signals:** Strict homoglyph substitutions (`paypa1`, `micros0ft`, `g00gle`, `amaz0n`, `netf1ix`), deceptive keyword subdomains (`*-security.*`, `*-verify.*`), and high-risk Top-Level Domains (`.xyz`, `.top`, `.click`, `.work`).

---

## Composite Scoring Model

$$\text{Composite Score} = \text{Primary Vector Score} + \left( \sum \text{Secondary Vector Scores} \times 0.20 \right)$$

$$\text{Final Score} = \min(\max(\text{round}(\text{Composite Score}), 0), 100)$$

* **Compound Attack Rules:** Critical multi-vector pairings (e.g. Lookalike domain + Phishing lure, or Executive Secrecy + Gift Card extortion) automatically escalate to High Risk ($\ge 75$), while single-vector signals remain appropriately categorized as Moderate Risk (Watchlist).

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

## Fleet Command Dashboard (SME Admin)

MailFlow includes a standalone, zero-dependency Fleet Command Center dashboard designed for organizational threat analytics, incident triage, and real-time defense monitoring.

* **Multi-Device & LAN Accessible:** Binds to `0.0.0.0:8500` so administrators and judges can access the dashboard from any workstation, laptop, or mobile device on the local network (`http://<HOST_IP>:8500`).
* **Bidirectional Real-Time Synchronization:** Automatic continuous reconciliation between active extension endpoints, backend threat registries, and the dashboard. Restoring or purging an incident in the dashboard instantly un-quarantines the email in Gmail without desync.
* **Authentication Gate:** Protected by an administrative session gate (`admin@mailflow` / `1234`).
* **SME Automated Policy Engine:** Global toggles for executive homoglyph protection, bank account redirection lock, and quishing defense.

---

## Quickstart Guide

### 1. Start the Backend Server
```bash
./start_backend.sh
```
*API runs at `http://0.0.0.0:8000`.*

### 2. Start the SME Admin Dashboard
```bash
./start_dashboard.sh
```
*Dashboard runs at `http://0.0.0.0:8500` (Open [http://localhost:8500](http://localhost:8500) or `http://<LAN_IP>:8500`).*

### 3. Load the Chrome Extension
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select the `/home/winters/MailFlow/extension` directory.
4. Open [Gmail](https://mail.google.com/), hover over any email row, and click the **MailFlow** shield button to scan.

