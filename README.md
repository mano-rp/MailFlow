# MailFlow — SME Email Shield

> **Native Gmail Threat Detection & Heuristic Defense Engine**  
> Client-side browser extension and local heuristic analysis engine protecting organizations against Business Email Compromise (BEC), credential harvesting, invoice manipulation, and homoglyph domain attacks.

---

## System Architecture

MailFlow pairs a Google Chrome content script running inside the Gmail DOM with a local, low-latency FastAPI evaluation service.

```mermaid
graph TD
    A[Gmail Inbox Interface] -->|1. User Clicks Action Button| B[Capture-Phase Event Interceptor]
    B -->|2. Extract Row Metadata| C[Payload Builder]
    C -->|3. POST /api/scan| D[FastAPI Heuristic Engine]
    
    subgraph Heuristic Evaluation Engine
        D --> E1[Vector 1: Urgency & Coercion]
        D --> E2[Vector 2: Financial & BEC]
        D --> E3[Vector 3: Credential Harvesting]
        D --> E4[Vector 4: Lookalike & Homoglyphs]
        
        E1 --> F[Composite Risk Calculator]
        E2 --> F
        E3 --> F
        E4 --> F
    end
    
    F -->|Risk Score 0 - 100| G{Risk Tier Evaluation}
    
    G -->|Score 0 - 35| H[Low Risk: Verified Safe]
    G -->|Score 36 - 74| I[Moderate Risk: Watchlist]
    G -->|Score 75 - 100| J[High Risk: Quarantine]
    
    H -->|Update Action Icon to Checkmark| K[Active Inbox Row]
    I -->|Retain Warning Status| K
    I -->|Index into Watchlist| L[MailFlow Tab View]
    J -->|Execute Slide-Out & Hide Row| K
    J -->|Index into Quarantine| L
    
    I -->|Sync State| M[(Local Storage)]
    J -->|Sync State| M
    M -->|Restore State on Reload| K
```

---

## Threat Detection Flow & Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor User as User
    participant Row as Gmail Email Row
    participant Ext as Content Script (content.js)
    participant API as Heuristic API (/api/scan)
    participant Store as Browser Storage (localStorage)
    participant Tab as MailFlow Triage View

    User->>Row: Hovers row and clicks [ Shield ] action button
    Note over Ext: Intercepts click at capture phase<br/>Stops Gmail row-click selection handlers
    Ext->>Row: Renders inline spinner and row highlight
    Ext->>Ext: Extracts sender, subject, preview snippet, timestamp
    Ext->>API: POST /api/scan { sender, subject, snippet }

    rect rgb(245, 247, 250)
        Note over API: Multi-Vector Security Pipeline
        API->>API: Step 1: Urgency & Psychological Coercion Analysis
        API->>API: Step 2: Financial Vector & Payment Tampering Detection
        API->>API: Step 3: Credential Harvesting & Auth Manipulation
        API->>API: Step 4: Sender Lookalike & Typo-Squatting Check
        API->>API: Computes composite risk score (0 - 100) and assigns tier
    end

    API-->>Ext: Returns ThreatRecord { id, risk_score, tier, threat_type, explanation }
    Ext->>Store: Persists record to local threat registry

    alt Low Risk (Score: 0 - 35)
        Ext->>Row: Updates action button to Checkmark [✓]
        Ext->>User: Displays "Verified Safe" notification
    else Moderate Risk (Score: 36 - 74)
        Ext->>Row: Updates action button to Warning [!]
        Ext->>Tab: Adds item to "Watchlist & Moderate Risks" section
        Ext->>Store: Saves warning state for cross-view retention
        Ext->>User: Displays caution notification
    else High Risk (Score: 75 - 100)
        Ext->>Row: Triggers CSS slide-to-right quarantine transition
        Ext->>Row: Hides row (display: none)
        Ext->>Ext: Increments sidebar badge counter (+1)
        Ext->>Tab: Indexes item under "Quarantined Threats"
        Ext->>User: Displays quarantine notification
    end
```

---

## Technical Detection Logic

Each scanned email payload is evaluated against four distinct heuristic modules. Each module inspects the metadata for known social engineering signatures and assigns a vector score.

```
                  ┌─────────────────────────────────────────┐
                  │    Scanned Email Metadata Payload       │
                  │ (Sender Name, Email, Subject, Snippet)  │
                  └────────────────────┬────────────────────┘
                                       │
         ┌───────────────────┬─────────┴─────────┬───────────────────┐
         ▼                   ▼                   ▼                   ▼
 ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
 │   Vector 1    │   │   Vector 2    │   │   Vector 3    │   │   Vector 4    │
 │   Urgency &   │   │  Financial &  │   │  Credential   │   │   Lookalike   │
 │   Coercion    │   │  Invoice BEC  │   │  Harvesting   │   │  & Homoglyphs │
 └───────┬───────┘   └───────┬───────┘   └───────┬───────┘   └───────┬───────┘
         │                   │                   │                   │
         └───────────────────┼───────────────────┴───────────────────┘
                             ▼
              ┌─────────────────────────────┐
              │ Composite Scoring Engine    │
              └──────────────┬──────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
   [ Low: 0 - 35 ]   [ Moderate: 36 - 74 ] [ High: 75 - 100 ]
     Verified Safe     Watchlist Flagged     Quarantined Row
```

### 1. Urgency & Coercion Analysis (`backend/heuristics/urgency.py`)
* **Objective:** Identifies artificial urgency, fear appeals, and deadline intimidation designed to bypass verification workflows.
* **Evaluated Signals:**
  * Strict time countdowns (`"within 24 hours"`, `"immediate action required"`, `"expires today"`).
  * Account penalties and suspension intimidation (`"account suspended"`, `"access revoked"`, `"service termination"`).
  * Legal and executive pressure (`"final notice"`, `"compliance violation"`, `"strictly confidential"`).

### 2. Financial Vector & BEC Manipulation (`backend/heuristics/financial.py`)
* **Objective:** Detects invoice fraud, payment redirection, banking parameter tampering, and gift card/crypto extortion.
* **Evaluated Signals:**
  * Bank routing alterations (`"updated bank details"`, `"new account"`, `"new IBAN"`, `"sort code"`).
  * Wire transfer and invoice manipulation (`"wire transfer"`, `"invoice overdue"`, `"payment advice"`).
  * Untraceable payment requests (cryptocurrency wallet addresses, prepaid gift cards).

### 3. Credential Harvesting & Auth Manipulation (`backend/heuristics/credentials.py`)
* **Objective:** Detects deceptive authentication redirects, password reset traps, and signature lures.
* **Evaluated Signals:**
  * Password traps (`"password reset request"`, `"password expired"`, `"unlock account"`).
  * Session and 2FA verification lures (`"verify identity"`, `"re-authenticate"`, `"2fa update"`).
  * Document signature lures (fake DocuSign, Adobe Sign, or Google Docs review notifications).

### 4. Lookalike Domains & Homoglyph Anomalies (`backend/heuristics/lookalike.py`)
* **Objective:** Detects brand typosquatting, character substitution homoglyphs, and high-risk top-level domains.
* **Evaluated Signals:**
  * Brand typosquatting / homoglyphs (`paypa1`, `micros0ft`, `g00gle`, `amaz0n`, `netf1ix`).
  * Security-deceptive subdomains (`*-security.*`, `*-auth.*`, `*-verify.*`, `*-support.*`).
  * High-risk TLD patterns (`.xyz`, `.top`, `.click`, `.work`, `.gq`, `.cf`).

---

## Composite Scoring Model

The composite scoring engine determines the overall threat score by evaluating primary and secondary vector contributions:

$$\text{Composite Score} = \text{Primary Vector Score} + \left( \sum \text{Secondary Vector Scores} \times 0.35 \right)$$

$$\text{Final Score} = \min(\max(\text{round}(\text{Composite Score}), 0), 100)$$

| Risk Tier | Score Range | Default Action | Interface Treatment |
| :--- | :---: | :--- | :--- |
| **Low Risk** | `0 – 35` | Mark Safe | Green checkmark indicator; thread remains in inbox |
| **Moderate Risk** | `36 – 74` | Flag Watchlist | Amber warning indicator; state retained; indexed in MailFlow tab |
| **High Risk** | `75 – 100` | Quarantine | Red alert indicator; slide-out quarantine transition; isolated in MailFlow tab |

---

## Chrome Extension & State Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Initialized: Extension Loaded in Gmail
    Initialized --> Monitoring: DOM Observer Active
    
    Monitoring --> Scanning: User clicks Scan [ Shield ]
    Scanning --> VerdictReceived: API Returns Risk Score
    
    state VerdictReceived {
        [*] --> LowRiskAction: Score <= 35
        [*] --> ModerateRiskAction: 36 <= Score <= 74
        [*] --> HighRiskAction: Score >= 75
        
        LowRiskAction --> MarkClean: Render Checkmark
        ModerateRiskAction --> RetainWarning: Render Warning Icon
        HighRiskAction --> QuarantineRow: Trigger Slide-Out & Hide
    }
    
    RetainWarning --> LocalStorageSync: Persist Threat Record
    QuarantineRow --> LocalStorageSync: Persist Threat Record
    
    LocalStorageSync --> PageReload: User Refreshes / Switches Views
    PageReload --> StateRestoration: Match Rows against LocalStorage
    StateRestoration --> Monitoring: Restore Warnings / Keep Quarantined
```

### Key UI Features

* **Capture-Phase Interception:** Action button click handlers utilize `{ capture: true }` and `e.stopImmediatePropagation()` to intercept user clicks before Gmail's row-selection scripts navigate into email threads.
* **MailFlow Threat Center View:** Injected directly into Gmail's left navigation sidebar. Displays quarantined and watchlist emails in a clean native table layout matching Gmail's internal styling.
* **Accordion Detail Drawers:** Clicking any row in the MailFlow tab expands an inline drawer presenting the security evaluation, matched heuristic triggers, full metadata, and a `[ Restore to Inbox ]` action.
* **Cross-Session State Retention:** Stores verified and flagged threat records in browser `localStorage`, ensuring moderate risk warnings and quarantined items remain synced across folder changes and page reloads.

---

## Quickstart Guide

### 1. Start the Backend Service

Execute the startup script from the project root:

```bash
./start_backend.sh
```

* Backend Host: `http://127.0.0.1:8000`
* Health Endpoint: `GET /api/ping`
* Scan Endpoint: `POST /api/scan`
* Threat Registry: `GET /api/threats`

### 2. Load the Extension into Google Chrome

1. Navigate to `chrome://extensions/` in Chrome.
2. Toggle on **Developer mode** in the upper-right corner.
3. Click **Load unpacked** and select the `/home/winters/MailFlow/extension` directory.
4. Open [Gmail](https://mail.google.com/) and hover over any email row to evaluate incoming messages.
