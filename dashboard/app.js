/**
 * MailFlow SME Admin Dashboard — Fleet Command Engine
 * Real-time heuristic event consumer, KPI calculator, and threat mitigation hub.
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  const POLLING_INTERVAL_MS = 3000;
  const CAPITAL_PER_HIGH_RISK_USD = 15000;

  // State Management
  const state = {
    threats: [],
    activeFilter: 'all',
    searchQuery: '',
    expandedThreatIds: new Set(),
    isBackendOnline: false,
    theme: localStorage.getItem('mailflow_dashboard_theme') || 'light',
    policies: JSON.parse(localStorage.getItem('mailflow_dashboard_policies') || '{"bank-rules":true,"homoglyph-lock":true,"quishing-rules":true}'),
  };

  // DOM Elements Cache
  const DOM = {
    html: document.documentElement,
    themeToggleBtn: document.getElementById('btn-theme-toggle'),
    themeIcon: document.getElementById('theme-icon'),
    backendStatusBadge: document.getElementById('backend-status-badge'),
    backendStatusDot: document.getElementById('backend-status-dot'),
    backendStatusText: document.getElementById('backend-status-text'),
    manualRefreshBtn: document.getElementById('btn-manual-refresh'),
    kpiTotalScans: document.getElementById('kpi-total-scans'),
    kpiHighThreats: document.getElementById('kpi-high-threats'),
    kpiModerateThreats: document.getElementById('kpi-moderate-threats'),
    kpiCapitalSaved: document.getElementById('kpi-capital-saved'),
    filterTabs: document.querySelectorAll('.filter-tab'),
    countAll: document.getElementById('count-all'),
    countHigh: document.getElementById('count-high'),
    countModerate: document.getElementById('count-moderate'),
    countLow: document.getElementById('count-low'),
    searchInput: document.getElementById('threat-search-input'),
    seedThreatsBtn: document.getElementById('btn-seed-threats'),
    exportLogBtn: document.getElementById('btn-export-log'),
    tableBody: document.getElementById('threat-table-body'),
    emptyState: document.getElementById('table-empty-state'),
    toastContainer: document.getElementById('toast-container'),
    policyToggles: document.querySelectorAll('.policy-toggle'),
  };

  /**
   * --------------------------------------------------------------------------
   * THEME & INITIALIZATION
   * --------------------------------------------------------------------------
   */
  function applyTheme(theme) {
    state.theme = theme;
    localStorage.setItem('mailflow_dashboard_theme', theme);

    if (theme === 'dark') {
      DOM.html.classList.add('dark');
      DOM.html.classList.remove('light');
      if (DOM.themeIcon) DOM.themeIcon.setAttribute('data-lucide', 'sun');
    } else {
      DOM.html.classList.remove('dark');
      DOM.html.classList.add('light');
      if (DOM.themeIcon) DOM.themeIcon.setAttribute('data-lucide', 'moon');
    }

    if (window.lucide) {
      window.lucide.createIcons();
    }
  }

  function toggleTheme() {
    applyTheme(state.theme === 'dark' ? 'light' : 'dark');
  }

  /**
   * --------------------------------------------------------------------------
   * SME POLICY CONTROLS
   * --------------------------------------------------------------------------
   */
  function initPolicies() {
    if (!DOM.policyToggles) return;

    DOM.policyToggles.forEach(toggle => {
      const key = toggle.dataset.policy;
      if (key && typeof state.policies[key] !== 'undefined') {
        toggle.checked = Boolean(state.policies[key]);
      }

      toggle.addEventListener('change', (e) => {
        const checked = e.target.checked;
        state.policies[key] = checked;
        localStorage.setItem('mailflow_dashboard_policies', JSON.stringify(state.policies));

        const policyNames = {
          'bank-rules': 'Auto-Quarantine Bank Updates',
          'homoglyph-lock': 'Executive Homoglyph Lock',
          'quishing-rules': 'Quishing & Userinfo Traps',
        };
        const name = policyNames[key] || key;
        showToast(`Policy '${name}' ${checked ? 'enabled' : 'disabled'} across fleet`, checked ? 'success' : 'warning');
      });
    });
  }

  /**
   * --------------------------------------------------------------------------
   * TOAST NOTIFICATION SYSTEM
   * --------------------------------------------------------------------------
   */
  function showToast(message, type = 'info') {
    if (!DOM.toastContainer) return;

    const toast = document.createElement('div');
    toast.className = 'dashboard-toast flex items-center gap-2.5 px-4 py-3 rounded-lg shadow-lg text-xs font-medium border backdrop-blur-md';

    if (type === 'success') {
      toast.className += ' bg-emerald-50 dark:bg-emerald-950/90 text-emerald-800 dark:text-emerald-200 border-emerald-200 dark:border-emerald-800';
      toast.innerHTML = `<i data-lucide="check-circle" class="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0"></i><span>${escapeHtml(message)}</span>`;
    } else if (type === 'error' || type === 'alert') {
      toast.className += ' bg-red-50 dark:bg-red-950/90 text-red-800 dark:text-red-200 border-red-200 dark:border-red-800';
      toast.innerHTML = `<i data-lucide="alert-octagon" class="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0"></i><span>${escapeHtml(message)}</span>`;
    } else if (type === 'warning') {
      toast.className += ' bg-amber-50 dark:bg-amber-950/90 text-amber-800 dark:text-amber-200 border-amber-200 dark:border-amber-800';
      toast.innerHTML = `<i data-lucide="alert-triangle" class="w-4 h-4 text-amber-600 dark:text-amber-400 flex-shrink-0"></i><span>${escapeHtml(message)}</span>`;
    } else {
      toast.className += ' bg-white dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200 border-zinc-200 dark:border-zinc-700';
      toast.innerHTML = `<i data-lucide="info" class="w-4 h-4 text-brand-500 flex-shrink-0"></i><span>${escapeHtml(message)}</span>`;
    }

    DOM.toastContainer.appendChild(toast);
    if (window.lucide) window.lucide.createIcons();

    setTimeout(() => {
      toast.classList.add('hiding');
      setTimeout(() => toast.remove(), 200);
    }, 4000);
  }

  /**
   * --------------------------------------------------------------------------
   * DEMO DATA SEEDER
   * --------------------------------------------------------------------------
   */
  const DEMO_SEEDS = [
    {
      id: 'mf_seed_bec01',
      timestamp: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
      sender: 'Sharma Logistics <billing@sharma-invoices.com>',
      recipient: 'sarah.cfo@acme-corp.com',
      subject: 'Re: INV-2291 final notice - updated bank details, action required',
      snippet: 'Dear Sir/Madam, This is the final notice regarding the pending settlement of Rs. 9,85000 against INV-2291. Our earlier current account is temporarily frozen pending an audit, so kindly remit funds to our new IBAN immediately.',
      risk_score: 100,
      tier: 'high',
      color: 'red',
      threat_type: 'Urgent Financial / BEC Fraud',
      action: 'quarantine_slide',
      explanation: 'High-risk threat detected (Score 100/100). Flagged for: Bank Account Redirection / IBAN Tampering; Deceptive Audit Migration Pretext; Coercive Final Notice Warning. Quarantined to protect organization capital.',
      matched_steps: [
        {
          step_name: 'Financial & Invoice Redirection Check',
          score: 70.0,
          matched_rules: [
            "Bank Account Redirection / IBAN Tampering (matched: 'updated bank details')",
            "Deceptive Audit / Account Migration Pretext (matched: 'temporarily frozen pending an audit')",
            "Invoice / Billing Vector (matched: 'INV-2291')"
          ]
        },
        {
          step_name: 'Urgency & Coercion Check',
          score: 55.0,
          matched_rules: [
            "Coercive Final Notice Warning (matched: 'final notice')",
            "High Urgency Call-to-Action (matched: 'action required')"
          ]
        }
      ]
    },
    {
      id: 'mf_seed_phish02',
      timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
      sender: 'IT Helpdesk <support@it-services.sbs>',
      recipient: 'nithin@acme-corp.com',
      subject: 'Action required: mailbox storage full - verify to avoid loss',
      snippet: 'Dear User, Your mailbox has reached its storage limit. Incoming mail will be rejected until you increase your quota. Verify your account today: https://outlook.office.com:portal@quota-fix.sbs/renew. Login to confirm your account credentials.',
      risk_score: 100,
      tier: 'high',
      color: 'red',
      threat_type: 'Deceptive URL Spoofing / Phish',
      action: 'quarantine_slide',
      explanation: 'High-risk threat detected (Score 100/100). Flagged for: Deceptive URL Userinfo Spoofing (@ syntax masquerade); High-Risk Phishing TLD in Link (.sbs); Mailbox Quota Phishing Lure. Quarantined automatically.',
      matched_steps: [
        {
          step_name: 'Sender / Lookalike Anomaly Check',
          score: 100.0,
          matched_rules: [
            'Deceptive URL Userinfo Spoofing (@ syntax masquerade)',
            "High-Risk Phishing TLD in Link (flagged: '.sbs')",
            'Deceptive Credential / Quota Portal Hostname'
          ]
        },
        {
          step_name: 'Credential Harvesting Check',
          score: 85.0,
          matched_rules: [
            "Mailbox Storage / Quota Phishing Lure (matched: 'mailbox storage full')",
            "IT Helpdesk / Administrator Impersonation (matched: 'IT Helpdesk')",
            "Explicit Credential Submission Demand (matched: 'login and confirm')"
          ]
        }
      ]
    },
    {
      id: 'mf_seed_ceo03',
      timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
      sender: 'Alex Vance (CEO) <ceo@acme-corp.co>',
      recipient: 'alex.dev@acme-corp.com',
      subject: 'Quick confidential task - need it now',
      snippet: 'Are you at your desk? I need you to handle something for a client urgently and it is strictly confidential - do not discuss with anyone in the team until it is done. Please purchase 5 Apple Gift Cards for a client presentation.',
      risk_score: 80,
      tier: 'high',
      color: 'red',
      threat_type: 'Executive Impersonation / Gift Card Fraud',
      action: 'quarantine_slide',
      explanation: 'High-risk threat detected (Score 80/100). Flagged for: Secrecy & Isolation Pretext; Executive Impersonation Bait; Gift Card Payment Extortion.',
      matched_steps: [
        {
          step_name: 'Urgency & Coercion Check',
          score: 65.0,
          matched_rules: [
            "Secrecy & Isolation Pretext (matched: 'strictly confidential')",
            "Executive Impersonation / Availability Bait (matched: 'are you at your desk')",
            "High Urgency Call-to-Action (matched: 'urgently')"
          ]
        },
        {
          step_name: 'Financial & Invoice Redirection Check',
          score: 45.0,
          matched_rules: [
            "Gift Card Payment Extortion / BEC Task (matched: 'Apple Gift Cards')"
          ]
        }
      ]
    },
    {
      id: 'mf_seed_mod04',
      timestamp: new Date(Date.now() - 50 * 60 * 1000).toISOString(),
      sender: 'CloudScale Billing <accounts@cloudscale.io>',
      recipient: 'sarah.cfo@acme-corp.com',
      subject: 'Invoice INV-2291 - updated bank details',
      snippet: 'Dear Sir, We have shifted our current account due to an internal annual audit. Kindly process the pending payment for INV-2291 of Rs. 4,20,000 to our new account.',
      risk_score: 70,
      tier: 'moderate',
      color: 'yellow',
      threat_type: 'Unverified Bank Account Update',
      action: 'flag_warning',
      explanation: 'Moderate caution advised (Score 70/100). Detected: Bank Account Redirection / IBAN Tampering; Invoice / Billing Vector. Verify sender authenticity before authorizing funds.',
      matched_steps: [
        {
          step_name: 'Financial & Invoice Redirection Check',
          score: 70.0,
          matched_rules: [
            "Bank Account Redirection / IBAN Tampering (matched: 'updated bank details')",
            "Deceptive Audit / Account Migration Pretext (matched: 'shifted our current account')",
            "Invoice / Billing Vector (matched: 'Invoice INV-2291')"
          ]
        }
      ]
    },
    {
      id: 'mf_seed_mod05',
      timestamp: new Date(Date.now() - 90 * 60 * 1000).toISOString(),
      sender: 'Nithin <nithin@internal-team.org>',
      recipient: 'nithin@acme-corp.com',
      subject: 'Quick confidential task - need it now',
      snippet: 'Are you at your desk? I need you to handle something for a client urgently and it is strictly confidential - do not discuss with anyone in the team until it is done.',
      risk_score: 65,
      tier: 'moderate',
      color: 'yellow',
      threat_type: 'Executive Urgency Lure',
      action: 'flag_warning',
      explanation: 'Moderate caution advised (Score 65/100). Detected: Secrecy & Isolation Pretext; Executive Impersonation / Availability Bait.',
      matched_steps: [
        {
          step_name: 'Urgency & Coercion Check',
          score: 65.0,
          matched_rules: [
            "Secrecy & Isolation Pretext (matched: 'strictly confidential')",
            "Executive Impersonation / Availability Bait (matched: 'are you at your desk')"
          ]
        }
      ]
    },
    {
      id: 'mf_seed_clean06',
      timestamp: new Date(Date.now() - 120 * 60 * 1000).toISOString(),
      sender: 'Amazon Web Services <no-reply@amazon.com>',
      recipient: 'devops@acme-corp.com',
      subject: 'Amazon Web Services Invoice [92837102]',
      snippet: 'Your latest AWS billing statement is now available in the AWS Management Console for account ending in 4920.',
      risk_score: 0,
      tier: 'low',
      color: 'green',
      threat_type: 'Verified Safe',
      action: 'verified',
      explanation: 'Clean (Score 0/100). Authentic sender with zero urgency coercion, payment tampering, or lookalike anomalies detected.',
      matched_steps: []
    },
    {
      id: 'mf_seed_clean07',
      timestamp: new Date(Date.now() - 180 * 60 * 1000).toISOString(),
      sender: 'Frank Andrade and Diana Dovgopol <news@substack.com>',
      recipient: 'nithin@acme-corp.com',
      subject: 'Frank Andrade and Diana Dovgopol posted new notes',
      snippet: 'Read the latest AI articles and curated research notes from Substack creators.',
      risk_score: 0,
      tier: 'low',
      color: 'green',
      threat_type: 'Verified Safe',
      action: 'verified',
      explanation: 'Clean (Score 0/100). Standard publication newsletter with no malicious indicators.',
      matched_steps: []
    }
  ];

  function seedDemoThreats() {
    let newCount = 0;
    DEMO_SEEDS.forEach(seed => {
      const exists = state.threats.some(t => t.id === seed.id);
      if (!exists) {
        state.threats.push(seed);
        newCount++;
      }
    });

    // Sort descending by timestamp
    state.threats.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    updateKPIMetrics();
    renderThreatTable();
    showToast(`Seeded ${newCount || DEMO_SEEDS.length} enterprise security incidents into threat ledger`, 'success');
  }

  /**
   * --------------------------------------------------------------------------
   * BACKEND HEALTH & LIVE POLLING ENGINE
   * --------------------------------------------------------------------------
   */
  async function checkBackendPing() {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${BACKEND_URL}/api/ping`, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      clearTimeout(timeout);

      if (res.ok) {
        state.isBackendOnline = true;
        if (DOM.backendStatusDot) {
          DOM.backendStatusDot.className = 'w-2 h-2 rounded-full bg-emerald-500 shadow-sm shadow-emerald-500/50';
        }
        if (DOM.backendStatusText) {
          DOM.backendStatusText.textContent = 'API Connected (:8000)';
        }
      } else {
        throw new Error('API non-200');
      }
    } catch {
      state.isBackendOnline = false;
      if (DOM.backendStatusDot) {
        DOM.backendStatusDot.className = 'w-2 h-2 rounded-full bg-red-500';
      }
      if (DOM.backendStatusText) {
        DOM.backendStatusText.textContent = 'API Offline (:8000)';
      }
    }
  }

  async function fetchLiveThreats() {
    await checkBackendPing();

    if (!state.isBackendOnline) return;

    try {
      const res = await fetch(`${BACKEND_URL}/api/threats`, {
        headers: { 'Accept': 'application/json' }
      });

      if (res.ok) {
        const data = await res.json();
        const incoming = [...(data.high_risk || []), ...(data.moderate_risk || [])];

        let stateChanged = false;
        incoming.forEach(inc => {
          const exists = state.threats.some(t => t.id === inc.id);
          if (!exists) {
            state.threats.unshift(inc);
            stateChanged = true;
          }
        });

        if (stateChanged) {
          updateKPIMetrics();
          renderThreatTable();
        }
      }
    } catch (err) {
      console.warn('[MailFlow Dashboard] Threat polling error:', err);
    }
  }

  /**
   * --------------------------------------------------------------------------
   * THREAT MITIGATION ACTIONS (RESTORE & PURGE)
   * --------------------------------------------------------------------------
   */
  async function restoreThreat(threatId) {
    if (!threatId) return;

    const threat = state.threats.find(t => t.id === threatId);
    if (!threat) return;

    try {
      if (state.isBackendOnline) {
        fetch(`${BACKEND_URL}/api/threats/restore`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: threatId })
        }).catch(() => {});
      }
    } catch (e) {
      console.warn('[MailFlow Dashboard] Restore request err:', e);
    }

    threat.tier = 'low';
    threat.risk_score = 0;
    threat.action = 'restored';
    threat.threat_type = 'Restored by Admin';
    threat.explanation = 'Threat restored to employee inbox by SME security administrator.';

    updateKPIMetrics();
    renderThreatTable();
    showToast(`Threat restored to ${threat.recipient || 'employee'} inbox`, 'success');
  }

  function purgeThreat(threatId) {
    if (!threatId) return;

    const row = DOM.tableBody.querySelector(`tr[data-id="${threatId}"]`);
    if (row) {
      row.classList.add('purging');
    }

    setTimeout(() => {
      state.threats = state.threats.filter(t => t.id !== threatId);
      state.expandedThreatIds.delete(threatId);
      updateKPIMetrics();
      renderThreatTable();
      showToast('Threat record purged from security ledger', 'info');
    }, 180);
  }

  function toggleThreatDrawer(threatId) {
    if (state.expandedThreatIds.has(threatId)) {
      state.expandedThreatIds.delete(threatId);
    } else {
      state.expandedThreatIds.add(threatId);
    }
    renderThreatTable();
  }

  /**
   * --------------------------------------------------------------------------
   * SEARCH, FILTER & EXPORT
   * --------------------------------------------------------------------------
   */
  function handleFilterClick(e) {
    const btn = e.target.closest('.filter-tab');
    if (!btn) return;

    DOM.filterTabs.forEach(t => {
      t.classList.remove('active', 'text-zinc-900', 'dark:text-white', 'bg-white', 'dark:bg-zinc-700', 'shadow-sm');
      t.classList.add('text-zinc-600', 'dark:text-zinc-400');
    });

    btn.classList.add('active', 'text-zinc-900', 'dark:text-white', 'bg-white', 'dark:bg-zinc-700', 'shadow-sm');
    btn.classList.remove('text-zinc-600', 'dark:text-zinc-400');

    state.activeFilter = btn.dataset.filter || 'all';
    renderThreatTable();
  }

  function handleSearchInput(e) {
    state.searchQuery = (e.target.value || '').trim();
    renderThreatTable();
  }

  function exportThreatLog() {
    if (state.threats.length === 0) {
      showToast('No incidents to export.', 'warning');
      return;
    }

    const jsonStr = JSON.stringify(state.threats, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mailflow_threat_ledger_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast(`Exported ${state.threats.length} threat incident records (JSON)`, 'success');
  }

  /**
   * --------------------------------------------------------------------------
   * KPI METRIC CALCULATION ENGINE
   * --------------------------------------------------------------------------
   */
  function updateKPIMetrics() {
    const totalScans = state.threats.length;
    const highThreats = state.threats.filter(t => t.tier === 'high').length;
    const moderateThreats = state.threats.filter(t => t.tier === 'moderate').length;
    const lowThreats = state.threats.filter(t => t.tier === 'low').length;
    const capitalSaved = highThreats * CAPITAL_PER_HIGH_RISK_USD;

    if (DOM.kpiTotalScans) DOM.kpiTotalScans.textContent = totalScans.toLocaleString();
    if (DOM.kpiHighThreats) DOM.kpiHighThreats.textContent = highThreats.toLocaleString();
    if (DOM.kpiModerateThreats) DOM.kpiModerateThreats.textContent = moderateThreats.toLocaleString();
    if (DOM.kpiCapitalSaved) DOM.kpiCapitalSaved.textContent = `$${capitalSaved.toLocaleString()}`;

    if (DOM.countAll) DOM.countAll.textContent = totalScans;
    if (DOM.countHigh) DOM.countHigh.textContent = highThreats;
    if (DOM.countModerate) DOM.countModerate.textContent = moderateThreats;
    if (DOM.countLow) DOM.countLow.textContent = lowThreats;
  }

  /**
   * --------------------------------------------------------------------------
   * TABLE RENDERING & ACCORDION DRAWER
   * --------------------------------------------------------------------------
   */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[m]);
  }

  function formatTimestamp(isoStr) {
    if (!isoStr) return 'Just now';
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr;
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ', ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return isoStr;
    }
  }

  function getFilteredThreats() {
    return state.threats.filter(t => {
      // Filter by tier tab
      if (state.activeFilter !== 'all' && t.tier !== state.activeFilter) {
        return false;
      }
      // Filter by search query
      if (state.searchQuery) {
        const q = state.searchQuery.toLowerCase();
        const sender = (t.sender || '').toLowerCase();
        const subject = (t.subject || '').toLowerCase();
        const type = (t.threat_type || '').toLowerCase();
        const recipient = (t.recipient || '').toLowerCase();
        const explanation = (t.explanation || '').toLowerCase();
        return sender.includes(q) || subject.includes(q) || type.includes(q) || recipient.includes(q) || explanation.includes(q);
      }
      return true;
    });
  }

  function renderThreatTable() {
    if (!DOM.tableBody) return;

    const filtered = getFilteredThreats();

    if (filtered.length === 0) {
      DOM.tableBody.innerHTML = '';
      if (DOM.emptyState) DOM.emptyState.classList.remove('hidden');
      return;
    }

    if (DOM.emptyState) DOM.emptyState.classList.add('hidden');

    DOM.tableBody.innerHTML = filtered.map(t => {
      const isExpanded = state.expandedThreatIds.has(t.id);
      const isHigh = t.tier === 'high';
      const isModerate = t.tier === 'moderate';

      // Badge Styling
      let badgeClass = 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800';
      let dotColor = 'bg-emerald-500';
      let actionPill = '<span class="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 font-medium"><i data-lucide="check" class="w-3.5 h-3.5"></i> Inbox Safe</span>';

      if (isHigh) {
        badgeClass = 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800';
        dotColor = 'bg-red-500';
        actionPill = '<span class="inline-flex items-center gap-1 text-red-600 dark:text-red-400 font-medium"><i data-lucide="shield-x" class="w-3.5 h-3.5"></i> Quarantined (Slide)</span>';
      } else if (isModerate) {
        badgeClass = 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800';
        dotColor = 'bg-amber-500';
        actionPill = '<span class="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400 font-medium"><i data-lucide="alert-circle" class="w-3.5 h-3.5"></i> Watchlist Flag</span>';
      }

      // Format Matched Rules list
      let matchedRulesHtml = '<span class="text-zinc-400 dark:text-zinc-500">No anomaly patterns matched</span>';
      if (t.matched_steps && t.matched_steps.length) {
        const rules = [];
        t.matched_steps.forEach(s => {
          if (s.matched_rules && s.matched_rules.length) {
            s.matched_rules.forEach(r => rules.push(r));
          }
        });
        if (rules.length) {
          matchedRulesHtml = rules.map(r => `
            <li class="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
              <span class="w-1.5 h-1.5 rounded-full ${isHigh ? 'bg-red-500' : isModerate ? 'bg-amber-500' : 'bg-emerald-500'}"></span>
              ${escapeHtml(r)}
            </li>
          `).join('');
          matchedRulesHtml = `<ul class="space-y-1">${matchedRulesHtml}</ul>`;
        }
      }

      const recipient = t.recipient || 'nithin@acme-corp.com';

      return `
        <tr class="threat-row hover:bg-zinc-50/80 dark:hover:bg-zinc-800/40 transition-colors" data-id="${escapeHtml(t.id)}">
          
          <!-- Time & Recipient -->
          <td class="py-3 px-4 align-top whitespace-nowrap">
            <div class="font-medium text-zinc-900 dark:text-white">${escapeHtml(formatTimestamp(t.timestamp))}</div>
            <div class="inline-flex items-center gap-1 mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 font-mono">
              <i data-lucide="user" class="w-3 h-3 text-zinc-400"></i>
              ${escapeHtml(recipient)}
            </div>
          </td>

          <!-- Sender & Subject -->
          <td class="py-3 px-4 align-top max-w-xs md:max-w-sm">
            <div class="font-semibold text-zinc-900 dark:text-white truncate" title="${escapeHtml(t.subject)}">${escapeHtml(t.subject || 'No Subject')}</div>
            <div class="text-[11px] text-zinc-500 dark:text-zinc-400 truncate mt-0.5" title="${escapeHtml(t.sender)}">${escapeHtml(t.sender || 'Unknown Sender')}</div>
          </td>

          <!-- Classification Badge -->
          <td class="py-3 px-4 align-top whitespace-nowrap">
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border ${badgeClass}">
              <span class="w-1.5 h-1.5 rounded-full ${dotColor}"></span>
              ${escapeHtml(t.threat_type || 'Unclassified')}
            </span>
          </td>

          <!-- Composite Score -->
          <td class="py-3 px-4 align-top whitespace-nowrap">
            <div class="flex items-center gap-2">
              <div class="w-12 bg-zinc-200 dark:bg-zinc-700 rounded-full h-1.5 overflow-hidden">
                <div class="h-full rounded-full ${isHigh ? 'bg-red-500' : isModerate ? 'bg-amber-500' : 'bg-emerald-500'}" style="width: ${t.risk_score}%"></div>
              </div>
              <span class="font-mono font-bold ${isHigh ? 'text-red-600 dark:text-red-400' : isModerate ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}">
                ${t.risk_score}/100
              </span>
            </div>
          </td>

          <!-- Autonomous Action -->
          <td class="py-3 px-4 align-top whitespace-nowrap">
            ${actionPill}
          </td>

          <!-- Actions -->
          <td class="py-3 px-4 align-top text-right whitespace-nowrap space-x-1">
            ${isHigh ? `
              <button class="btn-restore px-2.5 py-1 rounded text-[11px] font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 border border-zinc-200 dark:border-zinc-700 transition-all" data-id="${escapeHtml(t.id)}" title="Restore email to employee inbox">
                Restore
              </button>
            ` : ''}
            <button class="btn-purge p-1.5 rounded text-zinc-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-all" data-id="${escapeHtml(t.id)}" title="Purge threat record">
              <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
            </button>
            <button class="btn-toggle-drawer p-1.5 rounded text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-all" data-id="${escapeHtml(t.id)}" title="Toggle Heuristic Breakdown">
              <i data-lucide="${isExpanded ? 'chevron-up' : 'chevron-down'}" class="w-3.5 h-3.5"></i>
            </button>
          </td>

        </tr>

        <!-- Accordion Drawer (Expanded View) -->
        <tr class="bg-zinc-50/50 dark:bg-zinc-900/50 ${isExpanded ? '' : 'hidden'}" id="drawer-${escapeHtml(t.id)}">
          <td colspan="6" class="p-4 border-b border-zinc-200 dark:border-zinc-800 text-xs">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 bg-white dark:bg-zinc-800/80 p-4 rounded-lg border border-zinc-200 dark:border-zinc-700 shadow-inner">
              
              <!-- Left Column: Explanation & Metadata -->
              <div class="space-y-3">
                <div>
                  <span class="font-semibold text-zinc-900 dark:text-white uppercase tracking-wider text-[10px] text-zinc-500">Plain-English SME Guidance</span>
                  <p class="text-zinc-800 dark:text-zinc-200 mt-1 leading-relaxed">${escapeHtml(t.explanation || 'No detailed analysis provided.')}</p>
                </div>
                <div>
                  <span class="font-semibold text-zinc-900 dark:text-white uppercase tracking-wider text-[10px] text-zinc-500">Payload Preview / Snippet</span>
                  <p class="text-zinc-600 dark:text-zinc-400 font-mono text-[11px] bg-zinc-50 dark:bg-zinc-900 p-2.5 rounded border border-zinc-200 dark:border-zinc-800 mt-1 break-words">
                    ${escapeHtml(t.snippet || 'No snippet text available.')}
                  </p>
                </div>
              </div>

              <!-- Right Column: Triggered Heuristic Rules -->
              <div>
                <span class="font-semibold text-zinc-900 dark:text-white uppercase tracking-wider text-[10px] text-zinc-500">Triggered Security Vector Signals</span>
                <div class="mt-1.5 p-3 rounded bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800">
                  ${matchedRulesHtml}
                </div>
                <div class="mt-3 flex items-center justify-between text-[11px] text-zinc-500 dark:text-zinc-400">
                  <span>Deterministic ID: <code class="font-mono text-zinc-700 dark:text-zinc-300">${escapeHtml(t.id)}</code></span>
                  <span>Verdict Engine: <strong>Heuristic v0.1.0</strong></span>
                </div>
              </div>

            </div>
          </td>
        </tr>
      `;
    }).join('');

    if (window.lucide) {
      window.lucide.createIcons();
    }
  }

  // Export
  window.MailFlowDashboard = {
    state,
    applyTheme,
    toggleTheme,
    updateKPIMetrics,
    renderThreatTable,
    fetchLiveThreats,
    seedDemoThreats,
    showToast,
    exportThreatLog,
    restoreThreat,
    purgeThreat,
    toggleThreatDrawer,
  };

  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(state.theme);
    initPolicies();
    
    // Auto-seed initially
    seedDemoThreats();
    
    fetchLiveThreats();

    // Event Listeners
    if (DOM.themeToggleBtn) DOM.themeToggleBtn.addEventListener('click', toggleTheme);
    if (DOM.manualRefreshBtn) DOM.manualRefreshBtn.addEventListener('click', fetchLiveThreats);
    if (DOM.seedThreatsBtn) DOM.seedThreatsBtn.addEventListener('click', seedDemoThreats);
    if (DOM.exportLogBtn) DOM.exportLogBtn.addEventListener('click', exportThreatLog);
    if (DOM.searchInput) DOM.searchInput.addEventListener('input', handleSearchInput);

    DOM.filterTabs.forEach(tab => {
      tab.addEventListener('click', handleFilterClick);
    });

    // Delegated click listeners for table rows
    if (DOM.tableBody) {
      DOM.tableBody.addEventListener('click', (e) => {
        const restoreBtn = e.target.closest('.btn-restore');
        if (restoreBtn) {
          e.stopPropagation();
          restoreThreat(restoreBtn.dataset.id);
          return;
        }

        const purgeBtn = e.target.closest('.btn-purge');
        if (purgeBtn) {
          e.stopPropagation();
          purgeThreat(purgeBtn.dataset.id);
          return;
        }

        const drawerBtn = e.target.closest('.btn-toggle-drawer');
        if (drawerBtn) {
          e.stopPropagation();
          toggleThreatDrawer(drawerBtn.dataset.id);
          return;
        }

        const row = e.target.closest('.threat-row');
        if (row && row.dataset.id) {
          toggleThreatDrawer(row.dataset.id);
        }
      });
    }

    // Start background polling loop
    setInterval(fetchLiveThreats, POLLING_INTERVAL_MS);
  });

})();
