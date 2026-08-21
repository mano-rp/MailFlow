/**
 * MailFlow SME Admin Dashboard — Fleet Command Engine
 * Real-time heuristic event consumer, multi-user inbox partitioner, and triage hub.
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  const POLLING_INTERVAL_MS = 2500;
  const CAPITAL_PER_HIGH_RISK_USD = 15000;
  const PRIMARY_EXTENSION_USER = 'nithin@acme-corp.com';

  // Demo Authentication Constants
  const AUTH_CONFIG = {
    EMAIL: 'admin@mailflow',
    PASSWORD: '1234',
    STORAGE_KEY: 'mailflow_auth',
  };

  // State Management
  const state = {
    isAuthenticated: sessionStorage.getItem(AUTH_CONFIG.STORAGE_KEY) === 'true',
    threats: [],
    activeFilter: 'all',
    activeUserFilter: 'all',
    searchQuery: '',
    expandedThreatIds: new Set(),
    isBackendOnline: false,
    theme: localStorage.getItem('mailflow_dashboard_theme') || 'light',
    policies: JSON.parse(localStorage.getItem('mailflow_dashboard_policies') || '{"bank-rules":true,"homoglyph-lock":true,"quishing-rules":true}'),
  };

  // DOM Elements Cache
  const DOM = {
    html: document.documentElement,
    authView: document.getElementById('auth-view'),
    dashboardView: document.getElementById('dashboard-view'),
    authForm: document.getElementById('auth-form'),
    authEmail: document.getElementById('auth-email'),
    authPassword: document.getElementById('auth-password'),
    authError: document.getElementById('auth-error'),
    authErrorText: document.getElementById('auth-error-text'),
    btnDemoAutologin: document.getElementById('btn-demo-autologin'),
    btnAuthThemeToggle: document.getElementById('btn-auth-theme-toggle'),
    authThemeIcon: document.getElementById('auth-theme-icon'),
    btnLogout: document.getElementById('btn-logout'),
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
    userFilterSelect: document.getElementById('user-filter-select'),
    countAll: document.getElementById('count-all'),
    countHigh: document.getElementById('count-high'),
    countModerate: document.getElementById('count-moderate'),
    countLow: document.getElementById('count-low'),
    searchInput: document.getElementById('threat-search-input'),
    seedThreatsBtn: document.getElementById('btn-seed-threats'),
    clearThreatsBtn: document.getElementById('btn-clear-threats'),
    exportLogBtn: document.getElementById('btn-export-log'),
    tableBody: document.getElementById('threat-table-body'),
    emptyState: document.getElementById('table-empty-state'),
    toastContainer: document.getElementById('toast-container'),
    policyToggles: document.querySelectorAll('.policy-toggle'),
  };

  let pollingTimer = null;

  /**
   * --------------------------------------------------------------------------
   * AUTHENTICATION & SESSION GATE
   * --------------------------------------------------------------------------
   */
  function checkAuthState() {
    state.isAuthenticated = sessionStorage.getItem(AUTH_CONFIG.STORAGE_KEY) === 'true';

    if (state.isAuthenticated) {
      // Show Dashboard View
      if (DOM.authView) DOM.authView.classList.add('hidden');
      if (DOM.dashboardView) {
        DOM.dashboardView.classList.remove('hidden');
        DOM.dashboardView.classList.add('flex');
      }

      updateKPIMetrics();
      renderThreatTable();
      fetchLiveThreats();

      // Start Polling Loop
      if (!pollingTimer) {
        pollingTimer = setInterval(fetchLiveThreats, POLLING_INTERVAL_MS);
      }
    } else {
      // Show Auth Gate View
      if (DOM.authView) DOM.authView.classList.remove('hidden');
      if (DOM.dashboardView) {
        DOM.dashboardView.classList.add('hidden');
        DOM.dashboardView.classList.remove('flex');
      }

      if (pollingTimer) {
        clearInterval(pollingTimer);
        pollingTimer = null;
      }
    }

    if (window.lucide) window.lucide.createIcons();
  }

  function handleAuthSubmit(e) {
    if (e) e.preventDefault();

    const email = (DOM.authEmail?.value || '').trim();
    const password = (DOM.authPassword?.value || '').trim();

    if (email === AUTH_CONFIG.EMAIL && password === AUTH_CONFIG.PASSWORD) {
      if (DOM.authError) DOM.authError.classList.add('hidden');
      sessionStorage.setItem(AUTH_CONFIG.STORAGE_KEY, 'true');
      checkAuthState();
      showToast('Authenticated as SME Fleet Administrator', 'success');
    } else {
      if (DOM.authError) {
        DOM.authError.classList.remove('hidden');
        if (DOM.authErrorText) {
          DOM.authErrorText.textContent = 'Invalid credentials. Hint: admin@mailflow / 1234';
        }
      }
      const card = DOM.authView?.querySelector('div');
      if (card) {
        card.classList.remove('auth-shake');
        void card.offsetWidth; // Trigger reflow
        card.classList.add('auth-shake');
      }
      if (DOM.authPassword) {
        DOM.authPassword.value = '';
        DOM.authPassword.focus();
      }
    }
  }

  function handleDemoAutoLogin() {
    if (DOM.authEmail) DOM.authEmail.value = AUTH_CONFIG.EMAIL;
    if (DOM.authPassword) DOM.authPassword.value = AUTH_CONFIG.PASSWORD;
    handleAuthSubmit();
  }

  function handleLogout() {
    sessionStorage.removeItem(AUTH_CONFIG.STORAGE_KEY);
    state.isAuthenticated = false;
    if (DOM.authPassword) DOM.authPassword.value = '';
    if (DOM.authError) DOM.authError.classList.add('hidden');
    checkAuthState();
    showToast('Signed out of Command Center', 'info');
  }

  /**
   * --------------------------------------------------------------------------
   * THEME MANAGEMENT
   * --------------------------------------------------------------------------
   */
  function applyTheme(theme) {
    state.theme = theme;
    localStorage.setItem('mailflow_dashboard_theme', theme);

    if (theme === 'dark') {
      DOM.html.classList.add('dark');
      DOM.html.classList.remove('light');
      if (DOM.themeIcon) DOM.themeIcon.setAttribute('data-lucide', 'sun');
      if (DOM.authThemeIcon) DOM.authThemeIcon.setAttribute('data-lucide', 'sun');
    } else {
      DOM.html.classList.remove('dark');
      DOM.html.classList.add('light');
      if (DOM.themeIcon) DOM.themeIcon.setAttribute('data-lucide', 'moon');
      if (DOM.authThemeIcon) DOM.authThemeIcon.setAttribute('data-lucide', 'moon');
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
    toast.className = 'dashboard-toast flex items-center gap-2.5 px-3.5 py-2.5 rounded-md shadow-md text-xs font-medium border backdrop-blur-md transition-all';

    if (type === 'success') {
      toast.className += ' bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 border-zinc-200 dark:border-zinc-700';
      toast.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-500 flex-shrink-0"></span><span>${escapeHtml(message)}</span>`;
    } else if (type === 'error' || type === 'alert') {
      toast.className += ' bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 border-zinc-200 dark:border-zinc-700';
      toast.innerHTML = `<span class="w-2 h-2 rounded-full bg-red-500 flex-shrink-0"></span><span>${escapeHtml(message)}</span>`;
    } else if (type === 'warning') {
      toast.className += ' bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 border-zinc-200 dark:border-zinc-700';
      toast.innerHTML = `<span class="w-2 h-2 rounded-full bg-amber-500 flex-shrink-0"></span><span>${escapeHtml(message)}</span>`;
    } else {
      toast.className += ' bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 border-zinc-200 dark:border-zinc-700';
      toast.innerHTML = `<span class="w-2 h-2 rounded-full bg-zinc-400 flex-shrink-0"></span><span>${escapeHtml(message)}</span>`;
    }

    DOM.toastContainer.appendChild(toast);
    if (window.lucide) window.lucide.createIcons();

    setTimeout(() => {
      toast.classList.add('hiding');
      setTimeout(() => toast.remove(), 200);
    }, 3500);
  }

  /**
   * --------------------------------------------------------------------------
   * DEMO DATA SEEDER (MANUAL INGEST ONLY)
   * --------------------------------------------------------------------------
   */
  const DEMO_SEEDS = [
    {
      id: 'mf_sec_bec01',
      isLive: false,
      timestamp: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
      sender: 'Sharma Logistics <billing@sharma-invoices.com>',
      recipient: 'sarah.cfo@acme-corp.com',
      department: 'Finance & Operations',
      subject: 'Re: INV-2291 final notice - updated bank details, action required',
      snippet: 'Dear Sir/Madam, This is the final notice regarding the pending settlement of Rs. 9,85000 against INV-2291. Our earlier current account is temporarily frozen pending an audit, so kindly remit funds to our new IBAN immediately.',
      risk_score: 100,
      tier: 'high',
      color: 'red',
      threat_type: 'Urgent Financial / BEC Fraud',
      action: 'quarantine_slide',
      explanation: 'High-risk threat detected (Score 100/100). Flagged for: Bank Account Redirection / IBAN Tampering; Deceptive Audit Migration Pretext; Coercive Final Notice Warning.',
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
      id: 'mf_sec_ceo02',
      isLive: false,
      timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
      sender: 'Alex Vance (CEO) <ceo@acme-corp.co>',
      recipient: 'alex.dev@acme-corp.com',
      department: 'Engineering & Infrastructure',
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
            "Executive Impersonation / Availability Bait (matched: 'are you at your desk')"
          ]
        }
      ]
    },
    {
      id: 'mf_sec_mod03',
      isLive: false,
      timestamp: new Date(Date.now() - 50 * 60 * 1000).toISOString(),
      sender: 'CloudScale Billing <accounts@cloudscale.io>',
      recipient: 'sarah.cfo@acme-corp.com',
      department: 'Finance & Operations',
      subject: 'Invoice Statement & Updated Banking Terms',
      snippet: 'Please review the updated routing details and quarterly cloud statement.',
      risk_score: 70,
      tier: 'moderate',
      color: 'yellow',
      threat_type: 'Unverified Bank Account Update',
      action: 'flag_warning',
      explanation: 'Moderate caution advised (Score 70/100). Contains banking modification references.',
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

    updateKPIMetrics();
    renderThreatTable();
    showToast(`Added ${newCount || DEMO_SEEDS.length} audited feed entries`, 'success');
  }

  function clearThreats() {
    state.threats = [];
    state.expandedThreatIds.clear();
    updateKPIMetrics();
    renderThreatTable();
    showToast('Threat ledger cleared', 'info');
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
          DOM.backendStatusDot.className = 'w-2 h-2 rounded-full bg-emerald-500 shadow-sm';
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
    if (!state.isAuthenticated) return;

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
          // Tag incoming scans as primary extension workstation items
          const formatted = {
            ...inc,
            isLive: true,
            recipient: inc.recipient || PRIMARY_EXTENSION_USER,
            department: 'Active Extension Workstation'
          };

          const existingIdx = state.threats.findIndex(t => t.id === inc.id);
          if (existingIdx === -1) {
            // New incoming real scan -> insert at top
            state.threats.unshift(formatted);
            stateChanged = true;
          } else {
            // Update existing if state changed
            state.threats[existingIdx] = { ...state.threats[existingIdx], ...formatted };
          }
        });

        if (stateChanged) {
          updateKPIMetrics();
          renderThreatTable();
        }
      }
    } catch (err) {
      console.warn('[MailFlow Dashboard] Polling error:', err);
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
    showToast(`Restored to ${threat.recipient} inbox`, 'success');
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
      showToast('Threat record purged', 'info');
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
      t.classList.remove('active', 'text-zinc-900', 'dark:text-white', 'bg-white', 'dark:bg-zinc-700');
      t.classList.add('text-zinc-500', 'dark:text-zinc-400');
    });

    btn.classList.add('active', 'text-zinc-900', 'dark:text-white', 'bg-white', 'dark:bg-zinc-700');
    btn.classList.remove('text-zinc-500', 'dark:text-zinc-400');

    state.activeFilter = btn.dataset.filter || 'all';
    renderThreatTable();
  }

  function handleUserFilterChange(e) {
    state.activeUserFilter = e.target.value;
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
   * TABLE RENDERING WITH USER SEPARATION & SUBTLE MONOCHROME STYLING
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
      // Filter by user selection
      if (state.activeUserFilter !== 'all' && t.recipient !== state.activeUserFilter) {
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

    // Separate into real live extension items vs secondary accounts
    const liveItems = filtered.filter(t => t.isLive !== false);
    const secondaryItems = filtered.filter(t => t.isLive === false);

    // Build grouped row HTML
    let tableHtml = '';

    if (liveItems.length > 0) {
      tableHtml += `
        <tr class="bg-zinc-100/70 dark:bg-zinc-800/60 text-zinc-700 dark:text-zinc-300 font-semibold text-[11px]">
          <td colspan="6" class="py-2 px-4">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span>Active Extension Workstation (${PRIMARY_EXTENSION_USER})</span>
              <span class="text-[10px] font-normal text-zinc-400">— Live Ingestion Feed</span>
            </div>
          </td>
        </tr>
      `;
      tableHtml += liveItems.map(renderThreatRow).join('');
    }

    if (secondaryItems.length > 0) {
      tableHtml += `
        <tr class="bg-zinc-100/70 dark:bg-zinc-800/60 text-zinc-700 dark:text-zinc-300 font-semibold text-[11px]">
          <td colspan="6" class="py-2 px-4">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-zinc-400"></span>
              <span>Audited Organization Endpoints</span>
              <span class="text-[10px] font-normal text-zinc-400">— Secondary Fleet Feeds</span>
            </div>
          </td>
        </tr>
      `;
      tableHtml += secondaryItems.map(renderThreatRow).join('');
    }

    DOM.tableBody.innerHTML = tableHtml;

    if (window.lucide) {
      window.lucide.createIcons();
    }
  }

  function renderThreatRow(t) {
    const isExpanded = state.expandedThreatIds.has(t.id);
    const isHigh = t.tier === 'high';
    const isModerate = t.tier === 'moderate';

    // Subtle Monochrome Dot Indicators
    let dotColor = 'bg-zinc-400';
    let statusText = '<span class="text-zinc-600 dark:text-zinc-400 font-medium">Clean</span>';

    if (isHigh) {
      dotColor = 'bg-red-500';
      statusText = '<span class="text-red-600 dark:text-red-400 font-medium">Quarantined</span>';
    } else if (isModerate) {
      dotColor = 'bg-amber-500';
      statusText = '<span class="text-amber-600 dark:text-amber-400 font-medium">Watchlist</span>';
    }

    // Matched Rules list
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
            <span class="w-1.5 h-1.5 rounded-full ${isHigh ? 'bg-red-500' : isModerate ? 'bg-amber-500' : 'bg-zinc-400'}"></span>
            ${escapeHtml(r)}
          </li>
        `).join('');
        matchedRulesHtml = `<ul class="space-y-1">${matchedRulesHtml}</ul>`;
      }
    }

    const recipient = t.recipient || PRIMARY_EXTENSION_USER;

    return `
      <tr class="threat-row hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition-colors" data-id="${escapeHtml(t.id)}">
        
        <!-- Employee & Timestamp -->
        <td class="py-2.5 px-4 align-top whitespace-nowrap">
          <div class="font-medium text-zinc-900 dark:text-white font-mono text-[11px]">${escapeHtml(recipient)}</div>
          <div class="text-[10.5px] text-zinc-400 mt-0.5">${escapeHtml(formatTimestamp(t.timestamp))}</div>
        </td>

        <!-- Sender & Subject -->
        <td class="py-2.5 px-4 align-top max-w-xs md:max-w-sm">
          <div class="font-medium text-zinc-900 dark:text-white truncate" title="${escapeHtml(t.subject)}">${escapeHtml(t.subject || 'No Subject')}</div>
          <div class="text-[11px] text-zinc-500 dark:text-zinc-400 truncate mt-0.5" title="${escapeHtml(t.sender)}">${escapeHtml(t.sender || 'Unknown Sender')}</div>
        </td>

        <!-- Classification Badge -->
        <td class="py-2.5 px-4 align-top whitespace-nowrap">
          <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200 border border-zinc-200 dark:border-zinc-700">
            <span class="w-1.5 h-1.5 rounded-full ${dotColor}"></span>
            ${escapeHtml(t.threat_type || 'Unclassified')}
          </span>
        </td>

        <!-- Score -->
        <td class="py-2.5 px-4 align-top whitespace-nowrap font-mono text-[11.5px]">
          <span class="${isHigh ? 'text-red-600 dark:text-red-400 font-bold' : isModerate ? 'text-amber-600 dark:text-amber-400 font-semibold' : 'text-zinc-500'}">
            ${t.risk_score}/100
          </span>
        </td>

        <!-- Status -->
        <td class="py-2.5 px-4 align-top whitespace-nowrap">
          ${statusText}
        </td>

        <!-- Actions -->
        <td class="py-2.5 px-4 align-top text-right whitespace-nowrap space-x-1">
          ${isHigh ? `
            <button class="btn-restore px-2 py-0.5 rounded text-[11px] font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 border border-zinc-200 dark:border-zinc-700 transition-all cursor-pointer" data-id="${escapeHtml(t.id)}" title="Restore to Inbox">
              Restore
            </button>
          ` : ''}
          <button class="btn-purge p-1 rounded text-zinc-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-all cursor-pointer" data-id="${escapeHtml(t.id)}" title="Purge Record">
            <i data-lucide="trash" class="w-3.5 h-3.5"></i>
          </button>
          <button class="btn-toggle-drawer p-1 rounded text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-all cursor-pointer" data-id="${escapeHtml(t.id)}" title="Toggle Heuristic Details">
            <i data-lucide="${isExpanded ? 'chevron-up' : 'chevron-down'}" class="w-3.5 h-3.5"></i>
          </button>
        </td>

      </tr>

      <!-- Accordion Drawer (Expanded View) -->
      <tr class="bg-zinc-50/60 dark:bg-zinc-900/60 ${isExpanded ? '' : 'hidden'}" id="drawer-${escapeHtml(t.id)}">
        <td colspan="6" class="p-3.5 border-b border-zinc-200 dark:border-zinc-800 text-xs">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5 bg-white dark:bg-zinc-800/90 p-3.5 rounded border border-zinc-200 dark:border-zinc-700 shadow-sm">
            
            <!-- Left Column: Explanation & Snippet -->
            <div class="space-y-2.5">
              <div>
                <span class="font-semibold text-zinc-400 uppercase tracking-wider text-[10px]">SME Analysis</span>
                <p class="text-zinc-800 dark:text-zinc-200 mt-0.5 leading-relaxed text-[11.5px]">${escapeHtml(t.explanation || 'No detailed analysis.')}</p>
              </div>
              <div>
                <span class="font-semibold text-zinc-400 uppercase tracking-wider text-[10px]">Email Snippet</span>
                <p class="text-zinc-600 dark:text-zinc-400 font-mono text-[11px] bg-zinc-50 dark:bg-zinc-900 p-2 rounded border border-zinc-200 dark:border-zinc-800 mt-0.5 break-words">
                  ${escapeHtml(t.snippet || 'No snippet text available.')}
                </p>
              </div>
            </div>

            <!-- Right Column: Triggered Heuristic Rules -->
            <div>
              <span class="font-semibold text-zinc-400 uppercase tracking-wider text-[10px]">Triggered Security Signals</span>
              <div class="mt-1 p-2.5 rounded bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 text-[11.5px]">
                ${matchedRulesHtml}
              </div>
              <div class="mt-2.5 flex items-center justify-between text-[10.5px] text-zinc-400 font-mono">
                <span>ID: ${escapeHtml(t.id)}</span>
                <span>Engine: Heuristic v0.1.0</span>
              </div>
            </div>

          </div>
        </td>
      </tr>
    `;
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
    clearThreats,
    showToast,
    exportThreatLog,
    restoreThreat,
    purgeThreat,
    toggleThreatDrawer,
    handleAuthSubmit,
    handleDemoAutoLogin,
    handleLogout,
  };

  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(state.theme);
    initPolicies();
    
    // Check initial auth gate
    checkAuthState();

    // Event Listeners
    if (DOM.authForm) DOM.authForm.addEventListener('submit', handleAuthSubmit);
    if (DOM.btnDemoAutologin) DOM.btnDemoAutologin.addEventListener('click', handleDemoAutoLogin);
    if (DOM.btnLogout) DOM.btnLogout.addEventListener('click', handleLogout);
    if (DOM.btnAuthThemeToggle) DOM.btnAuthThemeToggle.addEventListener('click', toggleTheme);
    if (DOM.themeToggleBtn) DOM.themeToggleBtn.addEventListener('click', toggleTheme);
    if (DOM.manualRefreshBtn) DOM.manualRefreshBtn.addEventListener('click', fetchLiveThreats);
    if (DOM.seedThreatsBtn) DOM.seedThreatsBtn.addEventListener('click', seedDemoThreats);
    if (DOM.clearThreatsBtn) DOM.clearThreatsBtn.addEventListener('click', clearThreats);
    if (DOM.exportLogBtn) DOM.exportLogBtn.addEventListener('click', exportThreatLog);
    if (DOM.searchInput) DOM.searchInput.addEventListener('input', handleSearchInput);
    if (DOM.userFilterSelect) DOM.userFilterSelect.addEventListener('change', handleUserFilterChange);

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
  });

})();
