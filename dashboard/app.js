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
    policies: JSON.parse(localStorage.getItem('mailflow_dashboard_policies') || '{}'),
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
  };

  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(state.theme);
    updateKPIMetrics();
    renderThreatTable();
    fetchLiveThreats();

    if (DOM.themeToggleBtn) {
      DOM.themeToggleBtn.addEventListener('click', toggleTheme);
    }
    if (DOM.manualRefreshBtn) {
      DOM.manualRefreshBtn.addEventListener('click', fetchLiveThreats);
    }

    // Start background polling loop
    setInterval(fetchLiveThreats, POLLING_INTERVAL_MS);
  });

})();
