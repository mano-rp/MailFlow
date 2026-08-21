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

  // Export functions to window namespace for modular lifecycle
  window.MailFlowDashboard = {
    state,
    applyTheme,
    toggleTheme,
    updateKPIMetrics,
  };

  // Initial event bindings
  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(state.theme);
    updateKPIMetrics();
    if (DOM.themeToggleBtn) {
      DOM.themeToggleBtn.addEventListener('click', toggleTheme);
    }
  });

})();
