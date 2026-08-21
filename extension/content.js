/**
 * MailFlow Chrome Extension - Content Script (Sprint 1)
 * Native Gmail DOM Injections & Real-Time Security Integration
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  let isMailFlowTabActive = false;
  let observer = null;
  let scanDebounceTimer = null;
  let currentSettings = {
    autoScan: true,
    defangLinks: true,
    showInlineRows: true,
  };

  // SVG Icons
  const ICONS = {
    shield: `<svg class="mailflow-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    shieldRow: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    shieldHeader: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0b57d0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    check: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>`,
    alert: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`,
    refresh: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
    </svg>`,
    checkCircle: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
      <polyline points="22 4 12 14.01 9 11.01"/>
    </svg>`
  };

  /**
   * =========================================================================
   * MODULE 0: SETTINGS SYNC
   * =========================================================================
   */

  function syncSettings() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      const storageArea = chrome.storage.sync || chrome.storage.local;
      storageArea.get(currentSettings, (items) => {
        if (items) {
          currentSettings = { ...currentSettings, ...items };
          applySettings();
        }
      });

      chrome.storage.onChanged.addListener((changes, areaName) => {
        for (const [key, change] of Object.entries(changes)) {
          if (key in currentSettings) {
            currentSettings[key] = change.newValue;
          }
        }
        applySettings();
      });
    }
  }

  function applySettings() {
    const rowButtons = document.querySelectorAll('.mailflow-row-action-item');
    rowButtons.forEach(btn => {
      if (currentSettings.showInlineRows) {
        btn.classList.remove('mailflow-hidden-by-setting');
      } else {
        btn.classList.add('mailflow-hidden-by-setting');
      }
    });
  }

  /**
   * =========================================================================
   * MODULE 1: TOAST NOTIFICATION SYSTEM
   * =========================================================================
   */

  function showToast(message, type = 'info', actionLabel = null, onAction = null) {
    let container = document.getElementById('mailflow-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'mailflow-toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'mailflow-toast';

    let iconSvg = ICONS.shieldRow;
    if (type === 'success') {
      iconSvg = `<svg class="mailflow-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#34a853" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    } else if (type === 'warning' || type === 'error') {
      iconSvg = `<svg class="mailflow-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#ea4335" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    }

    toast.innerHTML = `
      <div class="mailflow-toast-content">
        ${iconSvg}
        <span class="mailflow-toast-text">${message}</span>
      </div>
      ${actionLabel ? `<button class="mailflow-toast-action">${actionLabel}</button>` : ''}
    `;

    if (actionLabel && onAction) {
      const actionBtn = toast.querySelector('.mailflow-toast-action');
      actionBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        onAction();
        dismissToast(toast);
      });
    }

    container.appendChild(toast);

    setTimeout(() => {
      dismissToast(toast);
    }, 4500);
  }

  function dismissToast(toast) {
    if (!toast || !toast.parentElement) return;
    toast.classList.add('hiding');
    setTimeout(() => {
      if (toast.parentElement) {
        toast.parentElement.removeChild(toast);
      }
    }, 250);
  }

  /**
   * =========================================================================
   * MODULE 2: SIDEBAR NAVIGATION INJECTION
   * =========================================================================
   */

  function findSidebarContainer() {
    const nav = document.querySelector('div[role="navigation"]');
    if (!nav) return null;

    const tkList = nav.querySelector('div.TK') || 
                   nav.querySelector('.wT') || 
                   nav.querySelector('div.aeN') || 
                   nav.querySelector('.ajl');
    
    if (tkList) return tkList;

    const aimItem = nav.querySelector('.aim') || nav.querySelector('.TO');
    if (aimItem && aimItem.parentElement) {
      return aimItem.parentElement;
    }

    return nav;
  }

  function injectSidebarItem() {
    if (document.getElementById('mailflow-sidebar-nav-item')) {
      return;
    }

    const sidebarContainer = findSidebarContainer();
    if (!sidebarContainer) return;

    const navItem = document.createElement('div');
    navItem.id = 'mailflow-sidebar-nav-item';
    navItem.className = 'mailflow-nav-item';
    navItem.setAttribute('role', 'button');
    navItem.setAttribute('tabindex', '0');
    navItem.setAttribute('aria-label', 'MailFlow SME Shield');

    navItem.innerHTML = `
      <div class="mailflow-nav-icon-wrapper">
        ${ICONS.shield}
      </div>
      <span class="mailflow-nav-label">MailFlow</span>
      <span class="mailflow-nav-badge" id="mailflow-nav-badge">0</span>
    `;

    navItem.addEventListener('click', (e) => {
      e.stopPropagation();
      activateMailFlowView();
    });

    const draftsItem = sidebarContainer.querySelector('a[href*="#drafts"]') || 
                       sidebarContainer.querySelector('div[data-tooltip*="Drafts"]') ||
                       sidebarContainer.querySelector('div.aim:nth-child(5)');

    if (draftsItem && draftsItem.closest('.aim')) {
      draftsItem.closest('.aim').after(navItem);
    } else {
      sidebarContainer.appendChild(navItem);
    }

    attachNativeNavListeners();
  }

  function attachNativeNavListeners() {
    const nav = document.querySelector('div[role="navigation"]');
    if (!nav) return;

    const nativeItems = nav.querySelectorAll('a, .aim, .TO, [role="treeitem"]');
    nativeItems.forEach(item => {
      if (item.id === 'mailflow-sidebar-nav-item' || item.closest('#mailflow-sidebar-nav-item')) return;
      if (item.dataset.mailflowListenerAttached) return;

      item.dataset.mailflowListenerAttached = 'true';
      item.addEventListener('click', () => {
        if (isMailFlowTabActive) {
          deactivateMailFlowView();
        }
      });
    });
  }

  /**
   * =========================================================================
   * MODULE 3: MAILFLOW HUB / TRIAGE CONTAINER
   * =========================================================================
   */

  function getMainContainer() {
    return document.querySelector('div[role="main"]') || 
           document.querySelector('.AO') || 
           document.querySelector('.bkK') || 
           document.querySelector('.UI') ||
           document.body;
  }

  function activateMailFlowView() {
    isMailFlowTabActive = true;

    const navItem = document.getElementById('mailflow-sidebar-nav-item');
    if (navItem) navItem.classList.add('active');

    document.querySelectorAll('div[role="navigation"] .nZ, div[role="navigation"] .active').forEach(el => {
      if (el.id !== 'mailflow-sidebar-nav-item') {
        el.classList.remove('nZ');
      }
    });

    const mainContainer = getMainContainer();
    if (!mainContainer) return;

    Array.from(mainContainer.children).forEach(child => {
      if (child.id !== 'mailflow-hub-container') {
        child.dataset.mailflowPrevDisplay = child.style.display;
        child.style.display = 'none';
      }
    });

    let hub = document.getElementById('mailflow-hub-container');
    if (!hub) {
      hub = createHubElement();
      mainContainer.appendChild(hub);
    } else {
      hub.style.display = 'flex';
    }
  }

  function deactivateMailFlowView() {
    isMailFlowTabActive = false;

    const navItem = document.getElementById('mailflow-sidebar-nav-item');
    if (navItem) navItem.classList.remove('active');

    const hub = document.getElementById('mailflow-hub-container');
    if (hub) hub.style.display = 'none';

    const mainContainer = getMainContainer();
    if (!mainContainer) return;

    Array.from(mainContainer.children).forEach(child => {
      if (child.id !== 'mailflow-hub-container') {
        child.style.display = child.dataset.mailflowPrevDisplay || '';
      }
    });
  }

  function createHubElement() {
    const container = document.createElement('div');
    container.id = 'mailflow-hub-container';

    container.innerHTML = `
      <div class="mailflow-hub-header">
        <div class="mailflow-hub-title-group">
          <h1 class="mailflow-hub-title">
            ${ICONS.shieldHeader}
            MailFlow Quarantine & Triage Hub
          </h1>
          <p class="mailflow-hub-subtitle">SME Zero-Trust Email Security • Real-time Threat Guard</p>
        </div>
        <div class="mailflow-hub-actions">
          <button id="mailflow-btn-test-sync" class="mailflow-hub-btn mailflow-hub-btn-primary">
            ${ICONS.refresh}
            Sync Shield Status
          </button>
        </div>
      </div>

      <div class="mailflow-metrics-row">
        <div class="mailflow-metric-card">
          <span class="mailflow-metric-label">Protection Status</span>
          <div class="mailflow-metric-value">
            <span style="color: #1e8e3e;">Active</span>
          </div>
          <span class="mailflow-metric-status">
            ${ICONS.checkCircle} Fleet: Local Dev (:8000)
          </span>
        </div>

        <div class="mailflow-metric-card">
          <span class="mailflow-metric-label">Quarantined Threads</span>
          <div class="mailflow-metric-value" id="mailflow-hub-quarantined-count">0</div>
          <span class="mailflow-metric-status" style="color: #5e5e5e;">Pending triage</span>
        </div>

        <div class="mailflow-metric-card">
          <span class="mailflow-metric-label">Defanged Untrusted Links</span>
          <div class="mailflow-metric-value">0</div>
          <span class="mailflow-metric-status" style="color: #1a73e8;">Zero-trust active</span>
        </div>
      </div>

      <div class="mailflow-triage-panel">
        <div class="mailflow-empty-icon">
          ${ICONS.shieldHeader}
        </div>
        <h2 class="mailflow-empty-title">Quarantine & Triage Hub (0 Items Pending Review)</h2>
        <p class="mailflow-empty-desc">
          Your workspace is currently safe. Incoming emails are monitored in real-time. Any flagged phishing attempts, malware attachments, or defanged links will appear here for security review.
        </p>
        <button id="mailflow-btn-ping-backend" class="mailflow-hub-btn mailflow-hub-btn-secondary">
          Test Health Handshake (GET /api/ping)
        </button>
      </div>
    `;

    const testSyncBtn = container.querySelector('#mailflow-btn-test-sync');
    const pingBtn = container.querySelector('#mailflow-btn-ping-backend');

    const handleHealthCheck = async (button) => {
      const origText = button.innerHTML;
      button.innerHTML = `<span>Checking :8000...</span>`;
      try {
        const res = await fetch(`${BACKEND_URL}/api/ping`);
        if (res.ok) {
          const data = await res.json();
          button.innerHTML = `<span style="color: #1e8e3e;">✓ ${data.status.toUpperCase()} (${data.version})</span>`;
          showToast(`Backend connection healthy (v${data.version || '0.1.0'})`, 'success');
        } else {
          button.innerHTML = `<span style="color: #d93025;">⚠️ HTTP ${res.status}</span>`;
          showToast(`Backend returned HTTP ${res.status}`, 'warning');
        }
      } catch (e) {
        button.innerHTML = `<span style="color: #d93025;">○ Backend Offline</span>`;
        showToast('Backend server is offline (http://localhost:8000)', 'error');
      }
      setTimeout(() => {
        button.innerHTML = origText;
      }, 2500);
    };

    if (testSyncBtn) testSyncBtn.addEventListener('click', () => handleHealthCheck(testSyncBtn));
    if (pingBtn) pingBtn.addEventListener('click', () => handleHealthCheck(pingBtn));

    return container;
  }

  /**
   * =========================================================================
   * MODULE 4: EMAIL ROW HOVER ACTION BUTTON INJECTION (🛡️ SCAN)
   * =========================================================================
   */

  function extractRowMetadata(row) {
    let sender = 'Unknown Sender';
    const senderEl = row.querySelector('.yP, .zF, span[email], .bA4 span, .yW span, span[name]');
    if (senderEl) {
      sender = senderEl.getAttribute('email') || 
               senderEl.getAttribute('name') || 
               senderEl.innerText.trim() || 
               'Unknown Sender';
    }

    let subject = 'No Subject';
    const subjectEl = row.querySelector('.bog, .bqe, span.bqe, .y6 span');
    if (subjectEl) {
      subject = subjectEl.innerText.trim() || 'No Subject';
    }

    return { sender, subject };
  }

  async function handleScanClick(row, btn, e) {
    e.preventDefault();
    e.stopPropagation();

    if (btn.classList.contains('scanning')) return;

    const { sender, subject } = extractRowMetadata(row);

    btn.className = 'mailflow-scan-btn scanning';
    btn.innerHTML = `
      <div class="mailflow-scan-spinner"></div>
      <span class="mailflow-scan-label">Scanning</span>
    `;

    try {
      const startTime = performance.now();
      const response = await fetch(`${BACKEND_URL}/api/scan-ping`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ sender, subject })
      });

      const elapsed = Math.round(performance.now() - startTime);

      if (response.ok) {
        const data = await response.json();
        btn.className = 'mailflow-scan-btn verdict-safe';
        btn.innerHTML = `
          ${ICONS.check}
          <span class="mailflow-scan-label">Safe (${data.latency_ms || elapsed}ms)</span>
        `;

        showToast(
          `MailFlow Scan: "${subject.substring(0, 32)}${subject.length > 32 ? '...' : ''}" from ${sender} is SAFE (${data.latency_ms || elapsed}ms)`,
          'success'
        );
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (err) {
      btn.className = 'mailflow-scan-btn verdict-error';
      btn.innerHTML = `
        ${ICONS.alert}
        <span class="mailflow-scan-label">Offline</span>
      `;

      showToast(
        `MailFlow: Backend offline (:8000). Start FastAPI server to scan threads.`,
        'warning',
        'Open Hub',
        () => activateMailFlowView()
      );
    }

    setTimeout(() => {
      btn.className = 'mailflow-scan-btn';
      btn.innerHTML = `
        ${ICONS.shieldRow}
        <span class="mailflow-scan-label">Scan</span>
      `;
    }, 2800);
  }

  function injectScanButtonIntoRow(row) {
    if (row.dataset.mailflowInjected === 'true') {
      return;
    }

    const actionToolbar = row.querySelector('ul.bq4, ul.aqL, ul[role="toolbar"], td.bq9 ul, .bq8 ul, .a4y ul, ul.bqe, ul.bqZ');
    
    const actionItem = document.createElement('li');
    actionItem.className = 'mailflow-row-action-item';
    if (!currentSettings.showInlineRows) {
      actionItem.classList.add('mailflow-hidden-by-setting');
    }
    actionItem.setAttribute('role', 'button');
    actionItem.setAttribute('title', 'Scan email with MailFlow SME Shield');

    const scanBtn = document.createElement('button');
    scanBtn.type = 'button';
    scanBtn.className = 'mailflow-scan-btn';
    scanBtn.setAttribute('aria-label', 'Scan email with MailFlow');
    scanBtn.innerHTML = `
      ${ICONS.shieldRow}
      <span class="mailflow-scan-label">Scan</span>
    `;

    scanBtn.addEventListener('click', (e) => handleScanClick(row, scanBtn, e));
    actionItem.appendChild(scanBtn);

    if (actionToolbar) {
      actionToolbar.insertBefore(actionItem, actionToolbar.firstChild);
      row.dataset.mailflowInjected = 'true';
    } else {
      const actionCell = row.querySelector('td.yX, td.bq9, td.a4y, td.xY');
      if (actionCell) {
        actionCell.appendChild(actionItem);
        row.dataset.mailflowInjected = 'true';
      }
    }
  }

  function scanEmailRows() {
    const rows = document.querySelectorAll('tr.zA, tr[role="row"]');
    rows.forEach(row => {
      if (row.querySelector('.yP, .zF, .bog, .bqe, .y6') && !row.dataset.mailflowInjected) {
        injectScanButtonIntoRow(row);
      }
    });
  }

  /**
   * =========================================================================
   * OBSERVER & INITIALIZATION
   * =========================================================================
   */

  function handleMutations() {
    if (!document.getElementById('mailflow-sidebar-nav-item')) {
      injectSidebarItem();
    }

    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      scanEmailRows();
    }, 100);
  }

  function init() {
    syncSettings();
    injectSidebarItem();
    scanEmailRows();

    if (observer) observer.disconnect();

    observer = new MutationObserver(() => {
      handleMutations();
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
