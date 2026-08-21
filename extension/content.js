/**
 * MailFlow Chrome Extension - Content Script
 * Native Gmail DOM Injections & Real-Time Threat Evaluation Engine
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  let isBackendOnline = false;
  let isMailFlowTabActive = (window.location.hash === '#mailflow');
  let observer = null;
  let scanDebounceTimer = null;
  let heartbeatTimer = null;

  // In-memory threat stores
  const quarantinedThreats = new Map();
  const moderateThreats = new Map();

  let currentSettings = {
    showInlineRows: true,
    autoScan: true,
  };

  // SVG Icons
  const ICONS = {
    shield: `<svg class="mailflow-nav-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    shieldRow: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    shieldHeader: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#0b57d0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    refresh: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
    </svg>`,
    check: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#1e8e3e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>`,
    warning: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#d97706" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
      <line x1="12" y1="9" x2="12" y2="13"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>`,
    alert: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#dc2626" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="15" y1="9" x2="9" y2="15"/>
      <line x1="9" y1="9" x2="15" y2="15"/>
    </svg>`,
    restore: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="1 4 1 10 7 10"/>
      <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
    </svg>`
  };

  /**
   * =========================================================================
   * MODULE 0: BACKEND HEALTH & SETTINGS
   * =========================================================================
   */

  async function checkBackendHeartbeat() {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${BACKEND_URL}/api/ping`, { signal: controller.signal });
      clearTimeout(timeout);
      isBackendOnline = res.ok;
    } catch (e) {
      isBackendOnline = false;
    }
  }

  function syncSettings() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      const storageArea = chrome.storage.sync || chrome.storage.local;
      storageArea.get(currentSettings, (items) => {
        if (items) {
          currentSettings = { ...currentSettings, ...items };
          applySettings();
        }
      });

      chrome.storage.onChanged.addListener((changes) => {
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
    const rowItems = document.querySelectorAll('.mailflow-row-action-item');
    rowItems.forEach(item => {
      item.style.display = currentSettings.showInlineRows ? 'inline-flex' : 'none';
    });

    const sidebarWrapper = document.getElementById('mailflow-aim-wrapper');
    if (sidebarWrapper) {
      sidebarWrapper.style.display = currentSettings.autoScan ? 'block' : 'none';
    }
  }

  /**
   * =========================================================================
   * MODULE 1: SEARCH BAR HOOK & TOASTS
   * =========================================================================
   */

  function setSearchBarText(text) {
    const searchInput = document.querySelector('input[name="q"], input[aria-label*="Search"], form[role="search"] input');
    if (searchInput && searchInput.value !== text) {
      searchInput.value = text;
      searchInput.dispatchEvent(new Event('input', { bubbles: true }));
      searchInput.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  function clearSearchBarIfMailFlow() {
    const searchInput = document.querySelector('input[name="q"], input[aria-label*="Search"], form[role="search"] input');
    if (searchInput && (searchInput.value === 'in:MailFlow' || searchInput.value === 'in:mailflow')) {
      searchInput.value = '';
      searchInput.dispatchEvent(new Event('input', { bubbles: true }));
      searchInput.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

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
    } else if (type === 'warning') {
      iconSvg = `<svg class="mailflow-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else if (type === 'error' || type === 'alert') {
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
   * MODULE 2: SIDEBAR LABEL INJECTION
   * =========================================================================
   */

  function findSidebarTargetAnchor() {
    const nav = document.querySelector('div[role="navigation"]');
    if (!nav) return null;

    const spamEl = nav.querySelector('a[href*="#spam"], div[data-tooltip*="Spam"], a[title*="Spam"]');
    if (spamEl) {
      const aim = spamEl.closest('.aim') || spamEl.closest('.TO') || spamEl;
      return { container: aim.parentElement, anchor: aim };
    }

    const allMailEl = nav.querySelector('a[href*="#all"], div[data-tooltip*="All Mail"], a[title*="All Mail"]');
    if (allMailEl) {
      const aim = allMailEl.closest('.aim') || allMailEl.closest('.TO') || allMailEl;
      return { container: aim.parentElement, anchor: aim };
    }

    const draftsEl = nav.querySelector('a[href*="#drafts"], div[data-tooltip*="Drafts"], a[title*="Drafts"]');
    if (draftsEl) {
      const aim = draftsEl.closest('.aim') || draftsEl.closest('.TO') || draftsEl;
      return { container: aim.parentElement, anchor: aim };
    }

    const tkList = nav.querySelector('div.TK') || nav.querySelector('.wT') || nav.querySelector('.byl');
    if (tkList) {
      return { container: tkList, anchor: null };
    }

    return null;
  }

  function injectSidebarItem() {
    if (document.getElementById('mailflow-aim-wrapper')) {
      return;
    }

    const target = findSidebarTargetAnchor();
    if (!target || !target.container) return;

    const aimWrapper = document.createElement('div');
    aimWrapper.id = 'mailflow-aim-wrapper';
    aimWrapper.className = 'aim mailflow-aim-item';

    const navItem = document.createElement('div');
    navItem.id = 'mailflow-sidebar-nav-item';
    navItem.className = 'TO mailflow-nav-item' + (isMailFlowTabActive ? ' active' : '');
    navItem.setAttribute('role', 'button');
    navItem.setAttribute('tabindex', '0');
    navItem.setAttribute('aria-label', 'MailFlow');

    navItem.innerHTML = `
      <div class="TN">
        <div class="qj">
          ${ICONS.shield}
        </div>
        <div class="aio aif">
          <span class="nU"><a class="J-Ke n0 mailflow-nav-label" href="#mailflow">MailFlow</a></span>
        </div>
        <div class="bsU">
          <span class="mailflow-status-dot dot-grey" id="mailflow-status-dot" title="MailFlow Status: Monitoring"></span>
        </div>
      </div>
    `;

    navItem.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      activateMailFlowView();
    });

    aimWrapper.appendChild(navItem);

    if (target.anchor) {
      target.anchor.after(aimWrapper);
    } else {
      target.container.appendChild(aimWrapper);
    }

    attachNativeNavListeners();
  }

  function attachNativeNavListeners() {
    const nav = document.querySelector('div[role="navigation"]');
    if (!nav) return;

    const nativeItems = nav.querySelectorAll('a, .aim, .TO, [role="treeitem"]');
    nativeItems.forEach(item => {
      if (item.id === 'mailflow-aim-wrapper' || item.closest('#mailflow-aim-wrapper')) return;
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
   * MODULE 3: GMAIL LIGHT MODE VIEW & THREAT LISTS
   * =========================================================================
   */

  function getMainContainer() {
    return document.querySelector('div[role="main"]') || 
           document.querySelector('.AO') || 
           document.querySelector('.bkK') || 
           document.querySelector('.UI') ||
           document.querySelector('.nH.bkK') ||
           document.body;
  }

  function ensureViewMounted() {
    const mainContainer = getMainContainer();
    if (!mainContainer) return;

    let placeholder = document.getElementById('mailflow-placeholder-view');
    if (!placeholder) {
      placeholder = document.createElement('div');
      placeholder.id = 'mailflow-placeholder-view';
      mainContainer.appendChild(placeholder);
    } else if (placeholder.parentElement !== mainContainer) {
      mainContainer.appendChild(placeholder);
    }
  }

  function syncMailFlowState() {
    ensureViewMounted();

    const navItem = document.getElementById('mailflow-sidebar-nav-item');

    if (isMailFlowTabActive) {
      document.body.classList.add('mailflow-active-mode');
      if (navItem) navItem.classList.add('active');

      document.querySelectorAll('div[role="navigation"] .nZ').forEach(el => {
        if (el !== navItem) {
          el.classList.remove('nZ');
        }
      });

      setSearchBarText('in:MailFlow');
    } else {
      document.body.classList.remove('mailflow-active-mode');
      if (navItem) navItem.classList.remove('active');
    }
  }

  function activateMailFlowView() {
    isMailFlowTabActive = true;
    history.replaceState(null, '', '#mailflow');
    syncMailFlowState();
  }

  function deactivateMailFlowView() {
    isMailFlowTabActive = false;
    clearSearchBarIfMailFlow();
    syncMailFlowState();
  }

  function handleHashChange() {
    if (window.location.hash === '#mailflow') {
      if (!isMailFlowTabActive) {
        activateMailFlowView();
      }
    } else {
      if (isMailFlowTabActive) {
        deactivateMailFlowView();
      }
    }
  }

  /**
   * =========================================================================
   * MODULE 4: EMAIL METADATA EXTRACTION & SCAN HANDLER
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

    let snippet = '';
    const snippetEl = row.querySelector('.y2, span.y2, .Zt');
    if (snippetEl) {
      snippet = snippetEl.innerText.trim();
    }

    return { sender, subject, snippet };
  }

  async function handleScanClick(row, btn, e) {
    e.preventDefault();
    e.stopPropagation();

    if (btn.classList.contains('scanning')) return;

    const { sender, subject, snippet } = extractRowMetadata(row);

    // Enter asynchronous scanning state with loading spinner
    btn.className = 'mailflow-scan-btn scanning';
    btn.innerHTML = `<div class="mailflow-scan-spinner"></div>`;

    const minLoadingTime = 900;
    const startTime = performance.now();

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ sender, subject, snippet })
      });

      const elapsed = performance.now() - startTime;
      if (elapsed < minLoadingTime) {
        await new Promise(r => setTimeout(r, minLoadingTime - elapsed));
      }

      if (response.ok) {
        const data = await response.json();
        applyScanVerdict(row, btn, data);
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (err) {
      btn.className = 'mailflow-scan-btn backend-offline';
      btn.innerHTML = ICONS.shieldRow;

      showToast(
        '⚠️ Backend offline (:8000). Start ./start_backend.sh to evaluate emails.',
        'error'
      );

      setTimeout(() => {
        btn.className = 'mailflow-scan-btn';
        btn.innerHTML = ICONS.shieldRow;
      }, 3000);
    }
  }

  function applyScanVerdict(row, btn, data) {
    // Handled in upcoming commits
  }

  function createScanButton(row) {
    const actionItem = document.createElement('li');
    actionItem.className = 'mailflow-row-action-item bqX';
    actionItem.setAttribute('role', 'button');
    actionItem.setAttribute('title', 'MailFlow Scan');
    actionItem.setAttribute('aria-label', 'MailFlow Scan');
    actionItem.setAttribute('data-tooltip', 'MailFlow Scan');

    if (!currentSettings.showInlineRows) {
      actionItem.style.display = 'none';
    }

    const scanBtn = document.createElement('button');
    scanBtn.type = 'button';
    scanBtn.className = 'mailflow-scan-btn';
    scanBtn.setAttribute('aria-label', 'MailFlow Scan');
    scanBtn.setAttribute('title', 'MailFlow Scan');
    scanBtn.innerHTML = ICONS.shieldRow;

    scanBtn.addEventListener('click', (e) => handleScanClick(row, scanBtn, e));
    actionItem.appendChild(scanBtn);

    return actionItem;
  }

  function ensureRowHasScanButton(row) {
    if (!row) return;

    const actionToolbar = row.querySelector('ul.bq4, ul.aqL, ul[role="toolbar"], td.bq9 ul, .bq8 ul, .a4y ul, td.yX ul, ul.bqe, ul.bqZ');
    
    if (actionToolbar) {
      const existing = actionToolbar.querySelector('.mailflow-row-action-item');
      if (!existing) {
        const button = createScanButton(row);
        actionToolbar.appendChild(button);
      } else if (actionToolbar.lastElementChild !== existing) {
        actionToolbar.appendChild(existing);
      }
    } else {
      const actionCell = row.querySelector('td.yX, td.bq9, td.a4y, td.xY');
      if (actionCell && !actionCell.querySelector('.mailflow-row-action-item')) {
        const button = createScanButton(row);
        actionCell.appendChild(button);
      }
    }
  }

  function scanAllEmailRows() {
    const rows = document.querySelectorAll('tr.zA, .zA');
    rows.forEach(row => {
      ensureRowHasScanButton(row);
    });
  }

  function setupHoverDelegation() {
    document.addEventListener('mouseover', (e) => {
      const row = e.target.closest('tr.zA, .zA');
      if (row) {
        ensureRowHasScanButton(row);
      }
    }, { capture: true, passive: true });

    document.addEventListener('focusin', (e) => {
      const row = e.target.closest('tr.zA, .zA');
      if (row) {
        ensureRowHasScanButton(row);
      }
    }, { capture: true, passive: true });
  }

  /**
   * =========================================================================
   * OBSERVER & PERSISTENT DOM SYNCHRONIZATION
   * =========================================================================
   */

  function handleMutations() {
    if (!document.getElementById('mailflow-aim-wrapper')) {
      injectSidebarItem();
    }

    syncMailFlowState();

    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      scanAllEmailRows();
    }, 80);
  }

  async function init() {
    syncSettings();
    await checkBackendHeartbeat();
    injectSidebarItem();
    scanAllEmailRows();
    setupHoverDelegation();
    syncMailFlowState();

    window.removeEventListener('hashchange', handleHashChange);
    window.addEventListener('hashchange', handleHashChange);

    if (observer) observer.disconnect();
    observer = new MutationObserver(() => {
      handleMutations();
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    if (heartbeatTimer) clearInterval(heartbeatTimer);
    heartbeatTimer = setInterval(checkBackendHeartbeat, 10000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
