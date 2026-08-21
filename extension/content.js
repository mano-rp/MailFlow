/**
 * MailFlow Chrome Extension - Content Script
 * Native Gmail DOM Injections & Real-Time Backend Security Gate
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  let isBackendOnline = false;
  let isMailFlowTabActive = false;
  let observer = null;
  let scanDebounceTimer = null;
  let heartbeatTimer = null;

  let currentSettings = {
    showInlineRows: true,
    autoScan: true,
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
    shieldDarkHeader: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#a8c7fa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    check: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"/>
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
      if (currentSettings.showInlineRows) {
        item.classList.remove('mailflow-hidden-by-setting');
      } else {
        item.classList.add('mailflow-hidden-by-setting');
      }
    });

    const sidebarWrapper = document.getElementById('mailflow-aim-wrapper');
    if (sidebarWrapper) {
      if (currentSettings.autoScan) {
        sidebarWrapper.style.display = 'block';
      } else {
        sidebarWrapper.style.display = 'none';
      }
    }
  }

  /**
   * =========================================================================
   * MODULE 1: TOAST NOTIFICATIONS
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
   * MODULE 2: SIDEBAR LABEL INJECTION (Between Spam, All Mail, etc.)
   * =========================================================================
   */

  function findSidebarTargetAnchor() {
    const nav = document.querySelector('div[role="navigation"]');
    if (!nav) return null;

    // Search for Spam, All Mail, Drafts, Purchases, or Sent
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

    // Outer .aim wrapper matching native Gmail list row structure
    const aimWrapper = document.createElement('div');
    aimWrapper.id = 'mailflow-aim-wrapper';
    aimWrapper.className = 'aim mailflow-aim-item';

    // Inner .TO button
    const navItem = document.createElement('div');
    navItem.id = 'mailflow-sidebar-nav-item';
    navItem.className = 'TO mailflow-nav-item';
    navItem.setAttribute('role', 'button');
    navItem.setAttribute('tabindex', '0');
    navItem.setAttribute('aria-label', 'MailFlow');

    navItem.innerHTML = `
      <div class="TN mailflow-nav-inner">
        <div class="mailflow-nav-icon-wrapper">
          ${ICONS.shield}
        </div>
        <span class="mailflow-status-dot dot-grey" id="mailflow-status-dot" title="Status: Monitoring"></span>
        <span class="mailflow-nav-label">MailFlow</span>
      </div>
    `;

    navItem.addEventListener('click', (e) => {
      e.stopPropagation();
      activateMailFlowView();
    });

    aimWrapper.appendChild(navItem);

    if (target.anchor) {
      // Insert perfectly after Spam / All Mail / Drafts
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

    // Also listen to hash changes & top logo clicks to restore view
    window.removeEventListener('hashchange', handleHashChange);
    window.addEventListener('hashchange', handleHashChange);
  }

  function handleHashChange() {
    if (isMailFlowTabActive) {
      deactivateMailFlowView();
    }
  }

  /**
   * =========================================================================
   * MODULE 3: ALMOST BLACK PLACEHOLDER VIEW (Suspected Emails Hub)
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

    // Deselect Gmail's native active items
    document.querySelectorAll('div[role="navigation"] .nZ, div[role="navigation"] .active').forEach(el => {
      if (el.id !== 'mailflow-sidebar-nav-item') {
        el.classList.remove('nZ');
      }
    });

    const mainContainer = getMainContainer();
    if (!mainContainer) return;

    Array.from(mainContainer.children).forEach(child => {
      if (child.id !== 'mailflow-placeholder-view') {
        child.dataset.mailflowPrevDisplay = child.style.display;
        child.style.display = 'none';
      }
    });

    let placeholder = document.getElementById('mailflow-placeholder-view');
    if (!placeholder) {
      placeholder = document.createElement('div');
      placeholder.id = 'mailflow-placeholder-view';
      placeholder.innerHTML = `
        <div class="mailflow-dark-header">
          <h1 class="mailflow-dark-title">
            ${ICONS.shieldDarkHeader}
            MailFlow
          </h1>
          <span class="mailflow-dark-badge">Suspected Emails</span>
        </div>
      `;
      mainContainer.appendChild(placeholder);
    }
    placeholder.style.display = 'flex';
  }

  function deactivateMailFlowView() {
    isMailFlowTabActive = false;

    const navItem = document.getElementById('mailflow-sidebar-nav-item');
    if (navItem) navItem.classList.remove('active');

    const placeholder = document.getElementById('mailflow-placeholder-view');
    if (placeholder) placeholder.style.display = 'none';

    const mainContainer = getMainContainer();
    if (!mainContainer) return;

    Array.from(mainContainer.children).forEach(child => {
      if (child.id !== 'mailflow-placeholder-view') {
        child.style.display = child.dataset.mailflowPrevDisplay || '';
      }
    });
  }

  /**
   * =========================================================================
   * MODULE 4: EMAIL ROW SCAN BUTTON INJECTION
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
          `MailFlow: "${subject.substring(0, 30)}${subject.length > 30 ? '...' : ''}" from ${sender} is SAFE (${data.latency_ms || elapsed}ms)`,
          'success'
        );
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (err) {
      btn.className = 'mailflow-scan-btn backend-offline';
      btn.innerHTML = `
        ${ICONS.shieldRow}
        <span class="mailflow-scan-label">Offline</span>
      `;

      showToast(
        '⚠️ Backend offline (:8000). Start ./start_backend.sh to scan threads.',
        'warning'
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
    if (!document.getElementById('mailflow-aim-wrapper')) {
      injectSidebarItem();
    }

    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      scanEmailRows();
    }, 100);
  }

  async function init() {
    syncSettings();
    await checkBackendHeartbeat();
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

    if (heartbeatTimer) clearInterval(heartbeatTimer);
    heartbeatTimer = setInterval(checkBackendHeartbeat, 10000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
