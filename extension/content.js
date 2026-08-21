/**
 * MailFlow Chrome Extension - Content Script
 * Native Gmail DOM Injections & Real-Time Threat Evaluation Engine
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  const STORAGE_KEY_QUARANTINED = 'mailflow_quarantined_threats';
  const STORAGE_KEY_MODERATE = 'mailflow_moderate_threats';

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
    trash: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="3 6 5 6 21 6"></polyline>
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
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
   * MODULE 0: PERSISTENT STORAGE, HEALTH & SETTINGS
   * =========================================================================
   */

  function loadStoredThreats() {
    try {
      const rawQ = localStorage.getItem(STORAGE_KEY_QUARANTINED);
      if (rawQ) {
        const items = JSON.parse(rawQ);
        if (Array.isArray(items)) {
          items.forEach(item => {
            if (item && item.id) quarantinedThreats.set(item.id, item);
          });
        }
      }
      const rawM = localStorage.getItem(STORAGE_KEY_MODERATE);
      if (rawM) {
        const items = JSON.parse(rawM);
        if (Array.isArray(items)) {
          items.forEach(item => {
            if (item && item.id) moderateThreats.set(item.id, item);
          });
        }
      }
    } catch (e) {
      console.warn('[MailFlow] Storage load error:', e);
    }
  }

  function persistStoredThreats() {
    try {
      const qList = Array.from(quarantinedThreats.values()).map(t => ({
        id: t.id,
        sender: t.sender,
        subject: t.subject,
        snippet: t.snippet,
        risk_score: t.risk_score,
        tier: t.tier,
        color: t.color,
        threat_type: t.threat_type,
        explanation: t.explanation,
        timestamp: t.timestamp
      }));
      const mList = Array.from(moderateThreats.values()).map(t => ({
        id: t.id,
        sender: t.sender,
        subject: t.subject,
        snippet: t.snippet,
        risk_score: t.risk_score,
        tier: t.tier,
        color: t.color,
        threat_type: t.threat_type,
        explanation: t.explanation,
        timestamp: t.timestamp
      }));
      localStorage.setItem(STORAGE_KEY_QUARANTINED, JSON.stringify(qList));
      localStorage.setItem(STORAGE_KEY_MODERATE, JSON.stringify(mList));
    } catch (e) {
      console.warn('[MailFlow] Storage save error:', e);
    }
  }

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
   * MODULE 1: SEARCH BAR HOOK & TOASTS (ZERO-LOOP SAFE)
   * =========================================================================
   */

  function setSearchBarText(text) {
    const searchInput = document.querySelector('input[name="q"], input[aria-label*="Search"], form[role="search"] input');
    if (searchInput && searchInput.value !== text) {
      // Set value visually without triggering synthetic input events that loop Gmail's router
      searchInput.value = text;
    }
  }

  function clearSearchBarIfMailFlow() {
    const searchInput = document.querySelector('input[name="q"], input[aria-label*="Search"], form[role="search"] input');
    if (searchInput && (searchInput.value === 'in:MailFlow' || searchInput.value === 'in:mailflow')) {
      searchInput.value = '';
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
   * MODULE 2: SIDEBAR LABEL INJECTION & BADGE MANAGEMENT
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

  function updateSidebarBadge() {
    const badge = document.getElementById('mailflow-counter-badge');
    const dot = document.getElementById('mailflow-status-dot');
    const count = quarantinedThreats.size;

    if (badge) {
      if (count > 0) {
        badge.textContent = count;
        badge.classList.add('visible');
      } else {
        badge.classList.remove('visible');
      }
    }

    if (dot) {
      if (count > 0) {
        dot.className = 'mailflow-status-dot dot-red';
      } else if (moderateThreats.size > 0) {
        dot.className = 'mailflow-status-dot dot-yellow';
      } else {
        dot.className = 'mailflow-status-dot dot-grey';
      }
    }
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
          <span class="mailflow-counter-badge" id="mailflow-counter-badge">0</span>
          <span class="mailflow-status-dot dot-grey" id="mailflow-status-dot"></span>
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

    updateSidebarBadge();
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
   * MODULE 3: GMAIL LIGHT MODE VIEW & SUSPECTED EMAILS DASHBOARD
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

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, function(m) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m];
    });
  }

  function renderMailFlowDashboard() {
    const placeholder = document.getElementById('mailflow-placeholder-view');
    if (!placeholder) return;

    const totalQuarantined = quarantinedThreats.size;
    const totalModerate = moderateThreats.size;
    const hasItems = totalQuarantined > 0 || totalModerate > 0;

    let contentHtml = '';

    if (!hasItems) {
      contentHtml = `
        <div class="mailflow-view-body">
          <div class="mailflow-empty-shield-icon">
            ${ICONS.shieldHeader}
          </div>
          <h2 class="mailflow-empty-heading">No suspected emails</h2>
          <p class="mailflow-empty-subtext">
            MailFlow SME Shield is actively monitoring your mailbox. Suspected emails flagged by the scan button will appear here for review.
          </p>
        </div>
      `;
    } else {
      let quarantinedHtml = '';
      if (totalQuarantined > 0) {
        let cards = '';
        quarantinedThreats.forEach((threat, id) => {
          cards += `
            <div class="mailflow-threat-card high" data-threat-id="${id}">
              <div class="mailflow-card-top">
                <div class="mailflow-card-badge-group">
                  <span class="mailflow-card-threat-badge high">🚨 ${threat.threat_type || 'High Risk Threat'}</span>
                  <span class="mailflow-card-score-pill">Risk: ${threat.risk_score}/100</span>
                </div>
              </div>
              <div class="mailflow-card-sender">From: ${escapeHtml(threat.sender)}</div>
              <div class="mailflow-card-subject">Subject: ${escapeHtml(threat.subject)}</div>
              <div class="mailflow-card-explanation">${escapeHtml(threat.explanation)}</div>
              <div class="mailflow-card-actions">
                <button class="mailflow-btn-restore" data-restore-id="${id}">
                  ${ICONS.restore}
                  <span>Restore to Inbox</span>
                </button>
              </div>
            </div>
          `;
        });

        quarantinedHtml = `
          <div class="mailflow-threat-section">
            <div class="mailflow-section-header">
              <div class="mailflow-section-title-wrap">
                <span class="mailflow-section-title">🚨 Quarantined Threats</span>
                <span class="mailflow-section-count red">${totalQuarantined}</span>
              </div>
            </div>
            <div class="mailflow-threat-list">
              ${cards}
            </div>
          </div>
        `;
      }

      let moderateHtml = '';
      if (totalModerate > 0) {
        let cards = '';
        moderateThreats.forEach((threat, id) => {
          cards += `
            <div class="mailflow-threat-card moderate" data-threat-id="${id}">
              <div class="mailflow-card-top">
                <div class="mailflow-card-badge-group">
                  <span class="mailflow-card-threat-badge moderate">⚠️ ${threat.threat_type || 'Moderate Warning'}</span>
                  <span class="mailflow-card-score-pill">Risk: ${threat.risk_score}/100</span>
                </div>
              </div>
              <div class="mailflow-card-sender">From: ${escapeHtml(threat.sender)}</div>
              <div class="mailflow-card-subject">Subject: ${escapeHtml(threat.subject)}</div>
              <div class="mailflow-card-explanation">${escapeHtml(threat.explanation)}</div>
            </div>
          `;
        });

        moderateHtml = `
          <div class="mailflow-threat-section">
            <div class="mailflow-section-header">
              <div class="mailflow-section-title-wrap">
                <span class="mailflow-section-title">⚠️ Watchlist & Moderate Risks</span>
                <span class="mailflow-section-count yellow">${totalModerate}</span>
              </div>
            </div>
            <div class="mailflow-threat-list">
              ${cards}
            </div>
          </div>
        `;
      }

      contentHtml = `
        <div class="mailflow-view-content">
          ${quarantinedHtml}
          ${moderateHtml}
        </div>
      `;
    }

    placeholder.innerHTML = `
      <div class="mailflow-view-header">
        <div class="mailflow-view-title-group">
          <h1 class="mailflow-view-title">
            ${ICONS.shieldHeader}
            MailFlow
          </h1>
          <span class="mailflow-view-badge">Threat Center</span>
        </div>
        <div class="mailflow-view-actions">
          ${hasItems ? `
            <button id="mailflow-btn-clear-all" class="mailflow-btn-action danger" aria-label="Clear All Flagged Threats">
              ${ICONS.trash}
              <span>Clear All</span>
            </button>
          ` : ''}
        </div>
      </div>
      ${contentHtml}
    `;

    // Clear All Action
    const clearBtn = placeholder.querySelector('#mailflow-btn-clear-all');
    if (clearBtn) {
      clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearAllThreats();
      });
    }

    // Restore Buttons
    placeholder.querySelectorAll('.mailflow-btn-restore').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const threatId = btn.dataset.restoreId;
        if (threatId) {
          restoreThreatToInbox(threatId);
        }
      });
    });
  }

  function clearAllThreats() {
    // 1. Un-hide all DOM rows
    document.querySelectorAll('tr.zA, .zA').forEach(row => {
      if (row.dataset.mfRisk === 'high' || row.classList.contains('mailflow-quarantine-slide')) {
        row.style.display = '';
        row.classList.remove('mailflow-quarantine-slide');
        delete row.dataset.mfRisk;
      }
      if (row.dataset.mfRisk === 'moderate') {
        delete row.dataset.mfRisk;
        const badge = row.querySelector('.mailflow-moderate-badge');
        if (badge) badge.remove();
      }
      const btn = row.querySelector('.mailflow-scan-btn');
      if (btn) {
        btn.className = 'mailflow-scan-btn';
        btn.innerHTML = ICONS.shieldRow;
      }
      const actionItem = row.querySelector('.mailflow-row-action-item');
      if (actionItem) {
        actionItem.setAttribute('data-tooltip', 'MailFlow Scan');
      }
    });

    // 2. Clear stores & local storage
    quarantinedThreats.clear();
    moderateThreats.clear();
    persistStoredThreats();

    // 3. Update sidebar badge & re-render view
    updateSidebarBadge();
    renderMailFlowDashboard();

    showToast('All flagged threats cleared', 'info');
  }

  async function restoreThreatToInbox(threatId) {
    const threat = quarantinedThreats.get(threatId);

    try {
      fetch(`${BACKEND_URL}/api/threats/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: threatId })
      }).catch(() => {});
    } catch (e) {}

    let row = threat ? threat.row : null;
    if (!row) {
      row = document.querySelector(`tr[data-mailflow-id="${threatId}"], .zA[data-mailflow-id="${threatId}"]`);
    }

    if (row) {
      row.classList.remove('mailflow-quarantine-slide');
      row.classList.add('mailflow-restored-row');
      delete row.dataset.mfRisk;
      row.style.display = '';

      const scanBtn = row.querySelector('.mailflow-scan-btn');
      if (scanBtn) {
        scanBtn.className = 'mailflow-scan-btn';
        scanBtn.innerHTML = ICONS.shieldRow;
        const actionItem = scanBtn.closest('.mailflow-row-action-item');
        if (actionItem) actionItem.setAttribute('data-tooltip', 'MailFlow Scan');
      }

      setTimeout(() => {
        row.classList.remove('mailflow-restored-row');
      }, 1000);
    }

    quarantinedThreats.delete(threatId);
    persistStoredThreats();
    updateSidebarBadge();
    renderMailFlowDashboard();

    showToast('Threat email restored to Inbox', 'success');
  }

  function ensureViewMounted() {
    const mainContainer = getMainContainer();
    if (!mainContainer) return;

    let placeholder = document.getElementById('mailflow-placeholder-view');
    if (!placeholder) {
      placeholder = document.createElement('div');
      placeholder.id = 'mailflow-placeholder-view';
      mainContainer.appendChild(placeholder);
      renderMailFlowDashboard();
    } else if (placeholder.parentElement !== mainContainer) {
      mainContainer.appendChild(placeholder);
    }
  }

  function activateMailFlowView() {
    isMailFlowTabActive = true;
    history.replaceState(null, '', '#mailflow');

    ensureViewMounted();
    document.body.classList.add('mailflow-active-mode');

    const navItem = document.getElementById('mailflow-sidebar-nav-item');
    if (navItem) navItem.classList.add('active');

    setSearchBarText('in:MailFlow');
    renderMailFlowDashboard();
  }

  function deactivateMailFlowView() {
    isMailFlowTabActive = false;
    document.body.classList.remove('mailflow-active-mode');

    const navItem = document.getElementById('mailflow-sidebar-nav-item');
    if (navItem) navItem.classList.remove('active');

    clearSearchBarIfMailFlow();
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
    let sender = '';
    const senderEl = row.querySelector('.yP, .zF, span[email], .bA4 span, .yW span, span[name], .yX div, .yW');
    if (senderEl) {
      sender = senderEl.getAttribute('email') || 
               senderEl.getAttribute('name') || 
               senderEl.innerText.trim() || 
               '';
    }

    let subject = '';
    const subjectEl = row.querySelector('.bog, .bqe, span.bqe, .y6 span');
    if (subjectEl) {
      subject = subjectEl.innerText.trim() || '';
    }

    let snippet = '';
    const snippetEl = row.querySelector('.y2, span.y2, .Zt');
    if (snippetEl) {
      snippet = snippetEl.innerText.trim() || '';
    }

    if (!sender || !subject) {
      const rawText = row.innerText || row.textContent || '';
      const lines = rawText.split('\n').map(s => s.trim()).filter(Boolean);
      if (!sender && lines.length > 0) sender = lines[0];
      if (!subject && lines.length > 1) subject = lines[1];
      if (!snippet && lines.length > 2) snippet = lines.slice(2).join(' ');
    }

    sender = sender || 'Unknown Sender';
    subject = subject || 'No Subject';

    return { sender, subject, snippet };
  }

  async function handleScanClick(row, btn, e) {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
    }

    if (!btn || btn.classList.contains('scanning')) return;

    // Instant visual feedback on button and row
    btn.className = 'mailflow-scan-btn scanning';
    btn.innerHTML = `<div class="mailflow-scan-spinner"></div>`;
    row.classList.add('mailflow-row-scanning');

    const { sender, subject, snippet } = extractRowMetadata(row);

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

      row.classList.remove('mailflow-row-scanning');

      if (response.ok) {
        const data = await response.json();
        applyScanVerdict(row, btn, data);
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (err) {
      row.classList.remove('mailflow-row-scanning');
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
    const { id, tier, risk_score, threat_type, explanation } = data;

    row.dataset.mailflowId = id;
    const actionItem = btn.closest('.mailflow-row-action-item');

    if (tier === 'low') {
      btn.className = 'mailflow-scan-btn verdict-low';
      btn.innerHTML = ICONS.check;
      if (actionItem) actionItem.setAttribute('data-tooltip', `MailFlow: Clean (${risk_score}/100)`);
      showToast(`🟢 MailFlow: Verified Safe (${risk_score}/100) — No threat vectors detected`, 'success');
    } else if (tier === 'moderate') {
      btn.className = 'mailflow-scan-btn verdict-moderate';
      btn.innerHTML = ICONS.warning;
      if (actionItem) actionItem.setAttribute('data-tooltip', `MailFlow Warning: ${threat_type} (${risk_score}/100)`);
      showToast(`🟡 MailFlow Caution: ${threat_type} (Score: ${risk_score}/100)`, 'warning');
      
      row.dataset.mfRisk = 'moderate';
      
      const subjectEl = row.querySelector('.bog, .bqe, span.bqe');
      if (subjectEl && !subjectEl.querySelector('.mailflow-moderate-badge')) {
        const badge = document.createElement('span');
        badge.className = 'mailflow-moderate-badge';
        badge.innerHTML = `⚠ Caution (${risk_score})`;
        subjectEl.prepend(badge);
      }

      moderateThreats.set(id, { ...data, row });
      persistStoredThreats();
      updateSidebarBadge();
    } else if (tier === 'high') {
      btn.className = 'mailflow-scan-btn verdict-high';
      btn.innerHTML = ICONS.alert;
      if (actionItem) actionItem.setAttribute('data-tooltip', `MailFlow Threat: ${threat_type} (${risk_score}/100)`);
      showToast(`🔴 Threat Quarantined: ${threat_type} (${risk_score}/100)`, 'alert');
      
      row.dataset.mfRisk = 'high';
      quarantinedThreats.set(id, { ...data, row });
      persistStoredThreats();

      // Smooth slide-to-right quarantine animation
      row.classList.add('mailflow-quarantine-slide');
      setTimeout(() => {
        row.style.display = 'none';
        updateSidebarBadge();
      }, 500);
    }
  }

  function createScanButton(row) {
    const actionItem = document.createElement('li');
    actionItem.className = 'mailflow-row-action-item bqX';
    actionItem.setAttribute('role', 'button');
    actionItem.setAttribute('aria-label', 'MailFlow Scan');
    actionItem.setAttribute('data-tooltip', 'MailFlow Scan');
    actionItem.setAttribute('data-tooltip-delay', '300');

    if (!currentSettings.showInlineRows) {
      actionItem.style.display = 'none';
    }

    const scanBtn = document.createElement('div');
    scanBtn.className = 'mailflow-scan-btn';
    scanBtn.setAttribute('aria-hidden', 'true');
    scanBtn.innerHTML = ICONS.shieldRow;

    actionItem.appendChild(scanBtn);

    const onTrigger = (e) => {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      handleScanClick(row, scanBtn, e);
    };

    actionItem.addEventListener('click', onTrigger, true);
    actionItem.addEventListener('mousedown', (e) => {
      e.stopPropagation();
      e.stopImmediatePropagation();
    }, true);

    return actionItem;
  }

  function ensureRowHasScanButton(row) {
    if (!row) return;

    // Check if this row matches a previously stored threat
    const { sender, subject } = extractRowMetadata(row);
    quarantinedThreats.forEach((threat, id) => {
      if (threat.sender === sender && threat.subject === subject) {
        row.dataset.mailflowId = id;
        row.dataset.mfRisk = 'high';
        row.style.display = 'none';
      }
    });

    moderateThreats.forEach((threat, id) => {
      if (threat.sender === sender && threat.subject === subject) {
        row.dataset.mailflowId = id;
        row.dataset.mfRisk = 'moderate';
        const subjectEl = row.querySelector('.bog, .bqe, span.bqe');
        if (subjectEl && !subjectEl.querySelector('.mailflow-moderate-badge')) {
          const badge = document.createElement('span');
          badge.className = 'mailflow-moderate-badge';
          badge.innerHTML = `⚠ Caution (${threat.risk_score})`;
          subjectEl.prepend(badge);
        }
      }
    });

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
    // 1. Mouseover listener to ensure toolbar has the scan button
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

    // 2. Global capture-phase click delegator for MailFlow scan button
    document.addEventListener('click', (e) => {
      const scanItem = e.target.closest('.mailflow-row-action-item, .mailflow-scan-btn');
      if (scanItem) {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();

        const row = scanItem.closest('tr.zA, .zA');
        const btn = scanItem.classList.contains('mailflow-scan-btn') 
          ? scanItem 
          : scanItem.querySelector('.mailflow-scan-btn');

        if (row && btn) {
          handleScanClick(row, btn, e);
        }
      }
    }, { capture: true });

    // 3. Prevent mousedown from focusing / selecting row when clicking scan button
    document.addEventListener('mousedown', (e) => {
      const scanItem = e.target.closest('.mailflow-row-action-item, .mailflow-scan-btn');
      if (scanItem) {
        e.stopPropagation();
        e.stopImmediatePropagation();
      }
    }, { capture: true });
  }

  /**
   * =========================================================================
   * MODULE 5: OBSERVER & PERSISTENT DOM SYNCHRONIZATION (CLEAN & NON-RECURSIVE)
   * =========================================================================
   */

  function handleMutations() {
    if (!document.getElementById('mailflow-aim-wrapper')) {
      injectSidebarItem();
    }

    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      scanAllEmailRows();
    }, 150);
  }

  async function init() {
    loadStoredThreats();
    syncSettings();
    await checkBackendHeartbeat();
    injectSidebarItem();
    scanAllEmailRows();
    setupHoverDelegation();
    updateSidebarBadge();

    if (window.location.hash === '#mailflow') {
      activateMailFlowView();
    }

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
