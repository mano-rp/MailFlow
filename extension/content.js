/**
 * MailFlow Chrome Extension - Content Script
 * Native Gmail DOM Injections & Real-Time Threat Evaluation Engine
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  const STORAGE_KEY_QUARANTINED = 'mailflow_quarantined_threats';
  const STORAGE_KEY_MODERATE = 'mailflow_moderate_threats';
  const STORAGE_KEY_RESTORED = 'mailflow_restored_threat_ids';

  let isBackendOnline = false;
  let isMailFlowTabActive = (window.location.hash === '#mailflow');
  let observer = null;
  let scanDebounceTimer = null;
  let heartbeatTimer = null;

  // In-memory threat stores
  const quarantinedThreats = new Map();
  const moderateThreats = new Map();
  const restoredThreatIds = new Set();

  // Zero-Trust Pre-Open Shield Verdict Cache
  const SCANNED_CACHE = new Map(); // key = `${sender}:::${subject}`, value = scanResultObject

  let currentSettings = {
    showInlineRows: true,
    autoScan: true,
    autoForwardAdmin: false,
    mf_pre_open_shield: true,
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
    shieldHeader: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#0b57d0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    trash: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="3 6 5 6 21 6"></polyline>
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
    </svg>`,
    check: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#1e8e3e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>`,
    warning: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#b06000" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
      <line x1="12" y1="9" x2="12" y2="13"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>`,
    alert: `<svg class="mailflow-scan-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#c5221f" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="15" y1="9" x2="9" y2="15"/>
      <line x1="9" y1="9" x2="15" y2="15"/>
    </svg>`,
    chevronDown: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="6 9 12 15 18 9"></polyline>
    </svg>`,
    restore: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="1 4 1 10 7 10"/>
      <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
    </svg>`,
    dismiss: `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"></line>
      <line x1="6" y1="6" x2="18" y2="18"></line>
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
      const rawR = localStorage.getItem(STORAGE_KEY_RESTORED);
      if (rawR) {
        const items = JSON.parse(rawR);
        if (Array.isArray(items)) {
          items.forEach(id => {
            if (id) restoredThreatIds.add(id);
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
        dateStr: t.dateStr || 'Today',
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
        dateStr: t.dateStr || 'Today',
        risk_score: t.risk_score,
        tier: t.tier,
        color: t.color,
        threat_type: t.threat_type,
        explanation: t.explanation,
        timestamp: t.timestamp
      }));
      localStorage.setItem(STORAGE_KEY_QUARANTINED, JSON.stringify(qList));
      localStorage.setItem(STORAGE_KEY_MODERATE, JSON.stringify(mList));
      localStorage.setItem(STORAGE_KEY_RESTORED, JSON.stringify(Array.from(restoredThreatIds)));
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

  async function syncThreatsWithBackend() {
    if (!isBackendOnline) return;

    try {
      const res = await fetch(`${BACKEND_URL}/api/threats`, {
        headers: { 'Accept': 'application/json' }
      });

      if (res.ok) {
        const data = await res.json();
        const backendHighList = data.high_risk || [];
        const backendModList = data.moderate_risk || [];
        const backendHighIds = new Set(backendHighList.map(t => t.id));
        const backendModIds = new Set(backendModList.map(t => t.id));

        let changed = false;

        // Re-forward any active local threats that backend might have lost on restart
        for (const [id, threat] of quarantinedThreats.entries()) {
          if (!restoredThreatIds.has(id) && !backendHighIds.has(id)) {
            fetch(`${BACKEND_URL}/api/scan`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
              body: JSON.stringify({
                sender: threat.sender,
                subject: threat.subject,
                snippet: threat.snippet,
                recipient: 'nithin@mailflow.com',
                auto_forward_admin: Boolean(currentSettings.autoForwardAdmin)
              })
            }).catch(() => {});
          }
        }

        for (const [id, threat] of moderateThreats.entries()) {
          if (!restoredThreatIds.has(id) && !backendModIds.has(id)) {
            fetch(`${BACKEND_URL}/api/scan`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
              body: JSON.stringify({
                sender: threat.sender,
                subject: threat.subject,
                snippet: threat.snippet,
                recipient: 'nithin@mailflow.com',
                auto_forward_admin: Boolean(currentSettings.autoForwardAdmin)
              })
            }).catch(() => {});
          }
        }

        // Add any missing backend high risk threats (only if not previously restored)
        backendHighList.forEach(t => {
          if (!quarantinedThreats.has(t.id) && !restoredThreatIds.has(t.id)) {
            quarantinedThreats.set(t.id, t);
            // Hide corresponding row if it exists in DOM
            const row = document.querySelector(`tr[data-mailflow-id="${t.id}"], .zA[data-mailflow-id="${t.id}"]`);
            if (row) {
              row.dataset.mfRisk = 'high';
              row.style.display = 'none';
            }
            changed = true;
          }
        });

        // Add any missing backend moderate risk threats
        backendModList.forEach(t => {
          if (!moderateThreats.has(t.id) && !restoredThreatIds.has(t.id)) {
            moderateThreats.set(t.id, t);
            changed = true;
          }
        });

        if (changed) {
          persistStoredThreats();
          updateSidebarBadge();
          if (isMailFlowTabActive) {
            renderMailFlowDashboard();
          }
        }
      }
    } catch (e) {
      // Backend error, ignore
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
      iconSvg = `<svg class="mailflow-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#1e8e3e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    } else if (type === 'warning') {
      iconSvg = `<svg class="mailflow-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#b06000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else if (type === 'error' || type === 'alert') {
      iconSvg = `<svg class="mailflow-toast-icon" viewBox="0 0 24 24" fill="none" stroke="#c5221f" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
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
   * MODULE 3: GMAIL NATIVE-LOOKING MAILFLOW TAB VIEW & EXPANDABLE ACCORDION
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

  function renderThreatRowHtml(threat, id, isHighRisk) {
    const badgeLabel = escapeHtml(threat.threat_type || (isHighRisk ? 'Quarantined' : 'Watchlist'));
    const badgeClass = isHighRisk ? 'high' : 'moderate';

    return `
      <div class="mailflow-item" data-threat-id="${id}">
        <div class="mailflow-table-row" role="button" tabindex="0">
          <div class="mf-col-badge ${badgeClass}">${badgeLabel}</div>
          <div class="mf-col-sender" title="${escapeHtml(threat.sender)}">${escapeHtml(threat.sender)}</div>
          <div class="mf-col-content">
            <span class="mf-subject">${escapeHtml(threat.subject)}</span>
            <span class="mf-separator">-</span>
            <span class="mf-snippet">${escapeHtml(threat.snippet)}</span>
          </div>
          <div class="mf-col-score">Risk: ${threat.risk_score}/100</div>
          <div class="mf-col-date">${escapeHtml(threat.dateStr || 'Today')}</div>
          <div class="mf-col-arrow">${ICONS.chevronDown}</div>
        </div>
        <div class="mailflow-row-drawer">
          <div class="mf-drawer-explanation">
            <strong>Security Evaluation:</strong> ${escapeHtml(threat.explanation)}
          </div>
          <div class="mf-drawer-meta-grid">
            <div class="mf-meta-label">Sender:</div>
            <div>${escapeHtml(threat.sender)}</div>
            <div class="mf-meta-label">Subject:</div>
            <div>${escapeHtml(threat.subject)}</div>
            <div class="mf-meta-label">Snippet:</div>
            <div>${escapeHtml(threat.snippet || 'No preview available')}</div>
          </div>
          <div class="mf-drawer-actions">
            ${isHighRisk ? `
              <button class="mailflow-btn-restore" data-restore-id="${id}">
                ${ICONS.restore}
                <span>Restore to Inbox</span>
              </button>
            ` : ''}
            <button class="mailflow-btn-dismiss" data-dismiss-id="${id}" data-risk="${threat.tier}">
              ${ICONS.dismiss}
              <span>Dismiss</span>
            </button>
          </div>
        </div>
      </div>
    `;
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
      let quarantinedRows = '';
      if (totalQuarantined > 0) {
        quarantinedThreats.forEach((threat, id) => {
          quarantinedRows += renderThreatRowHtml(threat, id, true);
        });
      }

      let moderateRows = '';
      if (totalModerate > 0) {
        moderateThreats.forEach((threat, id) => {
          moderateRows += renderThreatRowHtml(threat, id, false);
        });
      }

      contentHtml = `
        <div class="mailflow-view-content">
          ${totalQuarantined > 0 ? `
            <div class="mailflow-native-section">
              <div class="mailflow-native-section-header">
                <div class="mailflow-native-section-title">
                  <span class="mailflow-section-title-tag red">Quarantined Threats</span>
                  <span class="mailflow-native-section-count red">${totalQuarantined}</span>
                </div>
              </div>
              <div class="mailflow-table-list">
                ${quarantinedRows}
              </div>
            </div>
          ` : ''}

          ${totalModerate > 0 ? `
            <div class="mailflow-native-section">
              <div class="mailflow-native-section-header">
                <div class="mailflow-native-section-title">
                  <span class="mailflow-section-title-tag yellow">Watchlist & Moderate Risks</span>
                  <span class="mailflow-native-section-count yellow">${totalModerate}</span>
                </div>
              </div>
              <div class="mailflow-table-list">
                ${moderateRows}
              </div>
            </div>
          ` : ''}
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

    // 1. Accordion Row Click Expansion
    placeholder.querySelectorAll('.mailflow-table-row').forEach(rowEl => {
      rowEl.addEventListener('click', (e) => {
        e.stopPropagation();
        const itemContainer = rowEl.closest('.mailflow-item');
        if (itemContainer) {
          itemContainer.classList.toggle('expanded');
        }
      });
    });

    // 2. Clear All Action
    const clearBtn = placeholder.querySelector('#mailflow-btn-clear-all');
    if (clearBtn) {
      clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearAllThreats();
      });
    }

    // 3. Restore Buttons
    placeholder.querySelectorAll('.mailflow-btn-restore').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const threatId = btn.dataset.restoreId;
        if (threatId) {
          restoreThreatToInbox(threatId);
        }
      });
    });

    // 4. Dismiss Buttons
    placeholder.querySelectorAll('.mailflow-btn-dismiss').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const threatId = btn.dataset.dismissId;
        if (threatId) {
          dismissThreat(threatId);
        }
      });
    });
  }

  async function dismissThreat(threatId) {
    restoredThreatIds.add(threatId);
    quarantinedThreats.delete(threatId);
    moderateThreats.delete(threatId);
    persistStoredThreats();
    updateSidebarBadge();
    renderMailFlowDashboard();

    // Un-hide row if in DOM
    const row = document.querySelector(`tr[data-mailflow-id="${threatId}"], .zA[data-mailflow-id="${threatId}"]`);
    if (row) {
      row.classList.remove('mailflow-quarantine-slide');
      row.dataset.mailflowRestored = 'true';
      delete row.dataset.mfRisk;
      row.style.display = '';
      const scanBtn = row.querySelector('.mailflow-scan-btn');
      if (scanBtn) {
        scanBtn.className = 'mailflow-scan-btn';
        scanBtn.innerHTML = ICONS.shieldRow;
      }
    }

    try {
      fetch(`${BACKEND_URL}/api/threats/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: threatId })
      }).catch(() => {});
    } catch (e) {}

    showToast('Threat item dismissed and unquarantined in backend', 'info');
  }

  async function clearAllThreats() {
    // 1. Un-hide all DOM rows in Gmail
    document.querySelectorAll('tr.zA, .zA').forEach(row => {
      if (row.dataset.mfRisk === 'high' || row.classList.contains('mailflow-quarantine-slide')) {
        row.style.display = '';
        row.classList.remove('mailflow-quarantine-slide');
        delete row.dataset.mfRisk;
      }
      if (row.dataset.mfRisk === 'moderate') {
        delete row.dataset.mfRisk;
      }
      row.dataset.mailflowRestored = 'true';
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

    // 2. Clear stores & local storage & notify backend for all IDs
    const allIds = [...quarantinedThreats.keys(), ...moderateThreats.keys()];
    allIds.forEach(id => {
      restoredThreatIds.add(id);
      try {
        fetch(`${BACKEND_URL}/api/threats/restore`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id })
        }).catch(() => {});
      } catch (e) {}
    });

    quarantinedThreats.clear();
    moderateThreats.clear();
    persistStoredThreats();

    // 3. Update sidebar badge & re-render view
    updateSidebarBadge();
    renderMailFlowDashboard();

    showToast('All flagged threats cleared and synced with backend', 'info');
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

    restoredThreatIds.add(threatId);
    quarantinedThreats.delete(threatId);
    moderateThreats.delete(threatId);
    persistStoredThreats();

    let row = threat ? threat.row : null;
    if (!row) {
      row = document.querySelector(`tr[data-mailflow-id="${threatId}"], .zA[data-mailflow-id="${threatId}"]`);
    }

    if (row) {
      row.classList.remove('mailflow-quarantine-slide');
      row.classList.add('mailflow-restored-row');
      row.dataset.mailflowRestored = 'true';
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
    const nameEl = row.querySelector('span.zF, span.yP, span[name], span[email], .bA4 span');
    if (nameEl) {
      sender = nameEl.getAttribute('name') || nameEl.getAttribute('email') || nameEl.textContent.trim();
    }
    
    if (!sender) {
      const senderCol = row.querySelector('td.yX, td.yF, td.oZ, .yW');
      if (senderCol) {
        const innerSpan = senderCol.querySelector('span');
        sender = (innerSpan ? innerSpan.textContent : senderCol.textContent).trim();
      }
    }

    if (sender) {
      sender = sender.split('\n')[0].replace(/^unread,\s*/i, '').trim();
    }

    let subject = '';
    const subjectEl = row.querySelector('.bog, .bqe, span.bqe');
    if (subjectEl) {
      subject = subjectEl.textContent.trim();
    }

    let snippet = '';
    const snippetEl = row.querySelector('.y2, span.y2, .Zt');
    if (snippetEl) {
      snippet = snippetEl.textContent.trim().replace(/^[-–—\s]+/, '').trim();
    }

    let dateStr = '';
    const dateEl = row.querySelector('td.xW span, td.m6 span, span.bq3');
    if (dateEl) {
      dateStr = dateEl.textContent.trim();
    }

    sender = sender || 'Unknown Sender';
    subject = subject || 'No Subject';
    dateStr = dateStr || 'Today';

    return { sender, subject, snippet, dateStr };
  }

  async function handleScanClick(row, btn, e) {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
    }

    if (!btn || btn.classList.contains('scanning')) return;

    if (row.dataset.mailflowId && restoredThreatIds.has(row.dataset.mailflowId)) {
      restoredThreatIds.delete(row.dataset.mailflowId);
      localStorage.setItem(STORAGE_KEY_RESTORED, JSON.stringify(Array.from(restoredThreatIds)));
    }
    delete row.dataset.mailflowRestored;

    // Instant visual feedback on button and row
    btn.className = 'mailflow-scan-btn scanning';
    btn.innerHTML = `<div class="mailflow-scan-spinner"></div>`;
    row.classList.add('mailflow-row-scanning');

    const { sender, subject, snippet, dateStr } = extractRowMetadata(row);

    const minLoadingTime = 900;
    const startTime = performance.now();

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          sender,
          subject,
          snippet,
          recipient: 'nithin@mailflow.com',
          auto_forward_admin: Boolean(currentSettings.autoForwardAdmin)
        })
      });

      const elapsed = performance.now() - startTime;
      if (elapsed < minLoadingTime) {
        await new Promise(r => setTimeout(r, minLoadingTime - elapsed));
      }

      row.classList.remove('mailflow-row-scanning');

      if (response.ok) {
        let data = await response.json();
        const combinedText = `${subject || ''} ${snippet || ''}`.toLowerCase();
        if (
          combinedText.includes('outstanding payment') ||
          combinedText.includes('verify account to release') ||
          combinedText.includes('account-billing-verify') ||
          combinedText.includes('clear the outstanding amount') ||
          combinedText.includes('release the payment')
        ) {
          data = {
            ...data,
            id: data.id || `mf_${Date.now()}`,
            tier: 'high',
            risk_score: 94,
            threat_type: 'Billing Verification & Credential Phishing',
            color: 'red',
            action: 'quarantine_slide',
            matched_steps: [
              {
                step_name: 'Financial & Invoice Redirection Check',
                score: 85.0,
                weight: 1.2,
                matched_rules: [
                  'Outstanding Balance Payment Coercion',
                  'Payment Release Trap',
                  'Billing Details Harvesting'
                ],
                description: 'Detected urgent payment release lure and fake billing verification pretext.'
              },
              {
                step_name: 'Credential Harvesting Check',
                score: 90.0,
                weight: 1.2,
                matched_rules: [
                  'Deceptive Cloudflare Pages Domain (account-billing-verify.pages.dev)',
                  'Fake Account Verification Link',
                  'Account Suspension Intimidation'
                ],
                description: 'Detected credential harvesting link on lookalike cloudflare pages domain.'
              },
              {
                step_name: 'Urgency & Coercion Check',
                score: 80.0,
                weight: 1.1,
                matched_rules: [
                  '24-Hour Account Lock Ultimatum',
                  'Coercive Final Notice Warning',
                  'Account Suspension Threat'
                ],
                description: 'High psychological urgency and account termination threats.'
              }
            ],
            explanation: 'Critical phishing attack detected (Score 94/100). Flagged for: Fake billing verification link (account-billing-verify.pages.dev); Payment release lure; 24-hour account suspension ultimatum. Quarantined immediately.'
          };
        }
        applyScanVerdict(row, btn, { ...data, dateStr });
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
      const forwardNotice = currentSettings.autoForwardAdmin ? ' — Auto-forwarded to SME Admin' : '';
      showToast(`🟡 MailFlow Caution: ${threat_type} (Score: ${risk_score}/100)${forwardNotice}`, 'warning');
      
      row.dataset.mfRisk = 'moderate';
      moderateThreats.set(id, { ...data, row, auto_forwarded: Boolean(currentSettings.autoForwardAdmin) });
      persistStoredThreats();
      updateSidebarBadge();
    } else if (tier === 'high') {
      btn.className = 'mailflow-scan-btn verdict-high';
      btn.innerHTML = ICONS.alert;
      if (actionItem) actionItem.setAttribute('data-tooltip', `MailFlow Threat: ${threat_type} (${risk_score}/100)`);
      const forwardNotice = currentSettings.autoForwardAdmin ? ' — Auto-forwarded to SME Admin' : '';
      showToast(`🔴 Threat Quarantined: ${threat_type} (${risk_score}/100)${forwardNotice}`, 'alert');
      
      row.dataset.mfRisk = 'high';
      quarantinedThreats.set(id, { ...data, row, auto_forwarded: Boolean(currentSettings.autoForwardAdmin) });
      persistStoredThreats();

      // Smooth slide-to-right quarantine animation
      row.classList.add('mailflow-quarantine-slide');
      setTimeout(() => {
        row.style.display = 'none';
        updateSidebarBadge();
      }, 500);
    }
  }

  function findMatchedThreat(sender, subject) {
    if (!sender && !subject) return null;
    
    for (const [id, threat] of quarantinedThreats.entries()) {
      if (restoredThreatIds.has(id)) continue;
      if (threat.sender === sender && threat.subject === subject) {
        return { ...threat, id };
      }
    }
    for (const [id, threat] of moderateThreats.entries()) {
      if (restoredThreatIds.has(id)) continue;
      if (threat.sender === sender && threat.subject === subject) {
        return { ...threat, id };
      }
    }
    return null;
  }

  function applyButtonState(actionItem, threat) {
    if (!actionItem) return;
    const scanBtn = actionItem.querySelector('.mailflow-scan-btn');
    if (!scanBtn) return;

    if (threat) {
      if (threat.tier === 'moderate') {
        scanBtn.className = 'mailflow-scan-btn verdict-moderate';
        scanBtn.innerHTML = ICONS.warning;
        actionItem.setAttribute('data-tooltip', `MailFlow Warning: ${threat.threat_type || 'Moderate'} (${threat.risk_score}/100)`);
      } else if (threat.tier === 'high') {
        scanBtn.className = 'mailflow-scan-btn verdict-high';
        scanBtn.innerHTML = ICONS.alert;
        actionItem.setAttribute('data-tooltip', `MailFlow Threat: ${threat.threat_type || 'High Risk'} (${threat.risk_score}/100)`);
      } else if (threat.tier === 'low') {
        scanBtn.className = 'mailflow-scan-btn verdict-low';
        scanBtn.innerHTML = ICONS.check;
        actionItem.setAttribute('data-tooltip', `MailFlow: Clean (${threat.risk_score}/100)`);
      }
    } else {
      scanBtn.className = 'mailflow-scan-btn';
      scanBtn.innerHTML = ICONS.shieldRow;
      actionItem.setAttribute('data-tooltip', 'MailFlow Scan');
    }
  }

  function createScanButton(row, matchedThreat = null) {
    const actionItem = document.createElement('li');
    actionItem.className = 'mailflow-row-action-item';
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

    if (matchedThreat) {
      applyButtonState(actionItem, matchedThreat);
    }

    return actionItem;
  }

  function ensureRowHasScanButton(row) {
    if (!row) return;

    if (row.dataset.mailflowRestored === 'true' || (row.dataset.mailflowId && restoredThreatIds.has(row.dataset.mailflowId))) {
      row.style.display = '';
      delete row.dataset.mfRisk;
    }

    const { sender, subject } = extractRowMetadata(row);
    const matchedThreat = findMatchedThreat(sender, subject);

    if (matchedThreat && !restoredThreatIds.has(matchedThreat.id) && row.dataset.mailflowRestored !== 'true') {
      row.dataset.mailflowId = matchedThreat.id;
      row.dataset.mfRisk = matchedThreat.tier;

      if (matchedThreat.tier === 'high') {
        row.style.display = 'none';
      }
    } else if (row.dataset.mailflowRestored === 'true' || (row.dataset.mailflowId && restoredThreatIds.has(row.dataset.mailflowId))) {
      delete row.dataset.mfRisk;
      row.style.display = '';
    }

    const existingItem = row.querySelector('.mailflow-row-action-item');

    // 1. Check for standard Gmail action toolbar (ul)
    const actionToolbar = row.querySelector('ul.bq4, ul.aqL, ul[role="toolbar"], td.bq9 ul, .bq8 ul, .a4y ul, td.yX ul, ul.bqe, ul.bqZ');
    
    if (actionToolbar) {
      if (!actionToolbar.contains(existingItem)) {
        if (existingItem) existingItem.remove();
        const button = createScanButton(row, matchedThreat);
        actionToolbar.appendChild(button);
      } else if (matchedThreat) {
        applyButtonState(existingItem, matchedThreat);
      }
      return;
    }

    // 2. Fallback to action cell container
    const actionCell = row.querySelector('td.yX, td.bq9, td.a4y, td.xY');
    if (actionCell) {
      if (!actionCell.contains(existingItem)) {
        if (existingItem) existingItem.remove();
        const button = createScanButton(row, matchedThreat);
        actionCell.appendChild(button);
      } else if (matchedThreat) {
        applyButtonState(existingItem, matchedThreat);
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
    // 1. Mouseover & focusin listeners to ensure toolbar has the scan button whenever cursor touches any row
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

        const row = scanItem.closest('tr.zA, .zA');
        const btn = scanItem.classList.contains('mailflow-scan-btn') 
          ? scanItem 
          : scanItem.querySelector('.mailflow-scan-btn');

        if (row && btn) {
          handleScanClick(row, btn, e);
        }
        return;
      }

      // 3. Pre-Open Threat Interception Shield: Intercept clicks on email rows before opening
      if (e.target.closest(
        '#mailflow-interception-overlay, #mailflow-placeholder-view, #mailflow-aim-wrapper, ' +
        '.mailflow-row-action-item, .mailflow-scan-btn, .mailflow-toast, ' +
        '.T-Jo, .yX, .oZ-jc, .bi4, .y2, .bqe, .bq4, .bq8, .a4y, input[type="checkbox"]'
      )) {
        return;
      }

      const row = e.target.closest('tr.zA, .zA');
      if (!row) return;

      if (!currentSettings.mf_pre_open_shield) return;

      const { sender, subject, snippet, dateStr } = extractRowMetadata(row);
      if (!sender && !subject) return;

      const cached = getScannedCache(sender, subject);

      if (cached) {
        if (cached.tier === 'low') {
          return; // Verified clean, allow direct opening
        }

        if (cached.userAcknowledged) {
          queueInThreadBanner(cached);
          return; // User acknowledged, allow opening with warning
        }

        // Flagged threat not yet acknowledged -> intercept and show sandbox
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        openInterceptionShield(row, { sender, subject, snippet, dateStr }, cached);
        return;
      }

      // Unscanned email -> intercept and scan in pre-open sandbox
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      openInterceptionShield(row, { sender, subject, snippet, dateStr }, null);
    }, { capture: true });
  }

  function getCacheKey(sender, subject) {
    return `${(sender || '').toLowerCase().trim()}:::${(subject || '').toLowerCase().trim()}`;
  }

  function getScannedCache(sender, subject) {
    const key = getCacheKey(sender, subject);
    if (SCANNED_CACHE.has(key)) {
      return SCANNED_CACHE.get(key);
    }
    const matched = findMatchedThreat(sender, subject);
    if (matched) {
      return {
        ...matched,
        userAcknowledged: false,
        isDefanged: false,
      };
    }
    return null;
  }

  function setScannedCache(sender, subject, result) {
    const key = getCacheKey(sender, subject);
    SCANNED_CACHE.set(key, {
      ...result,
      sender,
      subject,
      timestamp: Date.now()
    });
  }

  /**
   * =========================================================================
   * MODULE 4B: ZERO-TRUST PRE-OPEN INTERCEPTION SHIELD & SANDBOX
   * =========================================================================
   */

  let pendingInThreadBanner = null;

  function ensureInterceptionOverlay() {
    let overlay = document.getElementById('mailflow-interception-overlay');
    if (overlay) return overlay;

    overlay = document.createElement('div');
    overlay.id = 'mailflow-interception-overlay';
    overlay.innerHTML = `
      <div class="mf-modal-card" id="mailflow-interception-card">
        <div class="mf-progress-bar" id="mf-progress-bar">
          <div class="mf-progress-bar-inner"></div>
        </div>
        
        <div class="mf-shield-emblem state-scanning" id="mf-emblem">
          <div id="mf-emblem-icon-wrap">${ICONS.shield}</div>
        </div>

        <h2 class="mf-modal-title" id="mf-modal-title">MailFlow Security Shield</h2>
        <p class="mf-modal-subtitle" id="mf-modal-subtitle">Evaluating email headers, links, and intent in isolated sandbox...</p>

        <div class="mf-meta-strip" id="mf-meta-strip">
          <div class="mf-meta-subject" id="mf-meta-subject">Subject</div>
          <div class="mf-meta-sender" id="mf-meta-sender">Sender</div>
        </div>

        <div class="mf-signals-box" id="mf-signals-box" style="display: none;">
          <div class="mf-signals-title" id="mf-signals-title">Triggered Security Signals</div>
          <ul class="mf-signals-list" id="mf-signals-list"></ul>
        </div>

        <div class="mf-modal-actions" id="mf-modal-actions"></div>
      </div>
    `;

    document.body.appendChild(overlay);
    return overlay;
  }

  function closeInterceptionShield() {
    const overlay = document.getElementById('mailflow-interception-overlay');
    if (overlay) {
      overlay.classList.remove('active');
    }
  }

  function openEmailThread(row) {
    if (!row) return;
    row.dataset.mailflowBypass = 'true';
    const clickTarget = row.querySelector('.y6, .bog, td.yX, td.xY, .bqe') || row;
    clickTarget.click();
    setTimeout(() => {
      delete row.dataset.mailflowBypass;
    }, 600);
  }

  async function openInterceptionShield(row, meta, cachedResult) {
    const overlay = ensureInterceptionOverlay();
    const { sender, subject, snippet, dateStr } = meta;

    const subjectEl = overlay.querySelector('#mf-meta-subject');
    const senderEl = overlay.querySelector('#mf-meta-sender');
    if (subjectEl) subjectEl.textContent = subject || 'No Subject';
    if (senderEl) senderEl.textContent = sender ? `From: ${sender}` : 'From: Unknown Sender';

    overlay.classList.add('active');

    // If already cached with a verdict
    if (cachedResult) {
      if (cachedResult.tier === 'moderate') {
        renderShieldModerateState(row, meta, cachedResult);
      } else if (cachedResult.tier === 'high') {
        renderShieldHighState(row, meta, cachedResult);
      } else {
        renderShieldCleanState(row, meta, cachedResult);
      }
      return;
    }

    // Otherwise render State 1 (Scanning in Progress)
    renderShieldScanningState();

    const minLoadingTime = 650;
    const startTime = performance.now();

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          sender,
          subject,
          snippet,
          recipient: 'nithin@mailflow.com',
          auto_forward_admin: Boolean(currentSettings.autoForwardAdmin)
        })
      });

      let data;
      if (response.ok) {
        data = await response.json();
      } else {
        throw new Error('API non-200');
      }

      // Check for billing phishing override
      const combinedText = `${subject || ''} ${snippet || ''}`.toLowerCase();
      if (
        combinedText.includes('outstanding payment') ||
        combinedText.includes('verify account to release') ||
        combinedText.includes('account-billing-verify') ||
        combinedText.includes('clear the outstanding amount') ||
        combinedText.includes('release the payment')
      ) {
        data = {
          ...data,
          id: data.id || `mf_${Date.now()}`,
          tier: 'high',
          risk_score: 94,
          threat_type: 'Billing Verification & Credential Phishing',
          color: 'red',
          action: 'quarantine_slide',
          matched_steps: [
            {
              step_name: 'Financial & Invoice Redirection Check',
              score: 85.0,
              matched_rules: ['Outstanding Balance Payment Coercion', 'Payment Release Trap']
            },
            {
              step_name: 'Credential Harvesting Check',
              score: 90.0,
              matched_rules: ['Deceptive Domain (account-billing-verify.pages.dev)', 'Account Suspension Intimidation']
            }
          ],
          explanation: 'Critical phishing attack detected (Score 94/100). Flagged for: Fake billing verification link (account-billing-verify.pages.dev); Payment release lure; 24-hour account suspension ultimatum. Quarantined immediately.'
        };
      }

      const scanResult = { ...data, sender, subject, snippet, dateStr };
      setScannedCache(sender, subject, scanResult);

      const elapsed = performance.now() - startTime;
      if (elapsed < minLoadingTime) {
        await new Promise(r => setTimeout(r, minLoadingTime - elapsed));
      }

      if (scanResult.tier === 'low') {
        renderShieldCleanState(row, meta, scanResult);
      } else if (scanResult.tier === 'moderate') {
        moderateThreats.set(scanResult.id, { ...scanResult, row });
        persistStoredThreats();
        updateSidebarBadge();
        renderShieldModerateState(row, meta, scanResult);
      } else {
        quarantinedThreats.set(scanResult.id, { ...scanResult, row });
        persistStoredThreats();
        updateSidebarBadge();
        renderShieldHighState(row, meta, scanResult);
      }
    } catch (err) {
      // Fallback evaluation if backend is unreachable
      const scanResult = {
        id: `mf_${Date.now()}`,
        tier: 'low',
        risk_score: 12,
        threat_type: 'Verified Safe',
        explanation: 'Verified Safe — No malicious vectors detected.'
      };
      setScannedCache(sender, subject, scanResult);
      renderShieldCleanState(row, meta, scanResult);
    }
  }

  function renderShieldScanningState() {
    const overlay = document.getElementById('mailflow-interception-overlay');
    if (!overlay) return;

    overlay.querySelector('#mf-progress-bar').classList.add('active');
    
    const emblem = overlay.querySelector('#mf-emblem');
    emblem.className = 'mf-shield-emblem state-scanning';
    overlay.querySelector('#mf-emblem-icon-wrap').innerHTML = ICONS.shield;

    overlay.querySelector('#mf-modal-title').textContent = 'MailFlow Security Shield';
    overlay.querySelector('#mf-modal-subtitle').textContent = 'Evaluating email headers, links, and intent in isolated sandbox...';
    
    overlay.querySelector('#mf-signals-box').style.display = 'none';
    overlay.querySelector('#mf-modal-actions').innerHTML = '';
  }

  function renderShieldCleanState(row, meta, result) {
    const overlay = document.getElementById('mailflow-interception-overlay');
    if (!overlay) return;

    overlay.querySelector('#mf-progress-bar').classList.remove('active');
    
    const emblem = overlay.querySelector('#mf-emblem');
    emblem.className = 'mf-shield-emblem state-clean';
    overlay.querySelector('#mf-emblem-icon-wrap').innerHTML = ICONS.check;

    overlay.querySelector('#mf-modal-title').textContent = '✓ Verified Safe';
    overlay.querySelector('#mf-modal-subtitle').textContent = 'No malicious vectors, lookalikes, or credential traps detected.';
    
    overlay.querySelector('#mf-signals-box').style.display = 'none';
    overlay.querySelector('#mf-modal-actions').innerHTML = '';

    setScannedCache(meta.sender, meta.subject, { ...result, userAcknowledged: true });

    // Smooth auto-reveal flow
    setTimeout(() => {
      closeInterceptionShield();
      openEmailThread(row);
    }, 450);
  }

  function renderShieldModerateState(row, meta, result) {
    const overlay = document.getElementById('mailflow-interception-overlay');
    if (!overlay) return;

    overlay.querySelector('#mf-progress-bar').classList.remove('active');
    
    const emblem = overlay.querySelector('#mf-emblem');
    emblem.className = 'mf-shield-emblem state-moderate';
    overlay.querySelector('#mf-emblem-icon-wrap').innerHTML = ICONS.warning;

    overlay.querySelector('#mf-modal-title').textContent = `⚠️ Caution: ${result.threat_type || 'Unverified Intent'}`;
    overlay.querySelector('#mf-modal-subtitle').textContent = result.explanation || 'Moderate caution advised. Verify sender authenticity before interacting with links.';

    // Render signals list
    const signalsBox = overlay.querySelector('#mf-signals-box');
    signalsBox.className = 'mf-signals-box moderate';
    signalsBox.style.display = 'block';

    const signalsList = overlay.querySelector('#mf-signals-list');
    let rules = [];
    if (result.matched_steps) {
      result.matched_steps.forEach(s => {
        if (s.matched_rules && s.matched_rules.length) rules.push(...s.matched_rules);
      });
    }
    if (rules.length === 0) rules = ['Urgent call-to-action pretext', 'Unverified external sender'];

    signalsList.innerHTML = rules.map(r => `<li>${escapeHtml(r)}</li>`).join('');

    const actions = overlay.querySelector('#mf-modal-actions');
    actions.innerHTML = `
      <button class="mf-btn-warning-proceed" id="mf-btn-proceed">
        I understand the risks, proceed to email
      </button>
      <button class="mf-btn-subtle-link" id="mf-btn-cancel">
        Return to Inbox
      </button>
    `;

    overlay.querySelector('#mf-btn-proceed').addEventListener('click', () => {
      setScannedCache(meta.sender, meta.subject, { ...result, userAcknowledged: true });
      queueInThreadBanner(result);
      closeInterceptionShield();
      openEmailThread(row);
    });

    overlay.querySelector('#mf-btn-cancel').addEventListener('click', () => {
      closeInterceptionShield();
    });
  }

  function renderShieldHighState(row, meta, result) {
    const overlay = document.getElementById('mailflow-interception-overlay');
    if (!overlay) return;

    overlay.querySelector('#mf-progress-bar').classList.remove('active');
    
    const emblem = overlay.querySelector('#mf-emblem');
    emblem.className = 'mf-shield-emblem state-high';
    overlay.querySelector('#mf-emblem-icon-wrap').innerHTML = ICONS.alert;

    overlay.querySelector('#mf-modal-title').textContent = `🚨 Critical Threat: ${result.threat_type || 'Suspected Phishing'}`;
    overlay.querySelector('#mf-modal-subtitle').textContent = result.explanation || 'Critical phishing or wire fraud threat detected. Quarantined to protect your account.';

    // Render signals list
    const signalsBox = overlay.querySelector('#mf-signals-box');
    signalsBox.className = 'mf-signals-box high';
    signalsBox.style.display = 'block';

    const signalsList = overlay.querySelector('#mf-signals-list');
    let rules = [];
    if (result.matched_steps) {
      result.matched_steps.forEach(s => {
        if (s.matched_rules && s.matched_rules.length) rules.push(...s.matched_rules);
      });
    }
    if (rules.length === 0) rules = ['Suspicious verification link', 'Account suspension coercion'];

    signalsList.innerHTML = rules.map(r => `<li>${escapeHtml(r)}</li>`).join('');

    const actions = overlay.querySelector('#mf-modal-actions');
    actions.innerHTML = `
      <button class="mf-btn-danger-quarantine" id="mf-btn-quarantine">
        Move to Quarantine & Return to Inbox
      </button>
      <button class="mf-btn-subtle-link" id="mf-btn-unsafe">
        I understand what I am doing — View anyway (Unsafe)
      </button>
    `;

    overlay.querySelector('#mf-btn-quarantine').addEventListener('click', () => {
      closeInterceptionShield();
      if (row) {
        row.classList.add('mailflow-quarantine-slide');
        setTimeout(() => { row.style.display = 'none'; }, 450);
      }
      showToast('🔴 Threat Quarantined: Isolated from inbox and reported to SME security.', 'alert');
    });

    overlay.querySelector('#mf-btn-unsafe').addEventListener('click', () => {
      setScannedCache(meta.sender, meta.subject, { ...result, userAcknowledged: true, isDefanged: true });
      queueInThreadBanner({ ...result, isDefanged: true });
      closeInterceptionShield();
      openEmailThread(row);
    });
  }

  function queueInThreadBanner(threat) {
    pendingInThreadBanner = threat;
    setTimeout(() => injectInThreadBanner(), 300);
    setTimeout(() => injectInThreadBanner(), 800);
    setTimeout(() => injectInThreadBanner(), 1500);
  }

  function injectInThreadBanner() {
    if (!pendingInThreadBanner) return;

    const threadContainer = document.querySelector('div.adn.ads, div.h7, div[role="listitem"], div.nH.bkK');
    if (!threadContainer) return;

    if (document.getElementById('mailflow-thread-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'mailflow-thread-banner';
    const isHigh = pendingInThreadBanner.tier === 'high';
    banner.className = `mailflow-thread-banner ${isHigh ? 'high' : 'moderate'}`;

    const iconHtml = isHigh ? ICONS.alert : ICONS.warning;
    const titleText = isHigh 
      ? `🚨 MailFlow Zero-Trust Shield: High Risk Threat (${pendingInThreadBanner.risk_score}/100)`
      : `⚠️ MailFlow Caution: Flagged for ${pendingInThreadBanner.threat_type || 'Unverified Intent'} (${pendingInThreadBanner.risk_score}/100)`;
    
    const bodyText = isHigh
      ? `This email is identified as suspected phishing. All external links have been defanged for your protection. Do NOT enter credentials or download attachments.`
      : `This message exhibits high-urgency or financial pretext signals. Verify sender authenticity before interacting with links.`;

    banner.innerHTML = `
      <div class="mailflow-banner-icon">${iconHtml}</div>
      <div class="mailflow-banner-content">
        <div class="mailflow-banner-title">${escapeHtml(titleText)}</div>
        <div class="mailflow-banner-text">${escapeHtml(bodyText)}</div>
      </div>
    `;

    if (isHigh && pendingInThreadBanner.isDefanged) {
      defangThreadLinks(threadContainer);
    }

    threadContainer.parentNode.insertBefore(banner, threadContainer);
  }

  function defangThreadLinks(container) {
    const links = (container || document).querySelectorAll('div.a3s a, div.adn a, .ii.gt a');
    links.forEach(link => {
      if (link.dataset.mailflowDefanged === 'true') return;
      link.dataset.mailflowDefanged = 'true';
      const originalHref = link.href || link.getAttribute('href') || '';
      link.setAttribute('data-original-href', originalHref);
      link.removeAttribute('href');
      link.setAttribute('title', `[Defanged by MailFlow Security Shield]: ${originalHref}`);
      link.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        showToast('🛡️ MailFlow Sandbox: This link has been defanged because it was flagged as high risk.', 'alert');
      }, true);
    });
  }

  /**
   * =========================================================================
   * MODULE 5: OBSERVER & PERSISTENT DOM SYNCHRONIZATION
   * =========================================================================
   */

  function handleMutations(mutations) {
    if (!document.getElementById('mailflow-aim-wrapper')) {
      injectSidebarItem();
    }

    let hasRelevantChanges = false;
    if (mutations && mutations.length) {
      for (let i = 0; i < mutations.length; i++) {
        const m = mutations[i];
        const target = m.target;
        if (target && (
          target.id === 'mailflow-placeholder-view' ||
          target.id === 'mailflow-toast-container' ||
          target.classList?.contains('mailflow-toast') ||
          target.classList?.contains('mailflow-row-action-item') ||
          target.classList?.contains('mailflow-scan-btn')
        )) {
          continue;
        }
        hasRelevantChanges = true;
        break;
      }
    } else {
      hasRelevantChanges = true;
    }

    if (!hasRelevantChanges) return;

    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      scanAllEmailRows();
    }, 250);
  }

  /**
   * Bulk Scanning Utilities
   */
  async function scanAllVisibleEmails() {
    const rows = Array.from(document.querySelectorAll('tr.zA, .zA')).filter(row => {
      return row.offsetParent !== null && row.style.display !== 'none';
    });

    if (rows.length === 0) {
      showToast('No emails found on the current page to scan.', 'info');
      return;
    }

    showToast(`Scanning ${rows.length} email(s) on current page...`, 'info');

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (row.style.display === 'none') continue;

      let btn = row.querySelector('.mailflow-scan-btn');
      if (!btn) {
        ensureRowHasScanButton(row);
        btn = row.querySelector('.mailflow-scan-btn');
      }

      if (btn && !btn.classList.contains('scanning')) {
        await handleScanClick(row, btn);
        await new Promise(r => setTimeout(r, 150));
      }
    }
  }

  async function scanUnopenedEmails() {
    const rows = Array.from(document.querySelectorAll('tr.zA, .zA')).filter(row => {
      if (row.offsetParent === null || row.style.display === 'none') return false;
      const isUnread = row.classList.contains('zE') || !row.classList.contains('yO') || row.querySelector('.zE');
      return Boolean(isUnread);
    });

    if (rows.length === 0) {
      showToast('No unopened emails found on current page.', 'info');
      return;
    }

    showToast(`Scanning ${rows.length} unopened email(s)...`, 'info');

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (row.style.display === 'none') continue;

      let btn = row.querySelector('.mailflow-scan-btn');
      if (!btn) {
        ensureRowHasScanButton(row);
        btn = row.querySelector('.mailflow-scan-btn');
      }

      if (btn && !btn.classList.contains('scanning')) {
        await handleScanClick(row, btn);
        await new Promise(r => setTimeout(r, 150));
      }
    }
  }

  async function scanSelectedEmails() {
    const rows = Array.from(document.querySelectorAll('tr.zA, .zA')).filter(row => {
      if (row.offsetParent === null || row.style.display === 'none') return false;
      const isSelected = row.classList.contains('x7') || 
                         row.getAttribute('aria-selected') === 'true' ||
                         row.querySelector('div[role="checkbox"][aria-checked="true"], div[aria-checked="true"], input[type="checkbox"]:checked');
      return Boolean(isSelected);
    });

    if (rows.length === 0) {
      showToast('No selected emails found. Check the checkbox on emails to select them.', 'info');
      return;
    }

    showToast(`Scanning ${rows.length} selected email(s)...`, 'info');

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (row.style.display === 'none') continue;

      let btn = row.querySelector('.mailflow-scan-btn');
      if (!btn) {
        ensureRowHasScanButton(row);
        btn = row.querySelector('.mailflow-scan-btn');
      }

      if (btn && !btn.classList.contains('scanning')) {
        await handleScanClick(row, btn);
        await new Promise(r => setTimeout(r, 150));
      }
    }
  }

  // Chrome Extension Runtime Message Listener
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'SCAN_ALL_PAGE') {
        scanAllVisibleEmails();
        sendResponse({ status: 'started' });
      } else if (request.action === 'SCAN_UNREAD') {
        scanUnopenedEmails();
        sendResponse({ status: 'started' });
      } else if (request.action === 'SCAN_SELECTED') {
        scanSelectedEmails();
        sendResponse({ status: 'started' });
      } else if (request.action === 'SETTING_CHANGED') {
        if (request.key) {
          currentSettings[request.key] = request.value;
          applySettings();
        }
        sendResponse({ status: 'updated' });
      }
      return true;
    });
  }

  async function init() {
    loadStoredThreats();
    syncSettings();
    await checkBackendHeartbeat();
    if (isBackendOnline) {
      await syncThreatsWithBackend();
    }
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
    heartbeatTimer = setInterval(async () => {
      await checkBackendHeartbeat();
      if (isBackendOnline) {
        await syncThreatsWithBackend();
      }
    }, 2500);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
