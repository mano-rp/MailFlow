/**
 * MailFlow Chrome Extension - Content Script (Sprint 1)
 * Native Gmail DOM Injections & Real-Time Security Integration
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  let isMailFlowTabActive = false;
  let observer = null;

  // SVG Icons
  const ICONS = {
    shield: `<svg class="mailflow-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`,
    shieldHeader: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0b57d0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
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
   * MODULE 1: SIDEBAR NAVIGATION INJECTION
   * =========================================================================
   */

  function findSidebarContainer() {
    // Priority search for standard Gmail left nav list container
    const nav = document.querySelector('div[role="navigation"]');
    if (!nav) return null;

    // Look for Gmail's item group list container (.TK, .wT, .aim parent)
    const tkList = nav.querySelector('div.TK') || 
                   nav.querySelector('.wT') || 
                   nav.querySelector('div.aeN') || 
                   nav.querySelector('.ajl');
    
    if (tkList) return tkList;

    // Fallback: parent of inbox / any .aim item
    const aimItem = nav.querySelector('.aim') || nav.querySelector('.TO');
    if (aimItem && aimItem.parentElement) {
      return aimItem.parentElement;
    }

    return nav;
  }

  function injectSidebarItem() {
    if (document.getElementById('mailflow-sidebar-nav-item')) {
      return; // Already injected
    }

    const sidebarContainer = findSidebarContainer();
    if (!sidebarContainer) return;

    // Create native Gmail-styled navigation item
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

    // Click handler for tab switching
    navItem.addEventListener('click', (e) => {
      e.stopPropagation();
      activateMailFlowView();
    });

    // Insert after standard top folders or at top of the navigation list
    const draftsItem = sidebarContainer.querySelector('a[href*="#drafts"]') || 
                       sidebarContainer.querySelector('div[data-tooltip*="Drafts"]') ||
                       sidebarContainer.querySelector('div.aim:nth-child(5)');

    if (draftsItem && draftsItem.closest('.aim')) {
      draftsItem.closest('.aim').after(navItem);
    } else {
      sidebarContainer.appendChild(navItem);
    }

    // Attach listener to native Gmail items to reset MailFlow tab when clicked
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
   * MODULE 2: MAILFLOW HUB / TRIAGE CONTAINER
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

    // Deselect Gmail's native active items visually
    document.querySelectorAll('div[role="navigation"] .nZ, div[role="navigation"] .active').forEach(el => {
      if (el.id !== 'mailflow-sidebar-nav-item') {
        el.classList.remove('nZ');
      }
    });

    const mainContainer = getMainContainer();
    if (!mainContainer) return;

    // Hide native mail list tables
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

    // Button event listeners
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
        } else {
          button.innerHTML = `<span style="color: #d93025;">⚠️ HTTP ${res.status}</span>`;
        }
      } catch (e) {
        button.innerHTML = `<span style="color: #d93025;">○ Backend Offline</span>`;
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
   * OBSERVER & INITIALIZATION
   * =========================================================================
   */

  function init() {
    injectSidebarItem();

    if (observer) observer.disconnect();

    observer = new MutationObserver((mutations) => {
      // Re-inject sidebar if removed during Gmail route switches
      if (!document.getElementById('mailflow-sidebar-nav-item')) {
        injectSidebarItem();
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  // Run on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
