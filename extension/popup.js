// MailFlow Shield - Minimalist Settings & Quick Scans Controller

const API_BASE_URL = 'http://localhost:8000';

const DOM = {
  html: document.documentElement,
  statusDot: document.getElementById('status-dot'),
  statusText: document.getElementById('status-text'),
  btnCheckConnection: document.getElementById('btn-check-connection'),
  btnScanPage: document.getElementById('btn-scan-page'),
  btnScanUnread: document.getElementById('btn-scan-unread'),
  btnScanSelected: document.getElementById('btn-scan-selected'),
  toggleAutoforward: document.getElementById('toggle-autoforward'),
  themeBtnLight: document.getElementById('theme-btn-light'),
  themeBtnDark: document.getElementById('theme-btn-dark'),
};

const DEFAULT_SETTINGS = {
  theme: 'light',
  autoForwardAdmin: false,
};

// Storage helper with fallback
const storage = {
  get: (keys) => {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        const area = chrome.storage.sync || chrome.storage.local;
        area.get(keys, resolve);
      } else {
        const res = {};
        for (const k of Object.keys(keys)) {
          const v = localStorage.getItem(k);
          res[k] = v !== null ? JSON.parse(v) : keys[k];
        }
        resolve(res);
      }
    });
  },
  set: (items) => {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        const area = chrome.storage.sync || chrome.storage.local;
        area.set(items, resolve);
      } else {
        for (const [k, v] of Object.entries(items)) {
          localStorage.setItem(k, JSON.stringify(v));
        }
        resolve();
      }
    });
  }
};

// Theme Management
function setTheme(theme) {
  DOM.html.setAttribute('data-theme', theme);
  if (theme === 'dark') {
    DOM.themeBtnDark.classList.add('active');
    DOM.themeBtnDark.setAttribute('aria-checked', 'true');
    DOM.themeBtnLight.classList.remove('active');
    DOM.themeBtnLight.setAttribute('aria-checked', 'false');
  } else {
    DOM.themeBtnLight.classList.add('active');
    DOM.themeBtnLight.setAttribute('aria-checked', 'true');
    DOM.themeBtnDark.classList.remove('active');
    DOM.themeBtnDark.setAttribute('aria-checked', 'false');
  }
  storage.set({ theme });
}

// Backend Health Verification
async function checkBackendHealth() {
  DOM.statusDot.className = 'status-dot checking';
  DOM.statusText.textContent = 'MailFlow Server';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`${API_BASE_URL}/api/ping`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.ok) {
      DOM.statusDot.className = 'status-dot protected';
      DOM.statusText.textContent = 'MailFlow Server';
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    DOM.statusDot.className = 'status-dot offline';
    DOM.statusText.textContent = 'MailFlow Server';
  }
}

// Send command to active tab
function triggerTabAction(action) {
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].id) {
        chrome.tabs.sendMessage(tabs[0].id, { action: action }, () => {
          // Close popup after dispatching
          window.close();
        });
      }
    });
  }
}

// Initialize Popup
async function init() {
  const settings = await storage.get(DEFAULT_SETTINGS);

  // Apply Theme
  const currentTheme = settings.theme || 'light';
  setTheme(currentTheme);

  // Apply Autoforward Toggle
  if (DOM.toggleAutoforward) {
    DOM.toggleAutoforward.checked = settings.autoForwardAdmin ?? false;
    DOM.toggleAutoforward.addEventListener('change', (e) => {
      storage.set({ autoForwardAdmin: e.target.checked });
    });
  }

  // Listeners
  DOM.themeBtnLight.addEventListener('click', () => setTheme('light'));
  DOM.themeBtnDark.addEventListener('click', () => setTheme('dark'));
  DOM.btnCheckConnection.addEventListener('click', checkBackendHealth);

  if (DOM.btnScanPage) {
    DOM.btnScanPage.addEventListener('click', () => triggerTabAction('SCAN_ALL_PAGE'));
  }

  if (DOM.btnScanUnread) {
    DOM.btnScanUnread.addEventListener('click', () => triggerTabAction('SCAN_UNREAD'));
  }

  if (DOM.btnScanSelected) {
    DOM.btnScanSelected.addEventListener('click', () => triggerTabAction('SCAN_SELECTED'));
  }

  checkBackendHealth();
}

document.addEventListener('DOMContentLoaded', init);
