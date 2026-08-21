// MailFlow Shield - Settings Popup Controller

const API_BASE_URL = 'http://localhost:8000';

const DOM = {
  html: document.documentElement,
  statusCard: document.getElementById('status-card'),
  statusTitle: document.getElementById('status-title'),
  statusSubtitle: document.getElementById('status-subtitle'),
  statusLatency: document.getElementById('status-latency'),
  btnCheckConnection: document.getElementById('btn-check-connection'),
  offlineBanner: document.getElementById('offline-banner'),
  toggleInlineScan: document.getElementById('toggle-inline-scan'),
  toggleAutoShield: document.getElementById('toggle-auto-shield'),
  themeBtnLight: document.getElementById('theme-btn-light'),
  themeBtnDark: document.getElementById('theme-btn-dark'),
};

const DEFAULT_SETTINGS = {
  theme: 'light',
  showInlineRows: true,
  autoScan: true,
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
  const start = performance.now();

  DOM.statusCard.className = 'status-card checking';
  DOM.statusTitle.textContent = 'Checking connection...';
  DOM.statusSubtitle.textContent = 'http://localhost:8000';
  DOM.statusLatency.textContent = '...';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);

    const res = await fetch(`${API_BASE_URL}/api/ping`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const elapsed = Math.round(performance.now() - start);

    if (res.ok) {
      const data = await res.json();
      DOM.statusCard.className = 'status-card connected';
      DOM.statusTitle.textContent = '● Connected';
      DOM.statusSubtitle.textContent = `Backend online (v${data.version || '0.1.0'})`;
      DOM.statusLatency.textContent = `${elapsed} ms`;
      DOM.offlineBanner.classList.add('hidden');
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    DOM.statusCard.className = 'status-card disconnected';
    DOM.statusTitle.textContent = '○ Disconnected';
    DOM.statusSubtitle.textContent = 'Backend offline (:8000)';
    DOM.statusLatency.textContent = '-- ms';
    DOM.offlineBanner.classList.remove('hidden');
  }
}

// Initialize Popup
async function init() {
  const settings = await storage.get(DEFAULT_SETTINGS);

  // Apply Theme
  const currentTheme = settings.theme || 'light';
  setTheme(currentTheme);

  // Apply Toggle Settings
  DOM.toggleInlineScan.checked = settings.showInlineRows ?? true;
  DOM.toggleAutoShield.checked = settings.autoScan ?? true;

  // Listeners
  DOM.themeBtnLight.addEventListener('click', () => setTheme('light'));
  DOM.themeBtnDark.addEventListener('click', () => setTheme('dark'));

  DOM.toggleInlineScan.addEventListener('change', (e) => {
    storage.set({ showInlineRows: e.target.checked });
  });

  DOM.toggleAutoShield.addEventListener('change', (e) => {
    storage.set({ autoScan: e.target.checked });
  });

  DOM.btnCheckConnection.addEventListener('click', checkBackendHealth);

  checkBackendHealth();
}

document.addEventListener('DOMContentLoaded', init);
