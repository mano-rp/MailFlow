// MailFlow Shield Popup Controller

const API_BASE_URL = 'http://localhost:8000';

const DOM = {
  connectionPill: document.getElementById('connection-pill'),
  connectionText: document.getElementById('connection-text'),
  btnPing: document.getElementById('btn-ping'),
  btnPingText: document.getElementById('btn-ping-text'),
  btnReload: document.getElementById('btn-reload'),
  pingResultBox: document.getElementById('ping-result-box'),
  pingDot: document.getElementById('ping-dot'),
  pingSummary: document.getElementById('ping-summary'),
  pingLatency: document.getElementById('ping-latency'),
  pingMeta: document.getElementById('ping-meta'),
  toggleAutoscan: document.getElementById('toggle-autoscan'),
  toggleDefang: document.getElementById('toggle-defang'),
  toggleInlinerow: document.getElementById('toggle-inlinerow'),
};

const DEFAULT_SETTINGS = {
  autoScan: true,
  defangLinks: true,
  showInlineRows: true,
};

// Storage helper (supports chrome.storage.sync with fallback)
const storage = {
  get: (keys) => {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
        chrome.storage.sync.get(keys, resolve);
      } else if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(keys, resolve);
      } else {
        const result = {};
        for (const key of Object.keys(keys)) {
          const val = localStorage.getItem(key);
          result[key] = val !== null ? JSON.parse(val) : keys[key];
        }
        resolve(result);
      }
    });
  },
  set: (items) => {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
        chrome.storage.sync.set(items, resolve);
      } else if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set(items, resolve);
      } else {
        for (const [k, v] of Object.entries(items)) {
          localStorage.setItem(k, JSON.stringify(v));
        }
        resolve();
      }
    });
  },
};

// Initialize settings
async function initSettings() {
  const saved = await storage.get(DEFAULT_SETTINGS);
  DOM.toggleAutoscan.checked = saved.autoScan ?? true;
  DOM.toggleDefang.checked = saved.defangLinks ?? true;
  DOM.toggleInlinerow.checked = saved.showInlineRows ?? true;

  DOM.toggleAutoscan.addEventListener('change', (e) => {
    storage.set({ autoScan: e.target.checked });
  });

  DOM.toggleDefang.addEventListener('change', (e) => {
    storage.set({ defangLinks: e.target.checked });
  });

  DOM.toggleInlinerow.addEventListener('change', (e) => {
    storage.set({ showInlineRows: e.target.checked });
  });
}

// Test Ping Handler
async function performPing() {
  const startTime = performance.now();

  // Set UI to pinging state
  DOM.connectionPill.className = 'status-pill checking';
  DOM.connectionText.textContent = 'Pinging...';
  DOM.pingDot.className = 'ping-indicator-dot pinging';
  DOM.pingSummary.textContent = 'Contacting backend API...';
  DOM.pingLatency.textContent = '...';
  DOM.btnPing.disabled = true;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const response = await fetch(`${API_BASE_URL}/api/ping`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const endTime = performance.now();
    const latency = Math.round(endTime - startTime);

    if (response.ok) {
      const data = await response.json();
      // Update Connection Pill
      DOM.connectionPill.className = 'status-pill connected';
      DOM.connectionText.textContent = '● Connected (:8000)';

      // Update Result Box
      DOM.pingDot.className = 'ping-indicator-dot online';
      DOM.pingSummary.textContent = `Online (${data.status.toUpperCase()})`;
      DOM.pingLatency.textContent = `${latency} ms`;
      DOM.pingMeta.textContent = `v${data.version || '0.1.0'} · Response OK at ${new Date(data.timestamp || Date.now()).toLocaleTimeString()}`;
    } else {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
  } catch (err) {
    const endTime = performance.now();
    const latency = Math.round(endTime - startTime);

    // Update Connection Pill
    DOM.connectionPill.className = 'status-pill disconnected';
    DOM.connectionText.textContent = '○ Disconnected';

    // Update Result Box
    DOM.pingDot.className = 'ping-indicator-dot offline';
    DOM.pingSummary.textContent = 'Backend Offline';
    DOM.pingLatency.textContent = `${latency} ms`;
    DOM.pingMeta.textContent = `Cannot reach ${API_BASE_URL}/api/ping (${err.name === 'AbortError' ? 'Timeout' : 'Offline'})`;
  } finally {
    DOM.btnPing.disabled = false;
  }
}

// Reload active tab
async function reloadTab() {
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        chrome.tabs.reload(tabs[0].id);
        const originalText = DOM.btnReload.innerHTML;
        DOM.btnReload.innerHTML = `<span>Reloaded!</span>`;
        setTimeout(() => {
          DOM.btnReload.innerHTML = originalText;
        }, 1200);
      }
    });
  } else {
    window.location.reload();
  }
}

// Attach event listeners
DOM.btnPing.addEventListener('click', performPing);
DOM.btnReload.addEventListener('click', reloadTab);

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initSettings();
  performPing();
});
