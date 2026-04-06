/**
 * LLM Security Testing Framework — Dashboard JavaScript
 * April 2026 Version
 */

const BACKEND_URL = 'https://ethical-hacking-framework-tests.onrender.com';

/* ─────────────────────────────────────────────
   STATE - Updated for 2026 Models
───────────────────────────────────────────── */
const state = {
  config: {
    provider: 'groq',
    apiKey: '',
    baseUrl: '',
    model: 'llama-3.3-70b-versatile', // Updated 2026 standard
    systemPrompt: '',
    maxTokens: 1000,
    temperature: 0.7,
    testsPerCategory: 10,
    delayMs: 500,
    timeoutS: 60,
    stopOnCritical: false,
    scanProfile: 'all',
  },
  selectedPayloads: new Set(),
  scanRunning: false,
  results: [],
  report: null,
  sessionStats: { testsRun: 0, vulns: 0, riskScore: null, duration: null },
  pollInterval: null,
  scanStartTime: null,
};

/* ─────────────────────────────────────────────
   PROVIDER → MODEL MAP (Verified April 2026)
───────────────────────────────────────────── */
const PROVIDER_MODELS = {
  openai:    ['gpt-oss-120b', 'gpt-4o', 'gpt-4o-mini'],
  anthropic: ['claude-3-5-sonnet-latest', 'claude-3-opus-latest'],
  gemini:    ['gemini-1.5-pro', 'gemini-1.5-flash'],
  groq:      [
    'llama-3.3-70b-versatile', 
    'llama-3.1-8b-instant', 
    'gemma-4-26b-it', 
    'mixtral-8x7b-32768'
  ],
  mistral:   ['mistral-large-latest', 'mistral-small-3.1-24b-instruct'],
  custom:    ['custom-model'],
};

/* ─────────────────────────────────────────────
   UTILITY & CORE LOGIC
───────────────────────────────────────────── */
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];
const esc = s => String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;');

function log(level, msg) {
  const logEl = $('#execution-log');
  if (!logEl) return;
  const now = new Date();
  const ts = now.toTimeString().slice(0,5);
  const colors = { INFO:'#5a7a8a', OK:'#00ffb3', WARN:'#ffb020', ERR:'#ff3c5a', RUN:'#00c8ff' };
  const color = colors[level] || colors.INFO;
  const line = document.createElement('div');
  line.innerHTML = `<span style="color:var(--text2)">${ts}</span> <span style="color:${color};font-weight:700">${level}</span> <span>${esc(msg)}</span>`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function setNav(section) {
  $$('.nav-item').forEach(el => el.classList.remove('active'));
  $$('.section-panel').forEach(el => el.style.display = 'none');
  const navEl = $(`.nav-item[data-section="${section}"]`);
  const panelEl = $(`#panel-${section}`);
  if (navEl) navEl.classList.add('active');
  if (panelEl) panelEl.style.display = 'block';
}

function updateSessionStats() {
  const s = state.sessionStats;
  const el = id => document.getElementById(id);
  if (el('stat-tests-run'))  el('stat-tests-run').textContent  = s.testsRun;
  if (el('stat-vulns'))      el('stat-vulns').textContent      = s.vulns;
  if (el('stat-risk'))       el('stat-risk').textContent       = s.riskScore ?? '—';
  if (el('stat-duration'))   el('stat-duration').textContent   = s.duration  ?? '—';
}

/* ─────────────────────────────────────────────
   CONFIG FORM
───────────────────────────────────────────── */
function initConfigForm() {
  const providerSel = $('#provider-select');
  const modelSel    = $('#model-select');
  const baseUrlRow  = $('#base-url-row');
  const apiKeyInput = $('#api-key-input');
  const toggleKey   = $('#toggle-api-key');

  if (providerSel && modelSel) {
    providerSel.addEventListener('change', () => {
      const prov = providerSel.value;
      state.config.provider = prov;
      const models = PROVIDER_MODELS[prov] || ['custom-model'];
      modelSel.innerHTML = models.map(m => `<option value="${m}">${m}</option>`).join('');
      state.config.model = models[0];
      if (baseUrlRow) baseUrlRow.style.display = prov === 'custom' ? 'block' : 'none';
    });
    modelSel.addEventListener('change', () => { state.config.model = modelSel.value; });
  }

  if (toggleKey && apiKeyInput) {
    toggleKey.addEventListener('click', () => {
      apiKeyInput.type = apiKeyInput.type === 'password' ? 'text' : 'password';
      toggleKey.textContent = apiKeyInput.type === 'password' ? '👁' : '🙈';
    });
  }

  // FIXED: Strict numeric conversion for API compatibility
  const bindings = [
    ['#api-key-input',        'apiKey',           'input'],
    ['#base-url-input',       'baseUrl',          'input'],
    ['#system-prompt-input',  'systemPrompt',     'input'],
    ['#max-tokens-input',     'maxTokens',        'input', (v) => parseInt(v) || 1000],
    ['#temperature-input',    'temperature',      'input', (v) => parseFloat(v) || 0.7],
    ['#tests-per-cat-input',  'testsPerCategory', 'input', (v) => parseInt(v) || 10],
    ['#delay-input',          'delayMs',          'input', (v) => parseInt(v) || 500],
    ['#timeout-input',        'timeoutS',         'input', (v) => parseInt(v) || 60],
    ['#stop-on-critical',     'stopOnCritical',   'change', Boolean, true],
  ];

  bindings.forEach(([sel, key, evt, cast, isCheck]) => {
    const el = $(sel);
    if (!el) return;
    el.addEventListener(evt, () => {
      const raw = isCheck ? el.checked : el.value;
      state.config[key] = cast ? cast(raw) : raw;
    });
  });

  $$('input[name="scan-profile"]').forEach(radio => {
    radio.addEventListener('change', () => {
      state.config.scanProfile = radio.value;
      updatePayloadSuiteFromProfile(radio.value);
    });
  });

  $('#test-connection-btn')?.addEventListener('click', testConnection);
}

async function testConnection() {
  const btn = $('#test-connection-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Testing...'; }
  log('RUN', `Connecting to ${state.config.provider}...`);
  try {
    const res = await fetch(`${BACKEND_URL}/api/test-connection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider:   state.config.provider,
        api_key:    state.config.apiKey.trim(),
        model:      state.config.model,
        base_url:   state.config.baseUrl,
      }),
    });
    const data = await res.json();
    if (data.success) {
      log('OK', `Connected successfully.`);
      updateTopbarStatus('connected', `${state.config.provider} · ${state.config.model}`);
    } else {
      log('ERR', `Error: ${data.error}`);
      updateTopbarStatus('error', 'Connection failed');
    }
  } catch (err) {
    log('ERR', `Backend unreachable. Render might be booting up.`);
    updateTopbarStatus('error', 'Backend offline');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⟳ Test Connection'; }
  }
}

function updateTopbarStatus(state_, label) {
  const pip = $('.pip');
  const label_ = $('.topbar-status span');
  if (!pip || !label_) return;
  const colors = { connected:'#00ffb3', error:'#ff3c5a', scanning:'#00c8ff', idle:'#5a7a8a' };
  pip.style.background = colors[state_] || colors.idle;
  label_.textContent = label;
}

/* ─────────────────────────────────────────────
   SCAN EXECUTION
───────────────────────────────────────────── */
async function startScan() {
  if (state.scanRunning) return;
  if (!state.config.apiKey) { log('ERR', 'Missing API Key.'); setNav('config'); return; }

  state.scanRunning = true;
  state.results = [];
  state.scanStartTime = Date.now();
  updateScanUI(true);
  updateTopbarStatus('scanning', 'Scanning...');
  log('RUN', `Starting Scan with model: ${state.config.model}`);

  try {
    const res = await fetch(`${BACKEND_URL}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...state.config,
        selected_payloads: [...state.selectedPayloads]
      }),
    });
    const data = await res.json();
    if (data.success) startPolling(data.scan_id);
    else scanFinished(false);
  } catch (err) {
    log('ERR', 'Scan failed to start.');
    scanFinished(false);
  }
}

// ... Rest of your UI utility functions (appendResultRow, filter, etc) are unchanged and should stay ...

/* ─────────────────────────────────────────────
   INIT
───────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  log('INFO', 'System Ready.');
  initConfigForm();
  initScanControls();
  setNav('config');
});
