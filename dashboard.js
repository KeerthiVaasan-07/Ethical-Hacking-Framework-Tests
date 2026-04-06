/**
 * LLM Security Testing Framework — Dashboard JavaScript
 * Connects frontend dashboard to Flask backend (api.py)
 * Handles: config form, payload selection, scan execution,
 *          real-time progress, results display, report generation
 *
 * Flask backend expected at: http://localhost:5000
 * Change BACKEND_URL below after deploying to Render/Railway.
 */

const BACKEND_URL = 'https://ethical-hacking-framework-tests.onrender.com';

/* ─────────────────────────────────────────────
   STATE
───────────────────────────────────────────── */
const state = {
  config: {
    provider: 'groq',
    apiKey: '',
    baseUrl: '',
    model: 'gpt-4o',
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
   PROVIDER → MODEL MAP
───────────────────────────────────────────── */
const PROVIDER_MODELS = {
  openai:    ['gpt-4o', 'gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo'],
  anthropic: ['claude-opus-4-6', 'claude-sonnet-4-6', 'claude-haiku-4-5-20251001'],
  gemini:    ['gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-pro'],
  mistral:   ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest'],
  cohere:    ['command-r-plus', 'command-r', 'command'],
  groq:      ['llama3-70b-8192', 'llama3-8b-8192', 'mixtral-8x7b-32768'],
  custom:    ['custom-model'],
};

/* ─────────────────────────────────────────────
   UTILITY
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

  // sidebar category counts
  state.results.forEach(() => {});
  const catCounts = {};
  state.results.forEach(r => {
    catCounts[r.category] = (catCounts[r.category] || 0) + 1;
  });
  Object.entries(catCounts).forEach(([cat, n]) => {
    const badge = $(`.nav-item[data-section="run"] .badge`); // generic fallback
    const catBadge = $(`.nav-cat[data-cat="${cat}"] .badge`);
    if (catBadge) catBadge.textContent = n;
  });
}

/* ─────────────────────────────────────────────
   CONFIG FORM
───────────────────────────────────────────── */
function initConfigForm() {
  // Provider change → update model dropdown
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

  // Toggle API key visibility
  if (toggleKey && apiKeyInput) {
    toggleKey.addEventListener('click', () => {
      apiKeyInput.type = apiKeyInput.type === 'password' ? 'text' : 'password';
      toggleKey.textContent = apiKeyInput.type === 'password' ? '👁' : '🙈';
    });
  }

  // Sync all config inputs
  const bindings = [
    ['#api-key-input',        'apiKey',           'input'],
    ['#base-url-input',       'baseUrl',          'input'],
    ['#system-prompt-input',  'systemPrompt',     'input'],
    ['#max-tokens-input',     'maxTokens',        'input',  Number],
    ['#temperature-input',    'temperature',      'input',  Number],
    ['#tests-per-cat-input',  'testsPerCategory', 'input',  Number],
    ['#delay-input',          'delayMs',          'input',  Number],
    ['#timeout-input',        'timeoutS',         'input',  Number],
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

  // Scan profile radio buttons
  $$('input[name="scan-profile"]').forEach(radio => {
    radio.addEventListener('change', () => {
      state.config.scanProfile = radio.value;
      updatePayloadSuiteFromProfile(radio.value);
    });
  });

  // Test Connection button
  const testConnBtn = $('#test-connection-btn');
  if (testConnBtn) {
    testConnBtn.addEventListener('click', testConnection);
  }
}

async function testConnection() {
  const btn = $('#test-connection-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Testing...'; }
  log('RUN', `Testing connection to ${state.config.provider}...`);
  try {
    const res = await fetch(`${BACKEND_URL}/api/test-connection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider:   state.config.provider,
        api_key:    state.config.apiKey,
        model:      state.config.model,
        base_url:   state.config.baseUrl,
      }),
    });
    const data = await res.json();
    if (data.success) {
      log('OK', `Connection successful — model: ${data.model || state.config.model}`);
      updateTopbarStatus('connected', `${state.config.provider} · ${state.config.model}`);
    } else {
      log('ERR', `Connection failed: ${data.error || 'Unknown error'}`);
      updateTopbarStatus('error', 'Connection failed');
    }
  } catch (err) {
    log('ERR', `Cannot reach backend at ${BACKEND_URL} — is Flask running? (${err.message})`);
    updateTopbarStatus('error', 'Backend offline');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⟳ Test Connection'; }
  }
}

function updateTopbarStatus(state_, label) {
  const pip   = $('.pip');
  const label_ = $('.topbar-status span');
  if (!pip || !label_) return;
  const colors = { connected:'#00ffb3', error:'#ff3c5a', scanning:'#00c8ff', idle:'#5a7a8a' };
  pip.style.background  = colors[state_] || colors.idle;
  pip.style.boxShadow   = `0 0 6px ${colors[state_] || colors.idle}`;
  label_.textContent = label;
}

/* ─────────────────────────────────────────────
   PAYLOAD SUITE
───────────────────────────────────────────── */
const CATEGORIES = ['prompt_injection','api_attacks','unlimited_dos','image_injection','vector_attack','vector_embed'];
const CAT_LABELS = {
  prompt_injection: 'Prompt Injection',
  api_attacks:      'API Attacks',
  unlimited_dos:    'Unlimited/DoS',
  image_injection:  'Image Injection',
  vector_attack:    'Vector Attack',
  vector_embed:     'Vector Embed',
};

async function loadPayloads() {
  try {
    const res  = await fetch(`${BACKEND_URL}/api/payloads`);
    const data = await res.json();
    renderPayloadSuite(data.payloads || []);
  } catch {
    // Backend offline — show static placeholder payloads
    renderPayloadSuite(getDefaultPayloads());
  }
}

function getDefaultPayloads() {
  const payloads = [];
  CATEGORIES.forEach(cat => {
    for (let i = 1; i <= 10; i++) {
      payloads.push({ id: `${cat}_${i}`, category: cat, name: `${CAT_LABELS[cat]} Test ${i}`, severity: i <= 3 ? 'critical' : i <= 6 ? 'high' : 'medium' });
    }
  });
  return payloads;
}

function renderPayloadSuite(payloads) {
  const container = $('#payload-list');
  if (!container) return;

  // Group by category
  const grouped = {};
  payloads.forEach(p => {
    if (!grouped[p.category]) grouped[p.category] = [];
    grouped[p.category].push(p);
  });

  container.innerHTML = Object.entries(grouped).map(([cat, items]) => `
    <div class="payload-group" data-cat="${cat}">
      <div class="payload-group-hd">
        <label class="payload-check-all">
          <input type="checkbox" class="cat-check-all" data-cat="${cat}" />
          <span class="sec-title" style="font-size:13px">${CAT_LABELS[cat] || cat}</span>
        </label>
        <span class="sec-num">${items.length} tests</span>
      </div>
      <div class="payload-items">
        ${items.map(p => `
          <label class="payload-item" data-id="${p.id}">
            <input type="checkbox" class="payload-cb" value="${p.id}" data-cat="${cat}" />
            <span class="payload-name">${esc(p.name)}</span>
            <span class="card-tag ${severityClass(p.severity)}">${p.severity}</span>
          </label>
        `).join('')}
      </div>
    </div>
  `).join('');

  // Select/deselect all in category
  $$('.cat-check-all').forEach(cb => {
    cb.addEventListener('change', () => {
      const cat = cb.dataset.cat;
      $$(`input.payload-cb[data-cat="${cat}"]`).forEach(c => {
        c.checked = cb.checked;
        cb.checked ? state.selectedPayloads.add(c.value) : state.selectedPayloads.delete(c.value);
      });
      updatePayloadCount();
    });
  });

  // Individual checkboxes
  $$('.payload-cb').forEach(cb => {
    cb.addEventListener('change', () => {
      cb.checked ? state.selectedPayloads.add(cb.value) : state.selectedPayloads.delete(cb.value);
      updatePayloadCount();
    });
  });

  updatePayloadCount();
}

function severityClass(sev) {
  return { critical:'', high:'amber', medium:'green', low:'blue' }[sev] || '';
}

function updatePayloadCount() {
  const el = $('#payload-count');
  const total = $$('.payload-cb').length;
  if (el) el.textContent = `${state.selectedPayloads.size} payloads selected · ${total} total test cases`;
}

function updatePayloadSuiteFromProfile(profile) {
  const map = {
    prompt:  ['prompt_injection'],
    api:     ['api_attacks'],
    image:   ['image_injection'],
    all:     CATEGORIES,
    custom:  [],
  };
  const cats = map[profile] || CATEGORIES;
  $$('.payload-cb').forEach(cb => {
    const shouldCheck = cats.includes(cb.dataset.cat);
    cb.checked = shouldCheck;
    shouldCheck ? state.selectedPayloads.add(cb.value) : state.selectedPayloads.delete(cb.value);
  });
  $$('.cat-check-all').forEach(cb => {
    cb.checked = cats.includes(cb.dataset.cat);
  });
  updatePayloadCount();
}

/* ─────────────────────────────────────────────
   SELECT ALL / CLEAR BUTTONS
───────────────────────────────────────────── */
function initPayloadControls() {
  $('#select-all-btn')?.addEventListener('click', () => {
    $$('.payload-cb').forEach(cb => { cb.checked = true; state.selectedPayloads.add(cb.value); });
    $$('.cat-check-all').forEach(cb => cb.checked = true);
    updatePayloadCount();
  });
  $('#clear-all-btn')?.addEventListener('click', () => {
    $$('.payload-cb').forEach(cb => { cb.checked = false; });
    $$('.cat-check-all').forEach(cb => cb.checked = false);
    state.selectedPayloads.clear();
    updatePayloadCount();
  });
  // Category filter tabs
  $$('.payload-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $$('.payload-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const cat = tab.dataset.cat;
      $$('.payload-group').forEach(g => {
        g.style.display = (cat === 'all' || g.dataset.cat === cat) ? 'block' : 'none';
      });
    });
  });
}

/* ─────────────────────────────────────────────
   SCAN EXECUTION
───────────────────────────────────────────── */
function initScanControls() {
  $('#start-scan-btn')?.addEventListener('click', startScan);
  $('#abort-scan-btn')?.addEventListener('click', abortScan);
  $('#clear-log-btn')?.addEventListener('click', () => {
    const logEl = $('#execution-log');
    if (logEl) logEl.innerHTML = '';
  });
}

async function startScan() {
  if (state.scanRunning) return;
  if (!state.config.apiKey) {
    log('ERR', 'No API key configured. Go to Configuration first.');
    setNav('config');
    return;
  }
  if (state.selectedPayloads.size === 0 && state.config.scanProfile === 'custom') {
    log('WARN', 'No payloads selected. Go to Payload Suite and select tests.');
    setNav('payloads');
    return;
  }

  state.scanRunning = true;
  state.results = [];
  state.scanStartTime = Date.now();
  updateScanUI(true);
  updateTopbarStatus('scanning', 'Scan running…');
  log('RUN', `Starting scan — profile: ${state.config.scanProfile} · provider: ${state.config.provider}`);

  try {
    const res = await fetch(`${BACKEND_URL}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider:           state.config.provider,
        api_key:            state.config.apiKey,
        model:              state.config.model,
        base_url:           state.config.baseUrl,
        system_prompt:      state.config.systemPrompt,
        max_tokens:         state.config.maxTokens,
        temperature:        state.config.temperature,
        tests_per_category: state.config.testsPerCategory,
        delay_ms:           state.config.delayMs,
        timeout_s:          state.config.timeoutS,
        stop_on_critical:   state.config.stopOnCritical,
        scan_profile:       state.config.scanProfile,
        selected_payloads:  [...state.selectedPayloads],
      }),
    });

    const data = await res.json();
    if (!data.success) {
      log('ERR', `Scan failed to start: ${data.error}`);
      scanFinished(false);
      return;
    }

    log('OK', `Scan started — scan_id: ${data.scan_id}`);
    startPolling(data.scan_id);
  } catch (err) {
    log('ERR', `Cannot reach backend: ${err.message}. Is Flask running on ${BACKEND_URL}?`);
    scanFinished(false);
  }
}

function startPolling(scanId) {
  state.pollInterval = setInterval(async () => {
    try {
      const res  = await fetch(`${BACKEND_URL}/api/scan/status/${scanId}`);
      const data = await res.json();
      handleScanUpdate(data);
      if (data.status === 'completed' || data.status === 'aborted' || data.status === 'error') {
        clearInterval(state.pollInterval);
        scanFinished(data.status === 'completed');
      }
    } catch (err) {
      log('WARN', `Poll error: ${err.message}`);
    }
  }, 1500);
}

function handleScanUpdate(data) {
  // Progress bar
  const pct = data.progress ?? 0;
  const progressBar = $('#progress-bar');
  const progressPct = $('#progress-pct');
  if (progressBar) progressBar.style.width = `${pct}%`;
  if (progressPct) progressPct.textContent = `${Math.round(pct)}%`;

  // Live counters
  setCounter('#counter-total',    data.total     ?? 0);
  setCounter('#counter-complete', data.completed ?? 0);
  setCounter('#counter-vulns',    data.vulnerabilities ?? 0);
  setCounter('#counter-risk',     data.risk_score != null ? data.risk_score.toFixed(1) : '—');

  // New results
  if (data.new_results?.length) {
    data.new_results.forEach(r => {
      state.results.push(r);
      log(r.vulnerable ? 'WARN' : 'OK',
          `[${r.category}] ${r.test_name} — ${r.vulnerable ? '⚠ VULNERABLE' : 'PASSED'}`);
      appendResultRow(r);
    });
  }

  // Log messages from backend
  data.log_messages?.forEach(m => log(m.level || 'INFO', m.message));

  // Duration
  const elapsed = ((Date.now() - state.scanStartTime) / 1000).toFixed(0);
  state.sessionStats.duration = `${elapsed}s`;
  state.sessionStats.testsRun = data.completed ?? state.results.length;
  state.sessionStats.vulns    = data.vulnerabilities ?? state.results.filter(r => r.vulnerable).length;
  state.sessionStats.riskScore = data.risk_score?.toFixed(1) ?? null;
  updateSessionStats();
}

function setCounter(sel, val) {
  const el = $(sel);
  if (el) el.textContent = val;
}

async function abortScan() {
  if (!state.scanRunning) return;
  try {
    await fetch(`${BACKEND_URL}/api/scan/abort`, { method: 'POST' });
    log('WARN', 'Scan abort requested.');
  } catch { log('WARN', 'Could not reach backend to abort.'); }
  clearInterval(state.pollInterval);
  scanFinished(false);
}

function scanFinished(success) {
  state.scanRunning = false;
  updateScanUI(false);
  updateTopbarStatus(success ? 'connected' : 'idle', success ? 'Scan complete' : 'Scan stopped');
  if (success) {
    log('OK', `Scan complete — ${state.results.length} tests, ${state.results.filter(r=>r.vulnerable).length} vulnerabilities found.`);
    generateReport();
    // Auto-navigate to results
    setTimeout(() => setNav('results'), 800);
  }
}

function updateScanUI(running) {
  const startBtn  = $('#start-scan-btn');
  const abortBtn  = $('#abort-scan-btn');
  const scanBadge = $('#scan-status-badge');
  if (startBtn) startBtn.disabled = running;
  if (abortBtn) abortBtn.disabled = !running;
  if (scanBadge) {
    scanBadge.style.display = running ? 'flex' : 'none';
  }
}

/* ─────────────────────────────────────────────
   RESULTS TABLE
───────────────────────────────────────────── */
function initResultsFilter() {
  $$('.result-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $$('.result-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      filterResults(tab.dataset.filter);
    });
  });
}

function appendResultRow(r) {
  const tbody = $('#results-tbody');
  if (!tbody) return;

  // Remove empty state row if present
  $('#results-empty')?.remove();

  const sevColor = { critical:'var(--red)', high:'var(--amber)', medium:'var(--acc)', low:'var(--acc2)' };
  const row = document.createElement('tr');
  row.className = `result-row ${r.vulnerable ? 'vuln' : 'pass'}`;
  row.dataset.id = r.id;
  row.innerHTML = `
    <td><span class="status-dot ${r.vulnerable ? 'dot-vuln' : 'dot-pass'}"></span></td>
    <td style="color:var(--acc2)">${esc(CAT_LABELS[r.category] || r.category)}</td>
    <td>${esc(r.test_name)}</td>
    <td><span style="color:${sevColor[r.severity] || 'var(--text2)'}">${r.severity || '—'}</span></td>
    <td style="color:${r.vulnerable ? 'var(--red)' : 'var(--acc)'}; font-weight:700">
      ${r.vulnerable ? '⚠ VULNERABLE' : '✓ PASSED'}
    </td>
  `;
  row.addEventListener('click', () => openResultModal(r));
  tbody.appendChild(row);
}

function filterResults(filter) {
  $$('.result-row').forEach(row => {
    const show = filter === 'all'
      || (filter === 'vulnerable' && row.classList.contains('vuln'))
      || (filter === 'passed'     && row.classList.contains('pass'))
      || (filter === 'error'      && row.classList.contains('err'));
    row.style.display = show ? '' : 'none';
  });
}

/* ─────────────────────────────────────────────
   RESULT MODAL
───────────────────────────────────────────── */
function openResultModal(r) {
  const modal = $('#result-modal');
  if (!modal) return;

  $('#modal-attack-payload').textContent  = r.payload        || '—';
  $('#modal-llm-response').textContent    = r.response       || '—';
  $('#modal-evidence').textContent        = r.evidence       || '—';
  $('#modal-description').textContent     = r.description    || '—';
  $('#modal-mitigation').textContent      = r.mitigation     || '—';

  modal.style.display = 'flex';
}

function initModal() {
  const modal   = $('#result-modal');
  const closeBtn = $('#modal-close');
  if (!modal) return;
  closeBtn?.addEventListener('click', () => modal.style.display = 'none');
  modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
}

/* ─────────────────────────────────────────────
   REPORT GENERATION
───────────────────────────────────────────── */
async function generateReport() {
  try {
    const res  = await fetch(`${BACKEND_URL}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ results: state.results, config: state.config }),
    });
    const data = await res.json();
    state.report = data;
    renderReport(data);
    log('OK', 'Security report generated.');
  } catch {
    // Generate client-side report fallback
    const report = buildClientReport();
    state.report = report;
    renderReport(report);
  }
}

function buildClientReport() {
  const vulns   = state.results.filter(r => r.vulnerable);
  const total   = state.results.length;
  const risk    = vulns.length ? ((vulns.length / total) * 10).toFixed(1) : '0.0';
  const cats    = {};
  state.results.forEach(r => {
    if (!cats[r.category]) cats[r.category] = { total:0, vuln:0 };
    cats[r.category].total++;
    if (r.vulnerable) cats[r.category].vuln++;
  });
  return {
    summary: {
      total_tests:      total,
      vulnerabilities:  vulns.length,
      risk_score:       risk,
      provider:         state.config.provider,
      model:            state.config.model,
      timestamp:        new Date().toISOString(),
    },
    categories: cats,
    results:    state.results,
  };
}

function renderReport(report) {
  const el = $('#report-summary');
  if (!el || !report?.summary) return;
  const s = report.summary;
  el.innerHTML = `
    <div class="report-meta">
      <div class="report-meta-row"><span>Provider</span><span style="color:var(--acc)">${esc(s.provider)} / ${esc(s.model)}</span></div>
      <div class="report-meta-row"><span>Total Tests</span><span style="color:var(--acc2)">${s.total_tests}</span></div>
      <div class="report-meta-row"><span>Vulnerabilities</span><span style="color:var(--red)">${s.vulnerabilities}</span></div>
      <div class="report-meta-row"><span>Risk Score</span><span style="color:var(--amber)">${s.risk_score} / 10</span></div>
      <div class="report-meta-row"><span>Timestamp</span><span style="color:var(--text2)">${new Date(s.timestamp).toLocaleString()}</span></div>
    </div>
    ${report.categories ? renderCategoryBreakdown(report.categories) : ''}
  `;
}

function renderCategoryBreakdown(cats) {
  return `
    <div style="margin-top:16px">
      ${Object.entries(cats).map(([cat, data]) => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <span style="color:var(--text2)">${CAT_LABELS[cat]||cat}</span>
          <span>
            <span style="color:var(--red)">${data.vuln} vuln</span>
            <span style="color:var(--text2)"> / ${data.total} tests</span>
          </span>
        </div>
      `).join('')}
    </div>
  `;
}

/* ─────────────────────────────────────────────
   REPORT DOWNLOAD
───────────────────────────────────────────── */
function initReportDownloads() {
  $('#download-txt-btn')?.addEventListener('click',  () => downloadReport('txt'));
  $('#download-json-btn')?.addEventListener('click', () => downloadReport('json'));
  $('#download-html-btn')?.addEventListener('click', () => downloadReport('html'));
}

function downloadReport(format) {
  if (!state.report) { log('WARN', 'No report yet. Run a scan first.'); return; }
  let content, mime, ext;
  if (format === 'json') {
    content = JSON.stringify(state.report, null, 2);
    mime    = 'application/json';
    ext     = 'json';
  } else if (format === 'html') {
    content = buildHtmlReport(state.report);
    mime    = 'text/html';
    ext     = 'html';
  } else {
    content = buildTxtReport(state.report);
    mime    = 'text/plain';
    ext     = 'txt';
  }
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `llm-vapt-report.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

function buildTxtReport(report) {
  const s = report.summary;
  const lines = [
    '═══════════════════════════════════════════',
    '  LLM Security Testing Framework — VAPT Report',
    '═══════════════════════════════════════════',
    `Provider    : ${s.provider} / ${s.model}`,
    `Total Tests : ${s.total_tests}`,
    `Vulns Found : ${s.vulnerabilities}`,
    `Risk Score  : ${s.risk_score} / 10`,
    `Timestamp   : ${s.timestamp}`,
    '',
    '─── Results ─────────────────────────────',
  ];
  report.results?.forEach(r => {
    lines.push(`[${r.vulnerable ? 'VULN' : 'PASS'}] ${r.category} › ${r.test_name} (${r.severity})`);
    if (r.vulnerable && r.evidence) lines.push(`       Evidence: ${r.evidence}`);
  });
  return lines.join('\n');
}

function buildHtmlReport(report) {
  const s = report.summary;
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>LLM VAPT Report</title>
<style>
  body{background:#050709;color:#c8d8e8;font-family:'Share Tech Mono',monospace;padding:40px;max-width:900px;margin:0 auto}
  h1{color:#00ffb3;font-size:28px;margin-bottom:8px}
  h2{color:#00c8ff;font-size:16px;margin:24px 0 12px;border-bottom:1px solid rgba(0,255,180,.12);padding-bottom:8px}
  .meta{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:24px}
  .meta-row{display:flex;justify-content:space-between;padding:8px 12px;background:rgba(0,255,180,.04);border:1px solid rgba(0,255,180,.1)}
  .vuln{color:#ff3c5a} .pass{color:#00ffb3} .high{color:#ffb020}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;padding:8px;background:rgba(0,255,180,.08);color:#00ffb3;font-size:11px;letter-spacing:.1em}
  td{padding:8px;border-bottom:1px solid rgba(0,255,180,.06);font-size:12px}
</style></head><body>
<h1>LLM Security Testing Framework</h1>
<p style="color:#5a7a8a">VAPT Report · ${new Date(s.timestamp).toLocaleString()}</p>
<h2>Executive Summary</h2>
<div class="meta">
  <div class="meta-row"><span>Provider / Model</span><span style="color:#00ffb3">${esc(s.provider)} / ${esc(s.model)}</span></div>
  <div class="meta-row"><span>Total Tests</span><span style="color:#00c8ff">${s.total_tests}</span></div>
  <div class="meta-row"><span>Vulnerabilities</span><span class="vuln">${s.vulnerabilities}</span></div>
  <div class="meta-row"><span>Risk Score</span><span class="high">${s.risk_score} / 10</span></div>
</div>
<h2>Test Results</h2>
<table>
  <tr><th>Status</th><th>Category</th><th>Test</th><th>Severity</th><th>Evidence</th></tr>
  ${report.results?.map(r => `
  <tr>
    <td class="${r.vulnerable?'vuln':'pass'}">${r.vulnerable?'⚠ VULNERABLE':'✓ PASSED'}</td>
    <td style="color:#00c8ff">${esc(r.category)}</td>
    <td>${esc(r.test_name)}</td>
    <td>${esc(r.severity||'—')}</td>
    <td style="color:#5a7a8a;font-size:11px">${esc(r.evidence||'—')}</td>
  </tr>`).join('')}
</table>
</body></html>`;
}

/* ─────────────────────────────────────────────
   NAVIGATION
───────────────────────────────────────────── */
function initNavigation() {
  $$('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const section = item.dataset.section;
      if (section) setNav(section);
    });
  });
  // Configure Payloads link
  $$('a[href="#payloads"], .configure-payloads-link').forEach(a => {
    a.addEventListener('click', e => { e.preventDefault(); setNav('payloads'); });
  });
  // Run Tests link from payload suite
  $$('a[href="#run"], .run-tests-link').forEach(a => {
    a.addEventListener('click', e => { e.preventDefault(); setNav('run'); });
  });
}

/* ─────────────────────────────────────────────
   INIT
───────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  log('INFO', 'LLM Security Testing Framework ready. Configure target to begin.');
  initNavigation();
  initConfigForm();
  initPayloadControls();
  initScanControls();
  initResultsFilter();
  initModal();
  initReportDownloads();
  loadPayloads();
  updateTopbarStatus('idle', 'idle');
  setNav('config');
});
