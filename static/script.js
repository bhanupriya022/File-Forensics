/* ─────────────────────────────────────────────
   File Forensics — script.js
   Navbar tabs · Upload · Detection · Mismatch · Risk · Report
───────────────────────────────────────────── */

const API_URL = 'http://127.0.0.1:5000/api/analyze';

let fileList    = [];   // { file, id }
let lastResults = null; // cached API response

// ── DOM ───────────────────────────────────────
const dropZone   = document.getElementById('dropZone');
const fileInput  = document.getElementById('fileInput');
const fileQueue  = document.getElementById('fileQueue');
const queueWrap  = document.getElementById('queueWrap');
const queueCount = document.getElementById('queueCount');
const queueHint  = document.getElementById('queueHint');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn   = document.getElementById('clearBtn');
const loaderWrap = document.getElementById('loaderWrap');
const newScanBtn = document.getElementById('newScanBtn');

// Hero
const heroStats   = document.getElementById('heroStats');
const heroTitle   = document.getElementById('heroTitle');
const heroSub     = document.getElementById('heroSub');
const statTotal   = document.getElementById('statTotal');
const statHigh    = document.getElementById('statHigh');
const statMismatch= document.getElementById('statMismatch');
const statSafe    = document.getElementById('statSafe');

// Status
const statusDot  = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');

// Tab result containers
const detectionEmpty   = document.getElementById('detectionEmpty');
const detectionResults = document.getElementById('detectionResults');
const mismatchEmpty    = document.getElementById('mismatchEmpty');
const mismatchResults  = document.getElementById('mismatchResults');
const riskEmpty        = document.getElementById('riskEmpty');
const riskResults      = document.getElementById('riskResults');
const reportEmpty      = document.getElementById('reportEmpty');
const reportResultsWrap= document.getElementById('reportResults');
const reportCards      = document.getElementById('reportCards');

// ── Tab navigation ────────────────────────────
const TAB_META = {
  home:      { title: 'File Forensics',      sub: 'Format & extension mismatch detector' },
  upload:    { title: 'Upload Files',        sub: 'Select or drop files to begin forensic analysis' },
  detection: { title: 'Format Detection',    sub: 'Identifies the true format of each file using magic bytes and heuristics' },
  mismatch:  { title: 'Mismatch Detection',  sub: 'Compares declared extensions against detected MIME types' },
  risk:      { title: 'Risk Assessment',     sub: 'Scores each file 0–100 based on format, extension, and disguise patterns' },
  report:    { title: 'Analysis Report',     sub: 'Full per-file forensic report with hashes and entropy' },
};

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    switchTab(link.dataset.tab);
  });
});

document.querySelectorAll('.nav-shortcut').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    switchTab(link.dataset.tab);
  });
});

function switchTab(tab) {
  document.querySelectorAll('.nav-link').forEach(l => l.classList.toggle('active', l.dataset.tab === tab));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === 'tab' + cap(tab)));
  const meta = TAB_META[tab] || {};
  heroTitle.textContent = meta.title || '';
  heroSub.textContent   = meta.sub   || '';
  // hide stats on home tab, show on others if data exists
  if (tab === 'home') heroStats.classList.add('hidden');
  else if (lastResults) heroStats.classList.remove('hidden');
}

function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

// ── Server health check ───────────────────────
(async () => {
  try {
    const r = await fetch('http://127.0.0.1:5000/api/health', { signal: AbortSignal.timeout(3000) });
    if (r.ok) { statusDot.className = 'status-dot online'; statusText.textContent = 'Server online'; }
    else throw 0;
  } catch {
    statusDot.className = 'status-dot offline'; statusText.textContent = 'Server offline';
  }
})();

// ── Drag-and-drop ─────────────────────────────
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
['dragleave','dragend'].forEach(ev => dropZone.addEventListener(ev, () => dropZone.classList.remove('drag-over')));

dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('drag-over');
  addFiles(Array.from(e.dataTransfer.files));
});

dropZone.addEventListener('click', e => {
  if (e.target.tagName === 'LABEL' || e.target.tagName === 'INPUT') return;
  fileInput.click();
});

fileInput.addEventListener('change', () => { addFiles(Array.from(fileInput.files)); fileInput.value = ''; });

// ── File queue ────────────────────────────────
function addFiles(files) {
  files.forEach(f => {
    if (!fileList.some(x => x.file.name === f.name && x.file.size === f.size))
      fileList.push({ file: f, id: crypto.randomUUID() });
  });
  renderQueue();
}

function removeFile(id) { fileList = fileList.filter(f => f.id !== id); renderQueue(); }

function renderQueue() {
  const has = fileList.length > 0;
  queueWrap.classList.toggle('hidden', !has);
  queueCount.textContent = fileList.length;
  queueHint.textContent  = fileList.length === 1 ? '1 file ready' : `${fileList.length} files ready`;

  fileQueue.innerHTML = '';
  fileList.forEach(({ file, id }) => {
    const ext = file.name.includes('.') ? file.name.split('.').pop().toUpperCase().slice(0,6) : '?';
    const type = file.type || 'unknown';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="fn" title="${esc(file.name)}">${esc(file.name)}</span></td>
      <td class="muted"><span class="ext-tag">${esc(ext)}</span> <span style="margin-left:4px">${esc(type)}</span></td>
      <td class="right">${humanSize(file.size)}</td>
      <td><button class="rm-btn" data-id="${id}">&times;</button></td>
    `;
    fileQueue.appendChild(tr);
  });

  fileQueue.querySelectorAll('.rm-btn').forEach(btn =>
    btn.addEventListener('click', () => removeFile(btn.dataset.id))
  );
}

clearBtn.addEventListener('click', () => { fileList = []; renderQueue(); });

// ── Analyze ───────────────────────────────────
analyzeBtn.addEventListener('click', async () => {
  if (!fileList.length) return;

  loaderWrap.classList.remove('hidden');
  queueWrap.classList.add('hidden');
  analyzeBtn.disabled = true;

  const fd = new FormData();
  fileList.forEach(({ file }) => fd.append('files', file));

  try {
    const res  = await fetch(API_URL, { method: 'POST', body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Server error');
    lastResults = data;
    populateAllTabs(data);
    switchTab('report');
  } catch (err) {
    showUploadError(err.message);
  } finally {
    loaderWrap.classList.add('hidden');
    analyzeBtn.disabled = false;
    renderQueue();
  }
});

newScanBtn.addEventListener('click', () => switchTab('upload'));
document.getElementById('homeGetStarted').addEventListener('click', () => switchTab('upload'));

// ── Populate all tabs after analysis ─────────
function populateAllTabs({ results, errors }) {
  const counts    = { SAFE: 0, LOW: 0, MEDIUM: 0, HIGH: 0 };
  results.forEach(r => counts[r.risk.level]++);
  const mismatches = results.filter(r => r.mismatch);

  // Hero stats
  heroStats.classList.remove('hidden');
  statTotal.textContent    = results.length;
  statHigh.textContent     = counts.HIGH;
  statMismatch.textContent = mismatches.length;
  statSafe.textContent     = counts.SAFE;

  // Sort order for all tabs: HIGH first
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, SAFE: 3 };
  const sorted = [...results].sort((a, b) => order[a.risk.level] - order[b.risk.level]);

  populateDetection(sorted);
  populateMismatch(sorted);
  populateRisk(sorted);
  populateReport(sorted, errors);
}

// ── Detection tab ─────────────────────────────
function populateDetection(results) {
  if (!results.length) return;

  detectionEmpty.classList.add('hidden');
  detectionResults.classList.remove('hidden');

  detectionResults.innerHTML = `
    <div class="mismatch-table-wrap">
      <table class="mismatch-table">
        <thead>
          <tr>
            <th>Filename</th>
            <th>Extension</th>
            <th>Detected Format</th>
            <th>MIME Type</th>
            <th>Method</th>
            <th>Entropy</th>
          </tr>
        </thead>
        <tbody>
          ${results.map(r => `
            <tr>
              <td><strong>${esc(r.filename)}</strong></td>
              <td><span class="ext-tag">${esc(r.extension)}</span></td>
              <td>${esc(r.detected_label)}</td>
              <td><span class="mono">${esc(r.detected_mime)}</span></td>
              <td>${esc(fmtMethod(r.detection_method))}</td>
              <td>${r.entropy}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ── Mismatch tab ──────────────────────────────
function populateMismatch(results) {
  if (!results.length) return;

  mismatchEmpty.classList.add('hidden');
  mismatchResults.classList.remove('hidden');

  const mismatches = results.filter(r => r.mismatch);
  const clean      = results.filter(r => !r.mismatch);

  let html = '';

  if (mismatches.length) {
    html += `
      <div style="margin-bottom:20px">
        <div class="section-head" style="border-radius:10px 10px 0 0;border:1px solid var(--border);border-bottom:none">
          <h2 class="section-title" style="color:var(--high)">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Mismatched Files
            <span class="count-badge" style="color:var(--high);border-color:var(--high-br);background:var(--high-bg)">${mismatches.length}</span>
          </h2>
        </div>
        <div class="mismatch-table-wrap" style="border-radius:0 0 10px 10px">
          <table class="mismatch-table">
            <thead><tr><th>Filename</th><th>Declared Ext</th><th>Detected Format</th><th>Expected MIME(s)</th><th>Actual MIME</th></tr></thead>
            <tbody>
              ${mismatches.map(r => `
                <tr class="row-mismatch">
                  <td><strong>${esc(r.filename)}</strong></td>
                  <td><span class="ext-tag">${esc(r.extension)}</span></td>
                  <td>${esc(r.detected_label)}</td>
                  <td><span class="mono" style="font-size:11px">${esc((r.expected_mimes||[]).join(', ') || '—')}</span></td>
                  <td><span class="mono" style="color:var(--high)">${esc(r.detected_mime)}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  } else {
    html += `<div class="no-results-note" style="background:var(--safe-bg);border-color:var(--safe-br);color:var(--safe);margin-bottom:20px">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      No mismatches detected — all extensions match their actual formats.
    </div>`;
  }

  if (clean.length) {
    html += `
      <div class="mismatch-table-wrap">
        <table class="mismatch-table">
          <thead><tr><th>Filename</th><th>Extension</th><th>Detected Format</th><th>MIME Type</th><th>Status</th></tr></thead>
          <tbody>
            ${clean.map(r => `
              <tr>
                <td>${esc(r.filename)}</td>
                <td><span class="ext-tag">${esc(r.extension)}</span></td>
                <td>${esc(r.detected_label)}</td>
                <td><span class="mono">${esc(r.detected_mime)}</span></td>
                <td><span class="badge safe">✓ Match</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
  }

  mismatchResults.innerHTML = html;
}

// ── Risk tab ──────────────────────────────────
function populateRisk(results) {
  if (!results.length) return;

  riskEmpty.classList.add('hidden');
  riskResults.classList.remove('hidden');

  riskResults.innerHTML = `
    <div class="risk-overview">
      <table class="risk-table">
        <thead>
          <tr>
            <th>Filename</th>
            <th>Risk Level</th>
            <th>Score</th>
            <th style="min-width:160px">Bar</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          ${results.map(r => `
            <tr>
              <td><strong>${esc(r.filename)}</strong><br><span style="font-size:11.5px;color:var(--text3)">${esc(r.detected_label)}</span></td>
              <td><span class="risk-pill ${r.risk.level}">${r.risk.level}</span>${r.mismatch ? `&nbsp;<span class="mismatch-pill">Mismatch</span>` : ''}</td>
              <td style="font-weight:600;color:var(--text)">${r.risk.score}<span style="color:var(--text3);font-weight:400">/100</span></td>
              <td>
                <div class="mini-bar-wrap">
                  <div class="mini-track"><div class="mini-fill ${r.risk.level}" style="width:${r.risk.score}%"></div></div>
                </div>
              </td>
              <td style="font-size:12.5px;color:var(--text2)">${r.risk.reasons.map(x => esc(x)).join('<br>')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ── Report tab ────────────────────────────────
function populateReport(results, errors) {
  if (!results.length && !errors.length) return;

  reportEmpty.classList.add('hidden');
  reportResultsWrap.classList.remove('hidden');
  reportCards.innerHTML = '';

  (errors || []).forEach(e => {
    const d = document.createElement('div');
    d.className = 'error-card';
    d.textContent = `${e.filename}: ${e.error}`;
    reportCards.appendChild(d);
  });

  results.forEach(r => reportCards.appendChild(buildReportCard(r)));
}

function showUploadError(msg) {
  reportEmpty.classList.add('hidden');
  reportResultsWrap.classList.remove('hidden');
  reportCards.innerHTML = '';
  const d = document.createElement('div');
  d.className = 'error-card';
  d.innerHTML = `<strong>Could not reach server.</strong> ${esc(msg)}<br>
    <small>Ensure <code>python app.py</code> is running.</small>`;
  reportCards.appendChild(d);
  switchTab('report');
}

// ── Report card ───────────────────────────────
function buildReportCard(r) {
  const ext = r.extension !== '(none)' ? r.extension.replace('.','').toUpperCase().slice(0,5) : '?';
  const card = document.createElement('div');
  card.className = 'result-card';

  const hdr = document.createElement('div');
  hdr.className = 'card-header';
  hdr.innerHTML = `
    <div class="ch-icon">${esc(ext)}</div>
    <div class="ch-info">
      <div class="ch-name" title="${esc(r.filename)}">${esc(r.filename)}</div>
      <div class="ch-meta">${esc(r.detected_label)} &nbsp;·&nbsp; ${esc(r.file_size_human)}</div>
    </div>
    <div class="ch-badges">
      ${r.mismatch ? `<span class="mismatch-pill">Mismatch</span>` : ''}
      <span class="risk-pill ${r.risk.level}">${r.risk.level}</span>
      <svg class="chevron" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>
  `;

  const body = document.createElement('div');
  body.className = 'card-body';
  body.innerHTML = buildReportBody(r);

  hdr.addEventListener('click', () => {
    const open = body.classList.toggle('open');
    hdr.classList.toggle('open', open);
    hdr.querySelector('.chevron').classList.toggle('open', open);
  });

  if (r.mismatch || r.risk.level === 'HIGH') {
    body.classList.add('open');
    hdr.classList.add('open');
    hdr.querySelector('.chevron').classList.add('open');
  }

  card.appendChild(hdr);
  card.appendChild(body);
  return card;
}

function buildReportBody(r) {
  const alertHtml = r.mismatch
    ? `<div class="card-alert err">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span><strong>Extension mismatch detected.</strong> ${esc(r.mismatch_detail)}</span>
      </div>`
    : `<div class="card-alert ok">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
        <span>${esc(r.mismatch_detail)}</span>
      </div>`;

  const rows = [
    ['Filename',          esc(r.filename)],
    ['Extension',         esc(r.extension)],
    ['File Size',         `${esc(r.file_size_human)} (${r.file_size.toLocaleString()} bytes)`],
    ['Actual Format',     esc(r.detected_label)],
    ['MIME Type',         `<span class="mono">${esc(r.detected_mime)}</span>`],
    ['Detection Method',  esc(fmtMethod(r.detection_method))],
    ['Shannon Entropy',   `${r.entropy} / 8.0`],
    ['Entropy Note',      esc(r.entropy_note)],
    ['Risk Score',        riskBarHtml(r)],
    ['Findings',          `<ul class="reason-list">${r.risk.reasons.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`],
    ['MD5',               `<span class="mono">${esc(r.hashes.md5)}</span>`],
    ['SHA-256',           `<span class="mono">${esc(r.hashes.sha256)}</span>`],
    ['Analyzed At',       esc(fmtDate(r.analyzed_at))],
  ];

  const tableRows = rows.map(([k, v]) => `<div class="dt-k">${k}</div><div class="dt-v">${v}</div>`).join('');
  return `${alertHtml}<div class="detail-table">${tableRows}</div>`;
}

function riskBarHtml(r) {
  return `
    <div class="risk-bar">
      <div class="risk-track"><div class="risk-fill ${r.risk.level}" style="width:${r.risk.score}%"></div></div>
      <span class="risk-score-lbl"><span class="risk-pill ${r.risk.level}" style="font-size:10px">${r.risk.level}</span> &nbsp;${r.risk.score}/100</span>
    </div>`;
}

// ── Helpers ───────────────────────────────────
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function humanSize(b) {
  const u = ['B','KB','MB','GB']; let v = b;
  for (const x of u) { if (v < 1024) return `${v.toFixed(v<10?1:0)} ${x}`; v /= 1024; }
  return `${v.toFixed(1)} TB`;
}

function fmtDate(iso) {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function fmtMethod(m) {
  return { magic_bytes:'Magic bytes', text_heuristic:'Text heuristic', unknown:'Unknown', empty:'Empty file' }[m] || m;
}
