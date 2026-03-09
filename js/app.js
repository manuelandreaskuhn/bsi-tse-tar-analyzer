// ─── app.js ───────────────────────────────────────────────────────────────
'use strict';

window.app = (function () {

  const S = {
    tarResult: null, archiveName: null, archiveType: 'standard',
    runResult: null, activeCat: null, filterStatus: 'all',
    activeFile: null, activeCert: null,
  };

  const $content   = document.getElementById('content');
  const $sidebar   = document.getElementById('sidebar');
  const $catList   = document.getElementById('sidebar-cat-list');
  const $btnReset  = document.getElementById('btn-reset');
  const $typeBadge = document.getElementById('header-type-badge');

  _showWelcome();

  // ── Welcome ──────────────────────────────────────────────────────────────
  function _showWelcome() {
    UIRenderer.renderWelcome($content);
    const dz = $content.querySelector('#drop-zone');
    const fi = $content.querySelector('#file-input');
    if (!dz || !fi) return;

    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
    dz.addEventListener('drop', e => {
      e.preventDefault();
      dz.classList.remove('drag-over');
      const f = e.dataTransfer.files[0];
      if (f) _loadFile(f);
    });
    dz.addEventListener('click', () => fi.click());
    fi.addEventListener('change', () => {
      if (fi.files[0]) { _loadFile(fi.files[0]); fi.value = ''; }
    });
  }

  // ── File loading ──────────────────────────────────────────────────────────
  function _loadFile(file) {
    S.archiveName = file.name;
    S.archiveType = /CertificateExport/i.test(file.name) ? 'cert-export' : 'standard';

    if ($typeBadge) {
      $typeBadge.textContent = S.archiveType === 'cert-export' ? 'CertificateExport' : 'Standard-Export';
    }

    UIRenderer.renderAnalyzing($content, file.name);

    const reader = new FileReader();
    reader.onload = evt => {
      try {
        S.tarResult = TarParser.parse(evt.target.result);
        _runAnalysis();
      } catch (e) {
        _showError(`TAR-Parsing fehlgeschlagen:\n${e.message}`);
      }
    };
    reader.onerror = () => _showError('Datei konnte nicht gelesen werden.');
    reader.readAsArrayBuffer(file);
  }

  // ── Analysis ──────────────────────────────────────────────────────────────
  function _runAnalysis() {
    UIRenderer.renderAnalyzing($content, S.archiveName);
    setTimeout(() => {
      try {
        S.runResult = RuleRunner.runAll({
          tarResult: S.tarResult, archiveName: S.archiveName, archiveType: S.archiveType,
        });
        $sidebar.style.display = 'block';
        if ($btnReset) $btnReset.style.display = 'inline-flex';
        UIRenderer.renderSidebar($catList, S.runResult.byCategory, null);
        $catList.onclick = e => {
          const item = e.target.closest('[data-cat]');
          if (item) _showCategory(item.dataset.cat);
        };
        _showOverview();
      } catch (e) {
        _showError(`Analyse-Fehler:\n${e.message}\n${e.stack || ''}`);
      }
    }, 60);
  }

  // ── Navigation ────────────────────────────────────────────────────────────
  function navigateTo(target) {
    if (target === 'overview' && S.runResult) _showOverview();
  }

  function _showOverview() {
    S.activeCat = null; S.activeFile = null; S.activeCert = null;
    UIRenderer.renderOverview($content, S.runResult, S.archiveName, S.archiveType);
    UIRenderer.renderSidebar($catList, S.runResult.byCategory, null);

    // Card clicks → category
    $content.onclick = e => {
      const card = e.target.closest('[data-cat]');
      if (card) { _showCategory(card.dataset.cat); return; }

      // File clicks in TAR file list
      const fileRow = e.target.closest('[data-log-file]');
      if (fileRow) { _showFileDetail(fileRow.dataset.logFile); return; }

      const certRow = e.target.closest('[data-cert-file]');
      if (certRow) { _showCertDetail(certRow.dataset.certFile); return; }
    };
  }

  function _showCategory(catName) {
    const catResults = S.runResult?.byCategory[catName];
    if (!catResults) return;
    S.activeCat = catName;
    S.filterStatus = 'all';
    UIRenderer.renderCategory($content, catName, catResults, 'all', _catIndex(catName), S.runResult);
    UIRenderer.renderSidebar($catList, S.runResult.byCategory, catName);
  }

  function _showFileDetail(filename) {
    const rr = S.runResult;
    if (!rr) return;
    const logEntry = rr.parsedLogs.find(l => l._filename === filename);
    if (!logEntry) return;
    S.activeFile = filename;
    S.activeCat = null;
    UIRenderer.renderFileDetail($content, filename, logEntry, rr.perFileResults[filename] || []);
    UIRenderer.renderSidebar($catList, rr.byCategory, null);
  }

  function _showCertDetail(filename) {
    const rr = S.runResult;
    if (!rr) return;
    const certEntry = rr.parsedCerts.find(c => c._filename === filename);
    if (!certEntry) return;
    S.activeCert = filename;
    S.activeCat = null;
    UIRenderer.renderCertDetail($content, filename, certEntry, rr.perCertResults[filename] || []);
    UIRenderer.renderSidebar($catList, rr.byCategory, null);
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  function setFilter(filterValue, btn) {
    S.filterStatus = filterValue;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    if (S.activeCat && S.runResult) {
      UIRenderer.renderCategory($content, S.activeCat,
        S.runResult.byCategory[S.activeCat], filterValue, _catIndex(S.activeCat), S.runResult);
    }
  }

  function toggleCheck(rowEl) {
    if (!rowEl) return;
    const d = rowEl.querySelector('.check-details');
    if (!d) return;
    const open = d.style.display !== 'none';
    d.style.display = open ? 'none' : 'block';
    const ic = rowEl.querySelector('.check-expand-icon');
    if (ic) ic.textContent = open ? '▼' : '▲';
  }

  function reset() {
    Object.assign(S, { tarResult: null, archiveName: null, archiveType: 'standard',
      runResult: null, activeCat: null, filterStatus: 'all', activeFile: null, activeCert: null });
    $sidebar.style.display = 'none';
    if ($btnReset)  $btnReset.style.display = 'none';
    if ($typeBadge) $typeBadge.textContent = '';
    _showWelcome();
  }

  function _catIndex(name) {
    const keys = Object.keys(S.runResult?.byCategory || {});
    const i = keys.indexOf(name);
    return i >= 0 ? i + 1 : null;
  }

  function _showError(msg) {
    $content.innerHTML = `<div class="card" style="border:2px solid var(--fail);padding:24px;margin:40px auto;max-width:600px">
      <div style="font-size:16px;font-weight:700;color:var(--fail);margin-bottom:12px">⛔ Fehler</div>
      <pre style="white-space:pre-wrap;font-size:12px;color:var(--text-muted);margin:0 0 16px">${_esc(msg)}</pre>
      <button class="btn btn-secondary" onclick="app.reset()">← Zurück</button>
    </div>`;
  }

  function _esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  return { navigateTo, setFilter, toggleCheck, reset };
})();
