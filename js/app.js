// ─── app.js – Haupt-Anwendungslogik ──────────────────────────────────────
'use strict';

(function() {

  // ── DOM refs ─────────────────────────────────────────────────────────────
  const dropZone       = document.getElementById('drop-zone');
  const fileInput      = document.getElementById('file-input');
  const archTypeSelect = document.getElementById('arch-type-select');
  const mainContent    = document.getElementById('main-content');
  const sidebarList    = document.getElementById('sidebar-cat-list');
  const sidebarSection = document.getElementById('sidebar-section');
  const navOverview    = document.getElementById('nav-overview');
  const navFiles       = document.getElementById('nav-files');
  const filterBar      = document.getElementById('filter-bar');
  const filterBtns     = document.querySelectorAll('.filter-btn');
  const newAnalysisBtn = document.getElementById('btn-new-analysis');

  // ── Application State ────────────────────────────────────────────────────
  let state = {
    tarResult:    null,
    archiveName:  null,
    archiveType:  'standard',     // 'standard' | 'cert-export'
    runResult:    null,
    activeView:   'welcome',      // 'welcome' | 'overview' | 'category' | 'files'
    activeCat:    null,
    filterStatus: null,           // null | 'PASS' | 'FAIL' | 'WARN' | 'INFO' | 'SKIP'
  };

  // ── Boot ─────────────────────────────────────────────────────────────────
  UIRenderer.renderWelcome(mainContent);
  _hideSidebar();

  // ── Event Listeners ───────────────────────────────────────────────────────

  // Drag-and-drop
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', ()  => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) _loadFile(file);
  });

  // File input click
  dropZone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) _loadFile(fileInput.files[0]);
  });

  // Archive-type toggle
  archTypeSelect && archTypeSelect.addEventListener('change', () => {
    state.archiveType = archTypeSelect.value;
    if (state.tarResult) _runAnalysis();
  });

  // Sidebar category links (delegated)
  sidebarList.addEventListener('click', e => {
    const link = e.target.closest('[data-cat]');
    if (link) {
      e.preventDefault();
      _showCategory(link.dataset.cat);
    }
  });

  // Sidebar: overview & files nav
  navOverview && navOverview.addEventListener('click', e => { e.preventDefault(); _showOverview(); });
  navFiles    && navFiles.addEventListener('click',    e => { e.preventDefault(); _showFiles(); });

  // Filter buttons
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const s = btn.dataset.status || null;
      state.filterStatus = (state.filterStatus === s) ? null : s;
      _applyFilter();
    });
  });

  // New analysis button
  newAnalysisBtn && newAnalysisBtn.addEventListener('click', () => _reset());

  // Overview card clicks (delegated)
  mainContent.addEventListener('click', e => {
    const card = e.target.closest('[data-cat]');
    if (card && state.runResult) _showCategory(card.dataset.cat);
  });

  // ── Core Functions ────────────────────────────────────────────────────────

  function _loadFile(file) {
    state.archiveName = file.name;

    // Auto-detect archive type from filename
    if (/CertificateExport/i.test(file.name)) {
      state.archiveType = 'cert-export';
      if (archTypeSelect) archTypeSelect.value = 'cert-export';
    } else if (/Export/i.test(file.name)) {
      state.archiveType = 'standard';
      if (archTypeSelect) archTypeSelect.value = 'standard';
    }

    UIRenderer.renderAnalyzing(mainContent, file.name);

    const reader = new FileReader();
    reader.onload = evt => {
      try {
        const buf = evt.target.result;
        state.tarResult = TarParser.parse(buf);
        _runAnalysis();
      } catch (e) {
        _showError(`TAR-Parsing fehlgeschlagen: ${e.message}`);
      }
    };
    reader.onerror = () => _showError('Datei konnte nicht gelesen werden.');
    reader.readAsArrayBuffer(file);
  }

  function _runAnalysis() {
    if (!state.tarResult) return;

    UIRenderer.renderAnalyzing(mainContent, state.archiveName);

    // Small delay to allow rendering before heavy computation
    setTimeout(() => {
      try {
        state.runResult = RuleRunner.runAll({
          tarResult:   state.tarResult,
          archiveName: state.archiveName,
          archiveType: state.archiveType,
        });
        _showOverview();
        _showSidebar();
        UIRenderer.renderSidebar(sidebarList, state.runResult.byCategory, null);
      } catch (e) {
        _showError(`Analyse fehlgeschlagen: ${e.message}\n${e.stack || ''}`);
      }
    }, 50);
  }

  function _showOverview() {
    state.activeView  = 'overview';
    state.activeCat   = null;
    _setFilterVisible(false);
    UIRenderer.renderOverview(mainContent, state.runResult, state.archiveName, state.archiveType);
    UIRenderer.renderSidebar(sidebarList, state.runResult.byCategory, null);
    _setActiveNav(navOverview);
  }

  function _showCategory(catName) {
    if (!state.runResult) return;
    const catResults = state.runResult.byCategory[catName];
    if (!catResults) return;

    state.activeView = 'category';
    state.activeCat  = catName;
    _setFilterVisible(true);
    _updateFilterBtns();

    UIRenderer.renderCategory(mainContent, catName, catResults, state.filterStatus);
    UIRenderer.renderSidebar(sidebarList, state.runResult.byCategory, catName);
    _setActiveNav(null);
  }

  function _showFiles() {
    if (!state.tarResult) return;
    state.activeView = 'files';
    state.activeCat  = null;
    _setFilterVisible(false);

    mainContent.innerHTML = '<h2 class="page-title">Dateien im Archiv</h2><div id="file-table-container"></div>';
    UIRenderer.renderFileTable(document.getElementById('file-table-container'), state.tarResult);
    _setActiveNav(navFiles);
  }

  function _applyFilter() {
    _updateFilterBtns();
    if (state.activeView === 'category' && state.activeCat) {
      const catResults = state.runResult.byCategory[state.activeCat];
      UIRenderer.renderCategory(mainContent, state.activeCat, catResults, state.filterStatus);
    }
  }

  function _updateFilterBtns() {
    filterBtns.forEach(btn => {
      const s = btn.dataset.status || null;
      btn.classList.toggle('active', s === state.filterStatus);
    });
  }

  function _reset() {
    state = {
      tarResult: null, archiveName: null, archiveType: 'standard',
      runResult: null, activeView: 'welcome', activeCat: null, filterStatus: null,
    };
    if (archTypeSelect) archTypeSelect.value = 'standard';
    fileInput.value = '';
    UIRenderer.renderWelcome(mainContent);
    _hideSidebar();
  }

  function _showError(msg) {
    mainContent.innerHTML = `<div class="error-box"><h3>Fehler</h3><pre>${_esc(msg)}</pre>
      <button class="btn" onclick="location.reload()">Neu starten</button></div>`;
  }

  function _showSidebar()  { sidebarSection && (sidebarSection.hidden = false); }
  function _hideSidebar()  { sidebarSection && (sidebarSection.hidden = true); }
  function _setFilterVisible(v) { filterBar && (filterBar.hidden = !v); }

  function _setActiveNav(el) {
    [navOverview, navFiles].forEach(n => n && n.classList.remove('active'));
    if (el) el.classList.add('active');
  }

  function _esc(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

})();
