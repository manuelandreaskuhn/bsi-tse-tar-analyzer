// ─── ui-renderer.js – Template-basiertes UI-Rendering ────────────────────
'use strict';

window.UIRenderer = (function() {

  const STATUS_ICON  = { PASS: '✓', FAIL: '✗', WARN: '⚠', INFO: 'ℹ', SKIP: '–' };
  const STATUS_LABEL = { PASS: 'PASS', FAIL: 'FAIL', WARN: 'WARN', INFO: 'INFO', SKIP: 'SKIP' };

  /** Render the welcome / drop screen */
  function renderWelcome(container) {
    container.innerHTML = '';
    container.appendChild(Utils.cloneTemplate('tpl-welcome'));
  }

  /** Render the "Analysing…" progress screen */
  function renderAnalyzing(container, filename) {
    container.innerHTML = '';
    const el = Utils.cloneTemplate('tpl-analyzing');
    const msg = el.querySelector('.analyzing-filename');
    if (msg) msg.textContent = filename || '…';
    container.appendChild(el);
  }

  /** Build the sidebar category list */
  function renderSidebar(sidebarList, byCategory, activeKey) {
    sidebarList.innerHTML = '';
    for (const [catName, catResults] of Object.entries(byCategory)) {
      const fails  = catResults.filter(r => r.status === 'FAIL').length;
      const warns  = catResults.filter(r => r.status === 'WARN').length;
      const passes = catResults.filter(r => r.status === 'PASS').length;
      const verdict = fails > 0 ? 'fail' : warns > 0 ? 'warn' : passes > 0 ? 'pass' : 'info';

      const el = Utils.cloneTemplate('tpl-sidebar-cat');
      const link = el.querySelector('.sidebar-cat-link');
      if (link) {
        link.textContent = catName;
        link.dataset.cat = catName;
        link.classList.add(`status-${verdict}`);
        if (catName === activeKey) link.classList.add('active');
      }

      const badge = el.querySelector('.sidebar-badge');
      if (badge) {
        badge.textContent = `${passes}P ${fails}F ${warns}W`;
        badge.className = `sidebar-badge verdict-${verdict}`;
      }
      sidebarList.appendChild(el);
    }
  }

  /** Render the overview page */
  function renderOverview(container, runResult, archiveName, archiveType) {
    const { stats, byCategory } = runResult;
    container.innerHTML = '';
    const el = Utils.cloneTemplate('tpl-overview');

    // Verdict banner
    const banner = el.querySelector('.verdict-banner');
    if (banner) {
      banner.classList.add(`verdict-${stats.verdict.toLowerCase()}`);
      const icon = banner.querySelector('.verdict-icon');
      const txt  = banner.querySelector('.verdict-text');
      if (icon) icon.textContent = STATUS_ICON[stats.verdict] || '?';
      if (txt)  txt.textContent  = stats.verdict;
    }

    // Stats grid
    _setQ(el, '.stat-total',  stats.total);
    _setQ(el, '.stat-pass',   stats.pass);
    _setQ(el, '.stat-fail',   stats.fail);
    _setQ(el, '.stat-warn',   stats.warn);
    _setQ(el, '.stat-info',   stats.info);
    _setQ(el, '.stat-skip',   stats.skip);
    _setQ(el, '.stat-logs',   stats.logCount);
    _setQ(el, '.stat-certs',  stats.certCount);

    // Meta info
    _setQ(el, '.meta-filename',    archiveName || '–');
    _setQ(el, '.meta-archtype',    archiveType === 'cert-export' ? 'CertificateExport' : 'Standard-Export');
    _setQ(el, '.meta-files',       runResult.parsedLogs.length + runResult.parsedCerts.length);
    _setQ(el, '.meta-parseerrors', stats.parseErrors);

    // Category cards grid
    const grid = el.querySelector('.ov-cat-grid');
    if (grid) {
      for (const [catName, catResults] of Object.entries(byCategory)) {
        const card = Utils.cloneTemplate('tpl-ov-cat-card');
        const fails  = catResults.filter(r => r.status === 'FAIL').length;
        const warns  = catResults.filter(r => r.status === 'WARN').length;
        const passes = catResults.filter(r => r.status === 'PASS').length;
        const verdict = fails > 0 ? 'fail' : warns > 0 ? 'warn' : passes > 0 ? 'pass' : 'info';

        card.classList.add(`verdict-${verdict}`);
        _setQ(card, '.ov-cat-name',   catName);
        _setQ(card, '.ov-cat-total',  catResults.length);
        _setQ(card, '.ov-cat-pass',   passes);
        _setQ(card, '.ov-cat-fail',   fails);
        _setQ(card, '.ov-cat-warn',   warns);
        _setQ(card, '.ov-cat-icon',   STATUS_ICON[verdict.toUpperCase()] || '?');
        card.dataset.cat = catName;
        card.style.cursor = 'pointer';
        grid.appendChild(card);
      }
    }

    container.appendChild(el);
    return el;
  }

  /** Render a single category result page */
  function renderCategory(container, catName, catResults, filterStatus) {
    container.innerHTML = '';
    const el = Utils.cloneTemplate('tpl-category');

    _setQ(el, '.cat-title', catName);

    const fails  = catResults.filter(r => r.status === 'FAIL').length;
    const warns  = catResults.filter(r => r.status === 'WARN').length;
    const passes = catResults.filter(r => r.status === 'PASS').length;
    const verdict = fails > 0 ? 'fail' : warns > 0 ? 'warn' : passes > 0 ? 'pass' : 'info';

    _setQ(el, '.cat-stat-total',  catResults.length);
    _setQ(el, '.cat-stat-pass',   passes);
    _setQ(el, '.cat-stat-fail',   fails);
    _setQ(el, '.cat-stat-warn',   warns);

    const list = el.querySelector('.check-list');
    if (list) {
      const filtered = filterStatus ? catResults.filter(r => r.status === filterStatus) : catResults;
      for (const result of filtered) {
        list.appendChild(_buildCheckRow(result));
      }
    }

    container.appendChild(el);
    return el;
  }

  /** Build a single check-row element */
  function _buildCheckRow(result) {
    const row = Utils.cloneTemplate('tpl-check-row');
    row.dataset.status = result.status;
    row.classList.add(`status-${result.status.toLowerCase()}`);

    _setQ(row, '.check-id',     result.id);
    _setQ(row, '.check-name',   result.name);
    _setQ(row, '.check-status', STATUS_LABEL[result.status] || result.status);
    _setQ(row, '.check-icon',   STATUS_ICON[result.status] || '?');

    const statusBadge = row.querySelector('.check-status-badge');
    if (statusBadge) statusBadge.classList.add(`status-${result.status.toLowerCase()}`);

    // Expandable detail section
    const detailEl = row.querySelector('.check-detail');
    const ruleEl   = row.querySelector('.check-rule-text');
    const refEl    = row.querySelector('.check-ref');

    if (detailEl) detailEl.textContent = result.detail || '–';
    if (ruleEl)   ruleEl.textContent   = result.ruleText || '';
    if (refEl)    refEl.textContent    = result.ref || '';

    // Expand/collapse toggle
    const header = row.querySelector('.check-header');
    const body   = row.querySelector('.check-body');
    if (header && body) {
      body.style.display = 'none';
      header.style.cursor = 'pointer';
      header.addEventListener('click', () => {
        const open = body.style.display !== 'none';
        body.style.display = open ? 'none' : 'block';
        const arrow = header.querySelector('.check-arrow');
        if (arrow) arrow.textContent = open ? '▶' : '▼';
      });
    }

    return row;
  }

  /** Render file table */
  function renderFileTable(container, tarResult) {
    container.innerHTML = '';
    if (!tarResult) return;
    const files = [...tarResult.files.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]));

    const table = document.createElement('table');
    table.className = 'file-table';
    table.innerHTML = `<thead><tr>
      <th>Dateiname</th><th>Größe</th><th>Typ</th>
    </tr></thead>`;
    const tbody = document.createElement('tbody');
    for (const [name, entry] of files) {
      const tr = document.createElement('tr');
      const type = Utils.classifyFile(name.split('/').pop()) || 'sonstige';
      tr.innerHTML = `<td class="file-name">${_esc(name)}</td>
        <td class="file-size">${Utils.formatBytes(entry.size)}</td>
        <td class="file-type">${_esc(type)}</td>`;
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    container.appendChild(table);
  }

  // ── helpers ──────────────────────────────────────────────────────────────

  function _setQ(parent, selector, text) {
    const el = parent.querySelector ? parent.querySelector(selector) : null;
    if (el) el.textContent = String(text ?? '');
  }

  function _esc(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  return {
    renderWelcome,
    renderAnalyzing,
    renderSidebar,
    renderOverview,
    renderCategory,
    renderFileTable,
  };
})();
