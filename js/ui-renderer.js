// ─── ui-renderer.js ───────────────────────────────────────────────────────
'use strict';

window.UIRenderer = (function () {

  const ICON = { PASS: '✓', FAIL: '✗', WARN: '⚠', INFO: 'ℹ', SKIP: '–' };
  const LABEL = { PASS: 'KONFORM', FAIL: 'NICHT KONFORM', WARN: 'BEDINGT KONFORM', INFO: 'INFO' };

  // Rules database (loaded async from rules.json)
  let _rulesDB = {};
  function loadRulesDB() {
    fetch('rules.json')
      .then(r => r.json())
      .then(db => { _rulesDB = db; })
      .catch(() => { });
  }
  loadRulesDB();

  // ── Public ──────────────────────────────────────────────────────────────

  function renderWelcome(container) {
    container.innerHTML = '';
    container.appendChild(Utils.cloneTemplate('tpl-welcome'));
  }

  function renderAnalyzing(container, filename) {
    container.innerHTML = '';
    const el = Utils.cloneTemplate('tpl-analyzing');
    _setId(el, 'analyzing-text', `Analysiere: ${filename || '…'}`);
    _setId(el, 'analyzing-sub', 'Bitte warten…');
    container.appendChild(el);
  }

  function renderOverview(container, runResult, archiveName, archiveType) {
    const { stats, byCategory, parsedLogs, parsedCerts, infoRows, tarResult, perFileResults, perCertResults } = runResult;
    container.innerHTML = '';
    const el = Utils.cloneTemplate('tpl-overview');
    const v = stats.verdict;

    const banner = el.querySelector('#ov-verdict');
    if (banner) banner.classList.add(v === 'FAIL' ? 'verdict-fail' : v === 'WARN' ? 'verdict-warn' : 'verdict-pass');

    _setId(el, 'ov-verdict-icon', ICON[v] || '?');
    _setId(el, 'ov-verdict-title', LABEL[v] || v);
    _setId(el, 'ov-verdict-sub', `${stats.fail} Fehler · ${stats.warn} Warnungen · ${stats.pass} bestanden`);
    _setId(el, 'ov-verdict-meta', `${stats.total} Prüfungen · ${stats.logCount} Logs · ${stats.certCount} Zertifikate`);
    _setId(el, 'ov-sub', archiveName || '');

    _setId(el, 'stat-total', stats.total);
    _setId(el, 'stat-pass', stats.pass);
    _setId(el, 'stat-fail', stats.fail);
    _setId(el, 'stat-warn', stats.warn);
    _setId(el, 'stat-info', stats.info);
    _setId(el, 'stat-skip', stats.skip);

    const t = stats.total || 1;
    _barW(el, 'bar-pass', stats.pass / t * 100);
    _barW(el, 'bar-fail', stats.fail / t * 100);
    _barW(el, 'bar-warn', stats.warn / t * 100);
    _barW(el, 'bar-info', stats.info / t * 100);
    _barW(el, 'bar-skip', stats.skip / t * 100);

    // Count log types
    const sysLogs = (parsedLogs || []).filter(l => l.logType === 'sys');
    const txnLogs = (parsedLogs || []).filter(l => l.logType === 'txn');
    const auditLogs = (parsedLogs || []).filter(l => l.logType === 'audit');
    const certCount = (parsedCerts || []).length;

    _fillMeta(el, '#meta-archive', [
      ['Dateiname', archiveName || '–'],
      ['Typ', archiveType === 'cert-export' ? 'CertificateExport' : 'Standard-Export'],
      ['Parse-Fehler', stats.parseErrors],
    ]);
    _fillMeta(el, '#meta-files', [
      ['Logs gesamt', (parsedLogs || []).length],
      ['SystemLog', sysLogs.length],
      ['TransactionLog', txnLogs.length],
      ['AuditLog', auditLogs.length],
      ['Zertifikate', certCount],
    ]);
    _fillMeta(el, '#meta-params', [
      ['Kategorien', Object.keys(byCategory).length],
      ['Checks gesamt', stats.total],
    ]);

    container.appendChild(el);
  }

  function renderAllFiles(container, runResult) {
    container.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.className = 'card';
    wrap.style.cssText = 'margin:0';

    const hdr = document.createElement('div');
    hdr.style.cssText = 'padding:16px 20px 0;';
    hdr.innerHTML = '<h2 style="font-size:16px;font-weight:700;color:var(--text);margin:0 0 12px">🗂 Dateien im Archiv</h2>';
    wrap.appendChild(hdr);

    const inner = document.createElement('div');
    inner.style.cssText = 'padding:0 20px 20px';
    _buildFilesSection(inner, runResult);
    wrap.appendChild(inner);

    container.appendChild(wrap);
  }

  function renderAllTests(container, runResult, filterStatus) {
    container.innerHTML = '';
    filterStatus = filterStatus || 'all';

    const { byCategory, stats } = runResult;
    const allResults = Object.entries(byCategory).flatMap(([cat, res]) =>
      res.map(r => ({ ...r, _cat: cat }))
    );

    const nf = allResults.filter(r => r.status === 'FAIL').length;
    const nw = allResults.filter(r => r.status === 'WARN').length;
    const np = allResults.filter(r => r.status === 'PASS').length;
    const ni = allResults.filter(r => r.status === 'INFO').length;
    const ns = allResults.filter(r => r.status === 'SKIP').length;

    const wrap = document.createElement('div');

    // Header
    const hdr = document.createElement('div');
    hdr.className = 'card';
    hdr.style.cssText = 'margin-bottom:16px;padding:16px 20px';
    hdr.innerHTML = `
      <h2 style="font-size:16px;font-weight:700;color:var(--text);margin:0 0 8px">🔍 Alle Tests</h2>
      <div style="font-size:13px;color:var(--text-muted)">
        ${allResults.length} Prüfungen aus ${Object.keys(byCategory).length} Kategorien
        &nbsp;·&nbsp;
        <span style="color:var(--fail)">✗ ${nf}</span> &nbsp;
        <span style="color:var(--warn)">⚠ ${nw}</span> &nbsp;
        <span style="color:var(--pass)">✓ ${np}</span> &nbsp;
        <span style="color:var(--info)">ℹ ${ni}</span> &nbsp;
        <span style="color:var(--text-muted)">– ${ns}</span>
      </div>
      <div class="filter-bar" style="margin-top:12px;flex-wrap:wrap;gap:6px">
        ${['all', 'FAIL', 'WARN', 'PASS', 'INFO', 'SKIP'].map(f =>
      `<button class="filter-btn${filterStatus === f ? ' active' : ''}" onclick="app.setAllTestsFilter('${f}',this)">${{ all: 'Alle', FAIL: '✗ Fehler', WARN: '⚠ Warnung', PASS: '✓ OK', INFO: 'ℹ Info', SKIP: '– Skipped' }[f]
      }</button>`
    ).join('')}
      </div>`;
    wrap.appendChild(hdr);

    // Grouped list
    const card = document.createElement('div');
    card.className = 'card';
    card.style.overflow = 'hidden';

    const filtered = filterStatus === 'all' ? allResults : allResults.filter(r => r.status === filterStatus);

    if (filtered.length === 0) {
      card.innerHTML = '<div style="padding:30px;text-align:center;color:var(--text-muted)">Keine Prüfungen für diesen Filter.</div>';
    } else {
      // Group by category, showing a group header before each category
      let lastCat = null;
      filtered.forEach(r => {
        if (r._cat !== lastCat) {
          lastCat = r._cat;
          const catHdr = document.createElement('div');
          catHdr.style.cssText = 'margin-top: 25px;padding:8px 16px 4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);background:var(--sidebar-bg);border-top:1px solid var(--border-light);cursor:pointer';
          catHdr.textContent = r._cat;
          catHdr.onclick = () => app.navigateTo('cat:' + r._cat);
          card.appendChild(catHdr);
        }
        card.appendChild(_buildCheckRow(r));
      });
    }
    wrap.appendChild(card);
    container.appendChild(wrap);
  }

  function _buildFilesSection(container, runResult) {
    const { parsedLogs, parsedCerts, tarResult, perFileResults, perCertResults } = runResult;
    const sysLogs = (parsedLogs || []).filter(l => l.logType === 'sys');
    const txnLogs = (parsedLogs || []).filter(l => l.logType === 'txn');
    const auditLogs = (parsedLogs || []).filter(l => l.logType === 'audit');
    const certCount = (parsedCerts || []).length;

    const allFiles = [...tarResult.files.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    const evtTypes = [...new Set(sysLogs.map(l => l.eventType).filter(Boolean))].sort();
    const opTypes = [...new Set(txnLogs.map(l => l.operationType).filter(Boolean))].sort();
    const clientIds = [...new Set(txnLogs.map(l => l.clientId).filter(Boolean))].sort();

    const fileMeta = allFiles.map(([name, entry]) => {
      const ext = name.split('.').pop().toLowerCase();
      const isLog = ext === 'log';
      const isCert = ['pem', 'cer', 'crt', 'cert', 'der'].includes(ext);
      const basename = name.split('/').pop();
      const logEntry = isLog ? (parsedLogs || []).find(l => l._filename === basename) : null;
      const certEntry = isCert ? (parsedCerts || []).find(c => c._filename === basename) : null;
      const logType = logEntry?.logType || null;
      const perFile = isLog ? (perFileResults?.[basename] || perFileResults?.[name] || []) : null;
      const perCert = isCert ? (perCertResults?.[basename] || perCertResults?.[name] || []) : null;
      const rs = perFile || perCert || [];
      const nf = rs.filter(r => (r.status || '').toUpperCase() === 'FAIL').length;
      const nw = rs.filter(r => (r.status || '').toUpperCase() === 'WARN').length;
      const np = rs.filter(r => (r.status || '').toUpperCase() === 'PASS').length;
      return { name, entry, ext, isLog, isCert, basename, logEntry, certEntry, logType, rs, nf, nw, np };
    });

    // Header
    const hdr = document.createElement('div');
    hdr.style.cssText = 'display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:10px';
    hdr.innerHTML = `
      <div style="font-size:13px;font-weight:700;color:var(--text)">
        ${allFiles.length} Dateien
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
        ${sysLogs.length ? `<span class="ftype-stat" style="background:#dbeafe;color:#1e40af">${sysLogs.length} SystemLog</span>` : ''}
        ${txnLogs.length ? `<span class="ftype-stat" style="background:#f3e8ff;color:#6b21a8">${txnLogs.length} TransactionLog</span>` : ''}
        ${auditLogs.length ? `<span class="ftype-stat" style="background:#fef3c7;color:#92400e">${auditLogs.length} AuditLog</span>` : ''}
        ${certCount ? `<span class="ftype-stat" style="background:#dcfce7;color:#166534">${certCount} Zertifikat${certCount !== 1 ? 'e' : ''}</span>` : ''}
      </div>`;
    container.appendChild(hdr);

    // Filter bar
    const filterBar = document.createElement('div');
    filterBar.className = 'file-filter-bar';

    const typeFilters = [
      { key: 'all', label: 'Alle', count: allFiles.length },
      { key: 'sys', label: 'SystemLog', count: sysLogs.length, show: sysLogs.length > 0 },
      { key: 'txn', label: 'TransactionLog', count: txnLogs.length, show: txnLogs.length > 0 },
      { key: 'audit', label: 'AuditLog', count: auditLogs.length, show: auditLogs.length > 0 },
      { key: 'cert', label: 'Zertifikate', count: certCount, show: certCount > 0 },
    ].filter(f => f.show !== false);

    const typeRow = document.createElement('div');
    typeRow.className = 'ff-type-row';
    typeFilters.forEach(tf => {
      const btn = document.createElement('button');
      btn.className = 'ff-type-btn' + (tf.key === 'all' ? ' active' : '');
      btn.dataset.typeKey = tf.key;
      btn.innerHTML = `${_esc(tf.label)} <span class="ff-count">${tf.count}</span>`;
      typeRow.appendChild(btn);
    });
    filterBar.appendChild(typeRow);

    const filesWithFail = fileMeta.filter(m => m.nf > 0).length;
    const filesWithWarn = fileMeta.filter(m => m.nw > 0 && m.nf === 0).length;
    if (filesWithFail + filesWithWarn > 0) {
      const verdictRow = document.createElement('div');
      verdictRow.className = 'ff-type-row ff-verdict-row';
      verdictRow.style.marginTop = '2px';
      const mkVBtn = (key, label, count, colorClass) => {
        const btn = document.createElement('button');
        btn.className = `ff-type-btn ff-verdict-btn ${colorClass}`;
        btn.dataset.verdictKey = key;
        btn.innerHTML = `${_esc(label)} <span class="ff-count">${count}</span>`;
        return btn;
      };
      if (filesWithFail > 0) verdictRow.appendChild(mkVBtn('fail', '✗ Fehler', filesWithFail, 'ff-vbtn-fail'));
      if (filesWithWarn > 0) verdictRow.appendChild(mkVBtn('warn', '⚠ Warnungen', filesWithWarn, 'ff-vbtn-warn'));
      const clearBtn = document.createElement('button');
      clearBtn.className = 'ff-type-btn ff-verdict-btn ff-vbtn-clear';
      clearBtn.dataset.verdictKey = '';
      clearBtn.style.display = 'none';
      clearBtn.textContent = '× Filter aufheben';
      verdictRow.appendChild(clearBtn);
      filterBar.appendChild(verdictRow);
    }

    const searchRow = document.createElement('div');
    searchRow.className = 'ff-search-row';
    searchRow.innerHTML = `
      <input class="ff-search" id="ff-text-search" type="text" placeholder="Dateiname / Inhalt suchen…">
      <div class="ff-cond-filters" id="ff-cond-filters" style="display:none"></div>`;
    filterBar.appendChild(searchRow);
    container.appendChild(filterBar);

    const condEl = filterBar.querySelector('#ff-cond-filters');
    const buildCondFilters = typeKey => {
      condEl.innerHTML = '';
      condEl.style.display = 'none';
      if (typeKey === 'sys' && evtTypes.length > 0) {
        condEl.style.display = 'flex';
        const sel = document.createElement('select');
        sel.className = 'ff-select'; sel.id = 'ff-evttype';
        sel.innerHTML = `<option value="">Alle eventTypes (${evtTypes.length})</option>` +
          evtTypes.map(e => `<option value="${_esc(e)}">${_esc(e)}</option>`).join('');
        condEl.appendChild(sel);
      } else if (typeKey === 'txn') {
        condEl.style.display = 'flex';
        if (opTypes.length > 0) {
          const sel = document.createElement('select');
          sel.className = 'ff-select'; sel.id = 'ff-optype';
          sel.innerHTML = `<option value="">Alle Operationen</option>` +
            opTypes.map(o => `<option value="${_esc(o)}">${_esc(o)}</option>`).join('');
          condEl.appendChild(sel);
        }
        if (clientIds.length > 0) {
          const sel2 = document.createElement('select');
          sel2.className = 'ff-select'; sel2.id = 'ff-client';
          sel2.innerHTML = `<option value="">Alle Clients (${clientIds.length})</option>` +
            clientIds.map(c => `<option value="${_esc(c)}">Client: ${_esc(c)}</option>`).join('');
          condEl.appendChild(sel2);
        }
        const txnInput = document.createElement('input');
        txnInput.className = 'ff-search ff-txn-search'; txnInput.id = 'ff-txnnum';
        txnInput.type = 'text'; txnInput.placeholder = 'Txn-Nr. filtern…'; txnInput.style.width = '120px';
        condEl.appendChild(txnInput);
      }
    };

    const listWrap = document.createElement('div');
    listWrap.className = 'card'; listWrap.style.overflow = 'hidden';
    const list = document.createElement('div');
    list.className = 'tar-file-list'; list.id = 'ov-tar-file-list';
    listWrap.appendChild(list);
    container.appendChild(listWrap);

    const rows = fileMeta.map(m => {
      const row = document.createElement('div');
      row.className = 'tar-file-row tar-file-row-v2';
      row.dataset.typeKey = m.logType || (m.isCert ? 'cert' : 'other');
      row.dataset.nameSearch = m.name.toLowerCase();
      if (m.nf > 0) { row.style.borderLeft = '3px solid var(--fail)'; row.style.background = 'rgba(220,38,38,.04)'; }
      else if (m.nw > 0) { row.style.borderLeft = '3px solid var(--warn)'; row.style.background = 'rgba(217,119,6,.04)'; }
      else if (m.np > 0) { row.style.borderLeft = '3px solid var(--pass)'; }
      if (m.isLog && m.logEntry) { row.dataset.logFile = m.name; row.style.cursor = 'pointer'; row.title = 'Klicken für Datei-Details'; }
      if (m.isCert && m.certEntry) { row.dataset.certFile = m.name; row.style.cursor = 'pointer'; row.title = 'Klicken für Zertifikat-Details'; }
      if (m.logEntry) {
        if (m.logEntry.eventType) row.dataset.evtType = m.logEntry.eventType;
        if (m.logEntry.operationType) row.dataset.opType = m.logEntry.operationType;
        if (m.logEntry.clientId) row.dataset.clientId = String(m.logEntry.clientId);
        if (m.logEntry.transactionNumber != null) row.dataset.txnNum = String(m.logEntry.transactionNumber);
      }
      const ltMap = {
        sys: { label: 'SystemLog', col: '#1e40af', bg: '#dbeafe' },
        txn: { label: 'TransactionLog', col: '#6b21a8', bg: '#f3e8ff' },
        audit: { label: 'AuditLog', col: '#92400e', bg: '#fef3c7' },
      };
      const badge = (col, bg, txt) => `<span style="padding:2px 7px;border-radius:10px;font-size:11px;font-weight:700;color:${col};background:${bg};border:1px solid ${col}40;white-space:nowrap;flex-shrink:0">${txt}</span>`;
      let logTypeBadge = '';
      if (m.logType && ltMap[m.logType]) {
        const { label, col, bg } = ltMap[m.logType];
        logTypeBadge = badge(col, bg, label);
        if (m.logType === 'txn' && m.logEntry?.operationType) {
          const opShort = { startTransaction: 'Start', updateTransaction: 'Update', finishTransaction: 'Finish' }[m.logEntry.operationType] || m.logEntry.operationType;
          logTypeBadge += badge('#374151', '#f3f4f6', opShort);
        }
      }
      let certTypeBadge = '';
      if (m.isCert && m.certEntry && !m.certEntry.parseError) {
        const iKey = JSON.stringify({ CN: m.certEntry.issuerDN?.CN, O: m.certEntry.issuerDN?.O });
        const sKey = JSON.stringify({ CN: m.certEntry.subjectDN?.CN, O: m.certEntry.subjectDN?.O });
        const ct = m.certEntry.isCA === true ? (iKey === sKey ? 'root' : 'subca') : 'leaf';
        const ctM = { root: { col: '#7c3aed', bg: '#f5f3ff', lbl: 'Root-CA' }, subca: { col: '#0369a1', bg: '#e0f2fe', lbl: 'Sub-CA' }, leaf: { col: '#059669', bg: '#ecfdf5', lbl: 'Blatt' } }[ct];
        if (ctM) certTypeBadge = badge(ctM.col, ctM.bg, ctM.lbl);
      }
      const verdictBadge = m.rs.length > 0
        ? (m.nf > 0 ? `<span class="sb-mini sb-mini-fail">✗ ${m.nf}</span>`
          : m.nw > 0 ? `<span class="sb-mini sb-mini-warn">⚠ ${m.nw}</span>`
            : m.np > 0 ? `<span class="sb-mini sb-mini-pass">✓</span>` : '') : '';
      const typeClass = `ftype-${['log', 'pem', 'cer', 'crt', 'cert', 'csv'].includes(m.ext) ? m.ext : 'other'}`;
      row.innerHTML =
        `<span class="tar-fname">${_esc(m.name)}</span>` +
        `<span class="tar-ftype ${typeClass}" style="flex-shrink:0">${_esc(m.ext)}</span>` +
        logTypeBadge + certTypeBadge + verdictBadge +
        `<span class="tar-fsize">${_formatBytes(m.entry.size)}</span>`;
      return row;
    });

    rows.forEach(r => list.appendChild(r));

    let currentType = 'all', currentVerdict = '';
    const applyFilter = () => {
      const textVal = (filterBar.querySelector('#ff-text-search')?.value || '').toLowerCase();
      const evtVal = (filterBar.querySelector('#ff-evttype')?.value || '').toLowerCase();
      const opVal = (filterBar.querySelector('#ff-optype')?.value || '').toLowerCase();
      const clientVal = (filterBar.querySelector('#ff-client')?.value || '').toLowerCase();
      const txnVal = (filterBar.querySelector('#ff-txnnum')?.value || '').toLowerCase();
      let visible = 0;
      rows.forEach((r, idx) => {
        const m = fileMeta[idx];
        const tk = r.dataset.typeKey || 'other';
        const name = r.dataset.nameSearch || '';
        const typeOk = currentType === 'all' || currentType === tk
          || (currentType === 'cert' && tk !== 'sys' && tk !== 'txn' && tk !== 'audit');
        if (!typeOk) { r.style.display = 'none'; return; }
        if (currentVerdict === 'fail' && m.nf === 0) { r.style.display = 'none'; return; }
        if (currentVerdict === 'warn' && (m.nw === 0 || m.nf > 0)) { r.style.display = 'none'; return; }
        if (textVal && !name.includes(textVal)) { r.style.display = 'none'; return; }
        if (evtVal && (r.dataset.evtType || '').toLowerCase() !== evtVal) { r.style.display = 'none'; return; }
        if (opVal && (r.dataset.opType || '').toLowerCase() !== opVal) { r.style.display = 'none'; return; }
        if (clientVal && (r.dataset.clientId || '').toLowerCase() !== clientVal) { r.style.display = 'none'; return; }
        if (txnVal && !(r.dataset.txnNum || '').toLowerCase().includes(txnVal)) { r.style.display = 'none'; return; }
        r.style.display = ''; visible++;
      });
      typeRow.querySelectorAll('.ff-type-btn').forEach(btn => {
        if (btn.dataset.typeKey === currentType) {
          const orig = typeFilters.find(f => f.key === currentType);
          const total = orig?.count ?? visible;
          btn.querySelector('.ff-count').textContent = visible < total ? `${visible}/${total}` : String(total);
        }
      });
    };
    typeRow.addEventListener('click', e => {
      const btn = e.target.closest('.ff-type-btn');
      if (!btn) return;
      typeRow.querySelectorAll('.ff-type-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active'); currentType = btn.dataset.typeKey;
      buildCondFilters(currentType);
      condEl.querySelectorAll('select, input').forEach(el2 => el2.addEventListener('input', applyFilter));
      applyFilter();
    });
    const verdictRowEl = filterBar.querySelector('.ff-verdict-row');
    if (verdictRowEl) {
      verdictRowEl.addEventListener('click', e => {
        const btn = e.target.closest('.ff-verdict-btn'); if (!btn) return;
        const key = btn.dataset.verdictKey || '';
        currentVerdict = (currentVerdict === key) ? '' : key;
        verdictRowEl.querySelectorAll('.ff-verdict-btn').forEach(b => b.classList.remove('active'));
        if (currentVerdict) verdictRowEl.querySelector(`[data-verdict-key="${currentVerdict}"]`)?.classList.add('active');
        const clearBtn = verdictRowEl.querySelector('.ff-vbtn-clear');
        if (clearBtn) clearBtn.style.display = currentVerdict ? '' : 'none';
        applyFilter();
      });
    }
    filterBar.querySelector('#ff-text-search')?.addEventListener('input', applyFilter);
  }

  function renderCategory(container, catName, catResults, filterStatus, catIndex, runResult) {
    container.innerHTML = '';
    const el = Utils.cloneTemplate('tpl-category');

    const fails = catResults.filter(r => r.status === 'FAIL').length;
    const warns = catResults.filter(r => r.status === 'WARN').length;
    const passes = catResults.filter(r => r.status === 'PASS').length;
    const skips = catResults.filter(r => r.status === 'SKIP').length;
    const infos = catResults.filter(r => r.status === 'INFO').length;

    _setId(el, 'cp-num', catIndex != null ? `Kategorie ${catIndex} von 35` : '');
    _setId(el, 'cp-title', catName);
    _setId(el, 'cp-count',
      `${catResults.length} Prüfungen · ✗ ${fails} · ⚠ ${warns} · ✓ ${passes} · ℹ ${infos} · – ${skips}`);

    // Special: info.csv category → show parsed content above checks
    const isInfoCat = /EXP_INF/i.test(catName) || /info\.csv/i.test(catName);
    if (isInfoCat && runResult?.infoRows) {
      const infoPanel = _buildInfoCsvPanel(runResult.infoRows, runResult.tarResult);
      el.querySelector('#cp-check-list')?.before(infoPanel);
    }

    const list = el.querySelector('#cp-check-list');
    if (list) {
      const filtered = (!filterStatus || filterStatus === 'all')
        ? catResults
        : catResults.filter(r => r.status === filterStatus);
      if (filtered.length === 0) {
        list.innerHTML = `<div style="padding:30px;text-align:center;color:var(--text-muted)">Keine Prüfungen für diesen Filter.</div>`;
      } else {
        filtered.forEach(r => list.appendChild(_buildCheckRow(r)));
      }
    }

    container.appendChild(el);
  }

  function renderSidebar(sidebarList, byCategory, activeCat) {
    sidebarList.innerHTML = '';
    Object.entries(byCategory).forEach(([name, res]) => {
      const el = Utils.cloneTemplate('tpl-sidebar-cat');
      const nf = res.filter(r => r.status === 'FAIL').length;
      const nw = res.filter(r => r.status === 'WARN').length;
      const np = res.filter(r => r.status === 'PASS').length;
      const ni = res.filter(r => r.status === 'INFO').length;
      const ns = res.filter(r => r.status === 'SKIP').length;
      const allSkip = ns === res.length && res.length > 0;

      // Verdict determines border + background tint
      const verdict = nf > 0 ? 'fail' : nw > 0 ? 'warn' : np > 0 ? 'pass' : allSkip ? 'skip' : 'info';
      el.dataset.cat = name;
      if (name === activeCat) el.classList.add('active');
      el.style.borderLeft = `3px solid var(--${verdict})`;
      if (nf > 0) el.style.background = 'rgba(220,38,38,.08)';
      else if (nw > 0) el.style.background = 'rgba(217,119,6,.08)';
      else if (allSkip) el.style.background = 'rgba(107,114,128,.06)';
      else if (np > 0) el.style.background = 'rgba(22,163,74,.04)';

      const nameEl = el.querySelector('.sidebar-cat-name');
      const miniEl = el.querySelector('.sidebar-mini-counts');

      if (nameEl) nameEl.textContent = name;

      // Mini badges: show all non-zero counters
      if (miniEl) {
        const parts = [];
        if (nf > 0) parts.push(`<span class="smc smc-f">✗ ${nf}</span>`);
        if (nw > 0) parts.push(`<span class="smc smc-w">⚠ ${nw}</span>`);
        if (np > 0) parts.push(`<span class="smc smc-p">✓ ${np}</span>`);
        if (ni > 0) parts.push(`<span class="smc smc-i">ℹ ${ni}</span>`);
        if (ns > 0) parts.push(`<span class="smc smc-s">– ${ns}</span>`);
        // Only show mini badges if there's more than one type of status
        miniEl.innerHTML = parts.join('');
      }

      sidebarList.appendChild(el);
    });
  }

  // ── File Detail Page ─────────────────────────────────────────────────────
  function renderFileDetail(container, filename, logEntry, checkResults) {
    container.innerHTML = '';
    const bn = filename.split('/').pop();
    const f = logEntry;
    const st = r => (r.status || '').toUpperCase();
    const fails = checkResults.filter(r => st(r) === 'FAIL').length;
    const warns = checkResults.filter(r => st(r) === 'WARN').length;
    const passes = checkResults.filter(r => st(r) === 'PASS').length;

    const logTypeColor = { txn: '#7c3aed', sys: '#0369a1', audit: '#c2410c', TransactionLog: '#7c3aed', SystemLog: '#0369a1', AuditLog: '#c2410c' };
    const logTypeBg = { txn: '#ede9fe', sys: '#e0f2fe', audit: '#fff7ed', TransactionLog: '#ede9fe', SystemLog: '#e0f2fe', AuditLog: '#fff7ed' };
    const logTypeLabel = { sys: 'SystemLog', txn: 'TransactionLog', audit: 'AuditLog' };
    const lt = logTypeLabel[f.logType] || f.logTypeLabel || f.logType || 'Unbekannt';
    const ltColor = logTypeColor[f.logType] || logTypeColor[lt] || '#6b7280';
    const ltBg = logTypeBg[f.logType] || logTypeBg[lt] || '#f1f5f9';

    const verdict = fails > 0 ? 'fail' : warns > 0 ? 'warn' : 'pass';
    const verdictColor = { fail: 'var(--fail)', warn: 'var(--warn)', pass: 'var(--pass)' }[verdict];

    const fmtUnix = t => {
      if (t == null) return '–';
      if (t < 1000000) return String(t);
      try { return new Date(t * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC'); } catch (e) { return String(t); }
    };

    container.innerHTML = `
      <div style="margin-bottom:16px">
        <button class="btn btn-secondary" style="margin-bottom:12px" onclick="app.navigateTo('files')">← Dateien im Archiv</button>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <span style="font-size:20px">📄</span>
          <span style="padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;color:${ltColor};background:${ltBg};border:1px solid ${ltColor}40">${_esc(lt)}</span>
          <span style="font-family:var(--mono);font-size:14px;font-weight:700;color:var(--text)">${_esc(bn)}</span>
          <span style="margin-left:auto;display:flex;gap:6px">
            ${fails > 0 ? `<span class="status-badge sb-fail">✗ ${fails} Fehler</span>` : ''}
            ${warns > 0 ? `<span class="status-badge sb-warn">⚠ ${warns} Warnungen</span>` : ''}
            ${fails === 0 && warns === 0 ? '<span class="status-badge sb-pass">✓ OK</span>' : ''}
          </span>
        </div>
      </div>

      ${f.parseError ? `
        <div class="card" style="border-left:4px solid var(--fail);padding:20px">
          <div style="font-weight:700;color:var(--fail);margin-bottom:8px">⛔ ASN.1 Parse-Fehler</div>
          <pre style="font-size:12px;white-space:pre-wrap;color:var(--text-muted)">${_esc(f.parseError)}</pre>
        </div>
      ` : `
        <div class="card" style="margin-bottom:16px">
          <div style="padding:14px 16px 4px;font-size:12px;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.05em">Log-Felder (ASN.1 geparst)</div>
          <div class="cert-fields-grid" style="padding:8px 16px 14px">
            ${_kv('Log-Typ', `<span style="color:${ltColor};font-weight:600">${_esc(lt)}</span>`)}
            ${_kv('version', f.version != null ? `${f.version}${f.version === 3 ? ' <span style="color:var(--pass)">✓</span>' : ' <span style="color:var(--fail)">✗</span>'}` : '–')}
            ${_kv('certifiedDataType OID', `<code>${_esc(f.certifiedDataType || f.oid || '–')}</code>`)}
            ${_kv('signatureAlgorithm', `<code>${_esc(f.sigAlgName || '–')}</code>${f.sigAlgOID ? ` <span style="font-size:10px;color:var(--text-muted)">${_esc(f.sigAlgOID)}</span>` : ''}`)}
            ${_kv('signatureCounter', f.signatureCounter != null ? `<code>${f.signatureCounter}</code>` : '–')}
            ${_kv('signatureCreationTime', f.signatureCreationTime != null ? `<code>${fmtUnix(f.signatureCreationTime)}</code>` : '–')}
            ${_kv('serialNumber', f.serialNumber ? `<code style="font-size:10px;word-break:break-all">${f.serialNumber.slice(0, 64)}${f.serialNumber.length > 64 ? '…' : ''}</code>` : '–')}
            ${_kv('signatureValue', f.signatureValueLen != null ? `<code>${f.signatureValueLen} Byte (${(f.signatureValueHex || '').slice(0, 16)}…)</code>` : '–')}
            ${f.eventType != null ? _kv('eventType', `<code>${_esc(f.eventType)}</code>`) : ''}
            ${f.eventOrigin != null ? _kv('eventOrigin', `<code>${_esc(f.eventOrigin)}</code>`) : ''}
            ${f.eventTriggeredByUser != null ? _kv('eventTriggeredByUser', `<code>${_esc(f.eventTriggeredByUser)}</code>`) : ''}
            ${f.eventDataLen != null ? _kv('eventData',
      f.eventDataLen === 0
        ? '<span style="color:var(--text-muted)">leer (0 Byte) – leere SEQUENCE ✓</span>'
        : `<code>${f.eventDataLen} Byte${f.eventDataDecoded ? ' · ' + _esc(f.eventDataDecoded.slice(0, 120)) : ''}</code>`)
        : (lt === 'SystemLog' ? _kv('eventData', '<span style="color:var(--fail)">✗ fehlt (Pflichtfeld)</span>') : '')}
            ${f.operationType != null ? _kv('operationType', `<code style="color:var(--accent)">${_esc(f.operationType)}</code>`) : ''}
            ${f.transactionNumber != null ? _kv('transactionNumber', `<code>Nr. ${f.transactionNumber}</code>`) : ''}
            ${f.clientId != null ? _kv('clientId', `<code>${_esc(String(f.clientId))}</code>`) : ''}
            ${f.processType != null ? _kv('processType', _esc(f.processType)) : ''}
            ${f.processDataLen != null ? _kv('processData', `<code style="font-size:10px">${f.processDataLen} Byte${f.processDataText ? ' · ' + _esc(f.processDataText.slice(0, 80)) : ''}</code>`) : ''}
            ${f.additionalExternalDataPresent ? _kv('additionalExternalData',
          `<code style="font-size:10px">${f.additionalExternalDataLen} Byte${f.additionalExternalDataText ? ' · ' + _esc(f.additionalExternalDataText.slice(0, 80)) : ''}</code>`) : ''}
            ${f.seAuditDataLen != null ? _kv('seAuditData', `<code style="font-size:10px">${f.seAuditDataLen} Byte${f.seAuditDataDecoded ? '<br>' + _esc(f.seAuditDataDecoded.slice(0, 200)) : ''}${f.seAuditDataHex ? '<br><span style="color:var(--text-muted)">' + _esc(f.seAuditDataHex.slice(0, 48)) + '…</span>' : ''}</code>`) : ''}
          </div>
        </div>
      `}

      <div class="card">
        <div style="padding:14px 16px 0;display:flex;justify-content:space-between;align-items:center">
          <div style="font-size:13px;font-weight:700;color:var(--text)">TR-Prüfungen (${checkResults.length})</div>
          <div style="display:flex;gap:6px">
            ${fails > 0 ? `<span class="status-badge sb-fail">✗ ${fails}</span>` : ''}
            ${warns > 0 ? `<span class="status-badge sb-warn">⚠ ${warns}</span>` : ''}
            <span class="status-badge sb-pass">✓ ${passes}</span>
          </div>
        </div>
        <div class="check-list" id="file-check-list" style="margin-top:8px"></div>
      </div>
    `;

    const cl = container.querySelector('#file-check-list');
    if (cl) checkResults.forEach(r => cl.appendChild(_buildCheckRow(r)));
  }

  // ── Cert Detail Page ──────────────────────────────────────────────────────
  function renderCertDetail(container, filename, certEntry, checkResults) {
    container.innerHTML = '';
    const bn = filename.split('/').pop();
    const c = certEntry;
    const st = r => (r.status || '').toUpperCase();
    const fails = checkResults.filter(r => st(r) === 'FAIL').length;
    const warns = checkResults.filter(r => st(r) === 'WARN').length;
    const passes = checkResults.filter(r => st(r) === 'PASS').length;

    const certType = c._certType || 'leaf';
    const certTypeLabel = c._certTypeLabel || 'TSE-Blatt';
    const typeColors = { root: '#d97706', subca: '#7c3aed', leaf: '#2563eb' };
    const typeBgs = { root: '#fffbeb', subca: '#ede9fe', leaf: '#eff6ff' };
    const tc = typeColors[certType] || '#6b7280';
    const tb = typeBgs[certType] || '#f9fafb';

    const fmtD = d => d ? d.toISOString().split('T')[0] : '–';
    const now = new Date();
    const vNow = c.notBefore && c.notAfter && c.notBefore <= now && now <= c.notAfter;

    container.innerHTML = `
      <div style="margin-bottom:16px">
        <button class="btn btn-secondary" style="margin-bottom:12px" onclick="app.navigateTo('files')">← Dateien im Archiv</button>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <span style="font-size:20px">🔐</span>
          <span style="padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;color:${tc};background:${tb};border:1px solid ${tc}40">${_esc(certTypeLabel)}</span>
          <span style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis">${_esc(bn)}</span>
          <span style="margin-left:auto;display:flex;gap:6px">
            ${fails > 0 ? `<span class="status-badge sb-fail">✗ ${fails}</span>` : ''}
            ${warns > 0 ? `<span class="status-badge sb-warn">⚠ ${warns}</span>` : ''}
            ${fails === 0 && warns === 0 ? '<span class="status-badge sb-pass">✓ OK</span>' : ''}
          </span>
        </div>
      </div>

      ${c.parseError ? `<div class="card" style="border-left:4px solid var(--fail);padding:20px"><div style="font-weight:700;color:var(--fail)">⛔ ASN.1 Parse-Fehler</div><pre style="font-size:12px">${_esc(c.parseError)}</pre></div>` : `
        <div class="card" style="margin-bottom:16px">
          <div style="padding:14px 16px 4px;font-size:12px;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.05em">Zertifikat-Felder</div>
          <div class="cert-fields-grid" style="padding:8px 16px 14px">
            ${_kv('Typ', `<span style="color:${tc};font-weight:600">${_esc(certTypeLabel)}</span>`)}
            ${_kv('Seriennummer', `<code style="font-size:10px;word-break:break-all">${_esc(c.serialNumber || '–')}</code>`)}
            ${_kv('Subject CN', `<code>${_esc(c.subjectDN?.CN || c.subjectDN?.O || '–')}</code>`)}
            ${_kv('Issuer CN', `<code>${_esc(c.issuerDN?.CN || c.issuerDN?.O || '–')}</code>`)}
            ${_kv('Gültig ab', `<code>${fmtD(c.notBefore)}</code>`)}
            ${_kv('Gültig bis', `<code style="color:${vNow ? 'var(--pass)' : 'var(--warn)'}">${fmtD(c.notAfter)}${vNow ? '' : ' ⚠'}</code>`)}
            ${c.pkupNotAfter ? _kv('Private Key bis', `<code>${fmtD(c.pkupNotAfter)}</code>`) : ''}
            ${_kv('Signaturalgorithmus', _esc(c.sigAlgName || c.signatureAlgorithm || '–'))}
            ${_kv('Schlüsselkurve', _esc(c.curveName || c.publicKeyCurve || '–'))}
            ${_kv('Basic Constraints', `<code>CA:${c.isCA ? 'TRUE' : 'FALSE'}${c.pathLen !== undefined ? `, pathlen:${c.pathLen}` : ''}</code>`)}
            ${_kv('SKI', `<code style="font-size:10px;word-break:break-all">${_esc(c.skiValue || '–')}</code>`)}
            ${c.akiValue ? _kv('AKI', `<code style="font-size:10px;word-break:break-all">${_esc(c.akiValue)}</code>`) : ''}
            ${(c.crlDistPoints || []).length > 0 ? _kv('CRL Distribution Point', `<a href="${_esc(c.crlDistPoints[0])}" style="font-size:11px;color:var(--accent)" target="_blank">${_esc(c.crlDistPoints[0])}</a>`) : ''}
            ${c.bsiTseOID ? _kv('BSI-TSE-OID', `<code>${_esc(c.bsiTseOID)}</code>`) : ''}
          </div>
        </div>
      `}

      <div class="card">
        <div style="padding:14px 16px 0;display:flex;justify-content:space-between;align-items:center">
          <div style="font-size:13px;font-weight:700;color:var(--text)">BSI TR-Prüfungen (${checkResults.length})</div>
          <div style="display:flex;gap:6px">
            ${fails > 0 ? `<span class="status-badge sb-fail">✗ ${fails}</span>` : ''}
            ${warns > 0 ? `<span class="status-badge sb-warn">⚠ ${warns}</span>` : ''}
            <span class="status-badge sb-pass">✓ ${passes}</span>
          </div>
        </div>
        <div class="check-list" id="cert-check-list" style="margin-top:8px"></div>
      </div>
    `;

    const cl = container.querySelector('#cert-check-list');
    if (cl) checkResults.forEach(r => cl.appendChild(_buildCheckRow(r)));
  }

  // ── Private builders ─────────────────────────────────────────────────────

  function _buildInfoCsvPanel(infoRows, tarResult) {
    const { components, description, unknownLines, raw } = infoRows;
    const REQUIRED = ['manufacturer', 'model', 'version', 'certification-id'];

    const panel = document.createElement('div');
    panel.style.marginBottom = '16px';

    // Components table
    const compRows = components.map(c => {
      const fldCell = (v, key) => {
        const ok = !!v;
        return `<td style="${ok ? '' : 'color:var(--fail);font-weight:600;background:var(--fail-bg)'}">
          ${ok ? _esc(v) : `✗ leer`}</td>`;
      };
      return `<tr>
        <td class="td-key">${_esc(c.component)}${c.validComponent ? '' : ' <span style="color:var(--fail)">✗</span>'}</td>
        ${fldCell(c.manufacturer)}
        ${fldCell(c.model)}
        ${fldCell(c.version)}
        <td style="font-family:var(--mono);font-size:10px${c['certification-id'] ? '' : ';color:var(--fail);font-weight:600;background:var(--fail-bg)'}">
          ${c['certification-id'] ? _esc(c['certification-id']) : '✗ leer'}</td>
        <td style="text-align:center">${c.validComponent
          ? '<span style="color:var(--pass);font-weight:700">✓</span>'
          : '<span style="color:var(--fail);font-weight:700">✗</span>'}</td>
      </tr>`;
    }).join('');

    panel.innerHTML = `
      <div class="card" style="margin-bottom:12px">
        <div style="padding:12px 16px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border)">
          <span style="font-size:16px">🏗</span>
          <div>
            <div style="font-size:13px;font-weight:700">Komponenten</div>
            <div style="font-size:11px;color:var(--text-muted)">Gültige Bezeichner: device · storage · integration-interface · CSP · SMA</div>
          </div>
        </div>
        <div style="overflow-x:auto">
          <table style="width:100%;border-collapse:collapse;font-size:12px">
            <thead><tr style="background:var(--sidebar-bg);border-bottom:2px solid var(--border)">
              <th style="padding:8px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--text-secondary)">Komponente</th>
              <th style="padding:8px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--text-secondary)">Hersteller</th>
              <th style="padding:8px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--text-secondary)">Modell</th>
              <th style="padding:8px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--text-secondary)">Version</th>
              <th style="padding:8px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--text-secondary)">Zertifizierungs-ID</th>
              <th style="padding:8px 12px;text-align:center;font-size:11px;font-weight:700;color:var(--text-secondary)">Gültig</th>
            </tr></thead>
            <tbody>
              ${compRows || `<tr><td colspan="6" style="padding:16px;text-align:center;color:var(--text-muted)">Keine Komponentenzeilen</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
        <div class="card">
          <div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:6px;align-items:center">
            <span>📝</span><span style="font-size:12px;font-weight:700">Beschreibung (description:)</span>
          </div>
          <div style="padding:10px 14px;font-family:var(--mono);font-size:12px;color:var(--text)">
            ${description !== null
        ? (description || '<span style="color:var(--text-muted)">(leer)</span>')
        : '<span style="color:var(--fail)">✗ Keine description:-Zeile</span>'}
          </div>
        </div>
        <div class="card">
          <div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:6px;align-items:center">
            <span>📄</span><span style="font-size:12px;font-weight:700">Rohdaten info.csv</span>
          </div>
          <div style="padding:10px 14px;font-family:var(--mono);font-size:11px;white-space:pre-wrap;word-break:break-all;color:var(--text-muted);max-height:160px;overflow-y:auto">${_esc(raw || '(nicht gefunden)')}</div>
        </div>
      </div>
    `;
    return panel;
  }

  function _buildCatCard(catName, catResults) {
    const card = Utils.cloneTemplate('tpl-ov-cat-card');
    const st = r => (r.status || '').toUpperCase();
    const fails = catResults.filter(r => st(r) === 'FAIL').length;
    const warns = catResults.filter(r => st(r) === 'WARN').length;
    const passes = catResults.filter(r => st(r) === 'PASS').length;
    const skips = catResults.filter(r => st(r) === 'SKIP').length;

    card.dataset.cat = catName;
    card.style.cursor = 'pointer';

    if (fails > 0) { card.style.borderLeft = '4px solid var(--fail)'; card.style.background = '#fff8f8'; }
    else if (warns > 0) { card.style.borderLeft = '4px solid var(--warn)'; card.style.background = '#fffdf5'; }
    else if (passes > 0) { card.style.borderLeft = '4px solid var(--pass)'; }
    else { card.style.borderLeft = '4px solid var(--info)'; }

    const nameEl = card.querySelector('.overview-cat-name');
    if (nameEl) nameEl.textContent = catName;

    const idEl = card.querySelector('.overview-cat-id');
    if (idEl) {
      idEl.innerHTML = [
        fails > 0 ? `<span style="color:var(--fail);font-weight:700">✗ ${fails}</span>` : '',
        warns > 0 ? `<span style="color:var(--warn);font-weight:700">⚠ ${warns}</span>` : '',
        passes > 0 ? `<span style="color:var(--pass)">✓ ${passes}</span>` : '',
        skips > 0 ? `<span style="color:var(--skip)">– ${skips}</span>` : '',
      ].filter(Boolean).join('&nbsp; ');
    }

    const bar = card.querySelector('.cat-status-bar');
    if (bar) {
      bar.innerHTML = `<div style="display:flex;height:5px;border-radius:3px;overflow:hidden;gap:1px;margin-top:8px">
        <div style="flex:${fails};background:var(--fail)"></div>
        <div style="flex:${warns};background:var(--warn)"></div>
        <div style="flex:${passes};background:var(--pass)"></div>
        <div style="flex:${skips};background:var(--skip)"></div>
      </div>`;
    }
    return card;
  }

  function _buildCheckRow(result) {
    const row = Utils.cloneTemplate('tpl-check-row');
    const s = result.status;
    row.dataset.checkId = result.id;
    row.classList.add(`status-${s.toLowerCase()}`);

    _setQ(row, '.check-id', result.id);
    _setQ(row, '.check-name', result.name);

    const short = (result.detail || '').split('\n')[0].slice(0, 120);
    _setQ(row, '.check-short-detail', short);

    const dot = row.querySelector('.check-dot');
    if (dot) dot.className = `check-dot cd-${s.toLowerCase()}`;

    const badge = row.querySelector('.status-badge');
    if (badge) {
      badge.textContent = s;
      badge.className = `status-badge sb-${s.toLowerCase()}`;
    }

    // Rule text: from result OR from rulesDB
    const ruleInfo = _rulesDB[result.id];
    const ruleText = result.ruleText || (ruleInfo && ruleInfo.rule) || '';
    const refText = result.ref || (ruleInfo && ruleInfo.ref) || '';

    _setQ(row, '.check-rule-body', ruleText);
    _setQ(row, '.check-detail-box', result.detail || '–');
    _setQ(row, '.check-ref', refText ? `📎 ${refText}` : '');

    // If we have extra rule info from DB, add it
    if (ruleInfo) {
      const extras = [];
      if (ruleInfo.pass_text) extras.push(`✓ Bestanden: ${ruleInfo.pass_text}`);
      if (ruleInfo.fail_text) extras.push(`✗ Fehler: ${ruleInfo.fail_text}`);
      if (ruleInfo.warn_text) extras.push(`⚠ Warnung: ${ruleInfo.warn_text}`);
      if (ruleInfo.regex) extras.push(`Regex: ${ruleInfo.regex}`);
      if (ruleInfo.allowed) extras.push(`Erlaubte Werte: ${ruleInfo.allowed}`);
      if (extras.length > 0) {
        const ruleExtra = row.querySelector('.check-rule-extra');
        if (ruleExtra) {
          ruleExtra.innerHTML = extras.map(e => `<div style="padding:2px 0;border-bottom:1px solid #fde68a20">${_esc(e)}</div>`).join('');
          ruleExtra.style.display = 'block';
        }
      }
    }

    const details = row.querySelector('.check-details');
    if (details) details.style.display = 'none';

    return row;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function _setId(parent, id, text) {
    const el = parent.querySelector('#' + id);
    if (el) el.textContent = String(text ?? '');
  }
  function _setQ(parent, sel, text) {
    const el = parent.querySelector(sel);
    if (el) el.textContent = String(text ?? '');
  }
  function _barW(parent, id, pct) {
    const el = parent.querySelector('#' + id);
    if (el) el.style.width = Math.min(100, Math.round(pct)) + '%';
  }
  function _fillMeta(parent, sel, rows) {
    const el = parent.querySelector(sel);
    if (!el) return;
    el.innerHTML = rows.map(([k, v]) =>
      `<div class="meta-kv-row"><span class="meta-key">${_esc(k)}</span>
       <span class="meta-val">${_esc(String(v))}</span></div>`
    ).join('');
  }
  function _kv(label, valueHtml) {
    return `<div class="cert-field">
      <div class="cf-label">${_esc(label)}</div>
      <div class="cf-value">${valueHtml}</div>
    </div>`;
  }
  function _formatBytes(b) {
    if (!b) return '0 B';
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
  }
  function _esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').trim();
  }

  return { renderWelcome, renderAnalyzing, renderOverview, renderAllFiles, renderAllTests, renderCategory, renderSidebar, renderFileDetail, renderCertDetail };
})();
