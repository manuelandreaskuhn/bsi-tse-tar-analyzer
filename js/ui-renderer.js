// ─── ui-renderer.js ───────────────────────────────────────────────────────
'use strict';

window.UIRenderer = (function () {

  const ICON  = { PASS: '✓', FAIL: '✗', WARN: '⚠', INFO: 'ℹ', SKIP: '–' };
  const LABEL = { PASS: 'KONFORM', FAIL: 'NICHT KONFORM', WARN: 'BEDINGT KONFORM', INFO: 'INFO' };

  // Rules database (loaded async from rules.json)
  let _rulesDB = {};
  function loadRulesDB() {
    fetch('rules.json')
      .then(r => r.json())
      .then(db => { _rulesDB = db; })
      .catch(() => {});
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
    _setId(el, 'analyzing-sub',  'Bitte warten…');
    container.appendChild(el);
  }

  function renderOverview(container, runResult, archiveName, archiveType) {
    const { stats, byCategory, parsedLogs, parsedCerts, infoRows, tarResult, perFileResults, perCertResults } = runResult;
    container.innerHTML = '';
    const el = Utils.cloneTemplate('tpl-overview');
    const v  = stats.verdict;

    const banner = el.querySelector('#ov-verdict');
    if (banner) banner.classList.add(v === 'FAIL' ? 'verdict-fail' : v === 'WARN' ? 'verdict-warn' : 'verdict-pass');

    _setId(el, 'ov-verdict-icon',  ICON[v] || '?');
    _setId(el, 'ov-verdict-title', LABEL[v] || v);
    _setId(el, 'ov-verdict-sub',   `${stats.fail} Fehler · ${stats.warn} Warnungen · ${stats.pass} bestanden`);
    _setId(el, 'ov-verdict-meta',  `${stats.total} Prüfungen · ${stats.logCount} Logs · ${stats.certCount} Zertifikate`);
    _setId(el, 'ov-sub', archiveName || '');

    _setId(el, 'stat-total', stats.total);
    _setId(el, 'stat-pass',  stats.pass);
    _setId(el, 'stat-fail',  stats.fail);
    _setId(el, 'stat-warn',  stats.warn);
    _setId(el, 'stat-info',  stats.info);
    _setId(el, 'stat-skip',  stats.skip);

    const t = stats.total || 1;
    _barW(el, 'bar-pass', stats.pass / t * 100);
    _barW(el, 'bar-fail', stats.fail / t * 100);
    _barW(el, 'bar-warn', stats.warn / t * 100);
    _barW(el, 'bar-info', stats.info / t * 100);
    _barW(el, 'bar-skip', stats.skip / t * 100);

    _fillMeta(el, '#meta-archive', [
      ['Dateiname', archiveName || '–'],
      ['Typ', archiveType === 'cert-export' ? 'CertificateExport' : 'Standard-Export'],
      ['Parse-Fehler', stats.parseErrors],
    ]);
    _fillMeta(el, '#meta-files', [
      ['Log-Nachrichten', stats.logCount],
      ['Zertifikate', stats.certCount],
    ]);
    _fillMeta(el, '#meta-params', [
      ['Kategorien', Object.keys(byCategory).length],
      ['Checks gesamt', stats.total],
    ]);

    // TAR file list (now with per-file verdict badges)
    if (tarResult) {
      const files = [...tarResult.files.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]));
      _setId(el, 'ov-tar-file-title', `Dateien im Archiv (${files.length})`);
      _setId(el, 'ov-tar-file-count', String(files.length));
      const listEl = el.querySelector('#ov-tar-file-list');
      if (listEl) {
        files.forEach(([name, entry]) => {
          const ext = name.split('.').pop().toLowerCase();
          const isLog  = ext === 'log';
          const isCert = ['pem','cer','crt','cert','der'].includes(ext);
          const isInfo = name.toLowerCase() === 'info.csv';

          const row = document.createElement('div');
          row.className = 'tar-file-row';

          // Verdict badge from per-file results
          let verdictBadge = '';
          if (isLog && perFileResults && perFileResults[name]) {
            const rs = perFileResults[name];
            const f = rs.filter(r => r.status === 'FAIL').length;
            const w = rs.filter(r => r.status === 'WARN').length;
            const p = rs.filter(r => r.status === 'PASS').length;
            if (f > 0) verdictBadge = `<span class="sb-mini sb-mini-fail">✗ ${f}</span>`;
            else if (w > 0) verdictBadge = `<span class="sb-mini sb-mini-warn">⚠ ${w}</span>`;
            else if (p > 0) verdictBadge = `<span class="sb-mini sb-mini-pass">✓</span>`;
            row.dataset.logFile = name;
            row.style.cursor = 'pointer';
            row.title = 'Klicken für Datei-Details';
          }
          if (isCert && perCertResults && perCertResults[name]) {
            const rs = perCertResults[name];
            const f = rs.filter(r => r.status === 'FAIL').length;
            const w = rs.filter(r => r.status === 'WARN').length;
            const p = rs.filter(r => r.status === 'PASS').length;
            if (f > 0) verdictBadge = `<span class="sb-mini sb-mini-fail">✗ ${f}</span>`;
            else if (w > 0) verdictBadge = `<span class="sb-mini sb-mini-warn">⚠ ${w}</span>`;
            else if (p > 0) verdictBadge = `<span class="sb-mini sb-mini-pass">✓</span>`;
            row.dataset.certFile = name;
            row.style.cursor = 'pointer';
            row.title = 'Klicken für Zertifikat-Details';
          }

          const typeClass = `ftype-${['log','pem','cer','crt','cert','csv'].includes(ext) ? ext : 'other'}`;
          row.innerHTML = `<span class="tar-fname">${_esc(name)}</span>
            <span class="tar-ftype ${typeClass}">${_esc(ext)}</span>
            ${verdictBadge}
            <span class="tar-fsize">${_formatBytes(entry.size)}</span>`;
          listEl.appendChild(row);
        });
      }
    }

    // Category grid
    const grid = el.querySelector('#ov-cat-grid');
    if (grid) {
      Object.entries(byCategory).forEach(([name, res]) => grid.appendChild(_buildCatCard(name, res)));
    }

    container.appendChild(el);
  }

  function renderCategory(container, catName, catResults, filterStatus, catIndex, runResult) {
    container.innerHTML = '';
    const el = Utils.cloneTemplate('tpl-category');

    const fails  = catResults.filter(r => r.status === 'FAIL').length;
    const warns  = catResults.filter(r => r.status === 'WARN').length;
    const passes = catResults.filter(r => r.status === 'PASS').length;
    const skips  = catResults.filter(r => r.status === 'SKIP').length;
    const infos  = catResults.filter(r => r.status === 'INFO').length;

    _setId(el, 'cp-num',   catIndex != null ? `Kategorie ${catIndex} von 35` : '');
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
      const fails  = res.filter(r => r.status === 'FAIL').length;
      const warns  = res.filter(r => r.status === 'WARN').length;
      const passes = res.filter(r => r.status === 'PASS').length;
      const verdict = fails > 0 ? 'fail' : warns > 0 ? 'warn' : passes > 0 ? 'pass' : 'info';

      el.dataset.cat = name;
      if (name === activeCat) el.classList.add('active');
      el.style.borderLeft = `3px solid var(--${verdict})`;
      if (fails > 0) el.style.background = 'rgba(220,38,38,.05)';
      else if (warns > 0) el.style.background = 'rgba(217,119,6,.05)';

      const nameEl  = el.querySelector('.sidebar-cat-name');
      const countEl = el.querySelector('.sidebar-cat-count');
      if (nameEl)  nameEl.textContent  = name;
      if (countEl) {
        countEl.textContent = fails > 0 ? `✗${fails}` : warns > 0 ? `⚠${warns}` : `✓${passes}`;
        countEl.className = `sidebar-cat-count ${fails>0?'has-fail':warns>0?'has-warn':'all-pass'}`;
      }
      sidebarList.appendChild(el);
    });
  }

  // ── File Detail Page ─────────────────────────────────────────────────────
  function renderFileDetail(container, filename, logEntry, checkResults) {
    container.innerHTML = '';
    const bn = filename.split('/').pop();
    const f  = logEntry;

    const fails = checkResults.filter(r => r.status === 'FAIL').length;
    const warns = checkResults.filter(r => r.status === 'WARN').length;
    const passes= checkResults.filter(r => r.status === 'PASS').length;

    const logTypeColor = { TransactionLog:'#7c3aed', SystemLog:'#0369a1', AuditLog:'#c2410c' };
    const logTypeBg    = { TransactionLog:'#ede9fe', SystemLog:'#e0f2fe', AuditLog:'#fff7ed' };
    const lt = f.logType || 'Unbekannt';
    const ltColor = logTypeColor[lt] || '#6b7280';
    const ltBg    = logTypeBg[lt]    || '#f1f5f9';

    const verdict = fails > 0 ? 'fail' : warns > 0 ? 'warn' : 'pass';
    const verdictColor = {fail:'var(--fail)',warn:'var(--warn)',pass:'var(--pass)'}[verdict];

    const fmtUnix = t => {
      if (t == null) return '–';
      if (t < 1000000) return String(t);
      try { return new Date(t * 1000).toISOString().replace('T',' ').replace('Z',' UTC'); } catch(e) { return String(t); }
    };

    container.innerHTML = `
      <div style="margin-bottom:16px">
        <button class="btn btn-secondary" style="margin-bottom:12px" onclick="app.navigateTo('overview')">← Übersicht</button>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <span style="font-size:20px">📄</span>
          <span style="padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;color:${ltColor};background:${ltBg};border:1px solid ${ltColor}40">${_esc(lt)}</span>
          <span style="font-family:var(--mono);font-size:14px;font-weight:700;color:var(--text)">${_esc(bn)}</span>
          <span style="margin-left:auto;display:flex;gap:6px">
            ${fails>0?`<span class="status-badge sb-fail">✗ ${fails} Fehler</span>`:''}
            ${warns>0?`<span class="status-badge sb-warn">⚠ ${warns} Warnungen</span>`:''}
            ${fails===0&&warns===0?'<span class="status-badge sb-pass">✓ OK</span>':''}
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
            ${_kv('version', f.version != null ? `${f.version}${f.version===3?' <span style="color:var(--pass)">✓</span>':' <span style="color:var(--fail)">✗</span>'}` : '–')}
            ${_kv('certifiedDataType OID', `<code>${_esc(f.certifiedDataType || f.oid || '–')}</code>`)}
            ${_kv('signatureAlgorithm', _esc(f.sigAlgName || f.signatureAlgorithm || '–'))}
            ${_kv('signatureCounter', f.signatureCounter != null ? `<code>${f.signatureCounter}</code>` : '–')}
            ${_kv('signatureCreationTime', f.signatureCreationTime != null ? `<code>${fmtUnix(f.signatureCreationTime)}</code>` : '–')}
            ${_kv('serialNumber', f.serialNumber ? `<code style="font-size:10px;word-break:break-all">${f.serialNumber.slice(0,64)}${f.serialNumber.length>64?'…':''}</code>` : '–')}
            ${_kv('signatureValue', f.signatureValueLen != null ? `<code>${f.signatureValueLen} Byte (${(f.signatureValueHex||'').slice(0,16)}…)</code>` : '–')}
            ${f.eventType   != null ? _kv('eventType',   `<code>${_esc(f.eventType)}</code>`) : ''}
            ${f.eventOrigin != null ? _kv('eventOrigin', `<code>${_esc(f.eventOrigin)}</code>`) : ''}
            ${f.eventTriggeredByUser != null ? _kv('eventTriggeredByUser', `<code>${f.eventTriggeredByUser}</code>`) : ''}
            ${f.operationType != null ? _kv('operationType', `<code style="color:var(--accent)">${_esc(f.operationType)}</code>`) : ''}
            ${f.transactionNumber != null ? _kv('transactionNumber', `<code>Nr. ${f.transactionNumber}</code>`) : ''}
            ${f.clientId != null ? _kv('clientId', `<code>${_esc(String(f.clientId))}</code>`) : ''}
            ${f.processType != null ? _kv('processType', _esc(f.processType)) : ''}
            ${f.processDataLen != null ? _kv('processData', `<code style="font-size:10px">${f.processDataLen} Byte${f.processDataText ? ' · ' + _esc(f.processDataText.slice(0,80)) : ''}</code>`) : ''}
            ${f.seAuditDataLen != null ? _kv('seAuditData', `<code style="font-size:10px">${f.seAuditDataLen} Byte${f.seAuditDataDecoded ? '<br>' + _esc(f.seAuditDataDecoded.slice(0,200)) : ''}</code>`) : ''}
          </div>
        </div>
      `}

      <div class="card">
        <div style="padding:14px 16px 0;display:flex;justify-content:space-between;align-items:center">
          <div style="font-size:13px;font-weight:700;color:var(--text)">TR-Prüfungen (${checkResults.length})</div>
          <div style="display:flex;gap:6px">
            ${fails>0?`<span class="status-badge sb-fail">✗ ${fails}</span>`:''}
            ${warns>0?`<span class="status-badge sb-warn">⚠ ${warns}</span>`:''}
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
    const c  = certEntry;

    const fails = checkResults.filter(r => r.status === 'FAIL').length;
    const warns = checkResults.filter(r => r.status === 'WARN').length;
    const passes= checkResults.filter(r => r.status === 'PASS').length;

    const certType = c._certType || 'leaf';
    const certTypeLabel = c._certTypeLabel || 'TSE-Blatt';
    const typeColors = { root: '#d97706', subca: '#7c3aed', leaf: '#2563eb' };
    const typeBgs    = { root: '#fffbeb', subca: '#ede9fe', leaf: '#eff6ff' };
    const tc = typeColors[certType] || '#6b7280';
    const tb = typeBgs[certType]    || '#f9fafb';

    const fmtD = d => d ? d.toISOString().split('T')[0] : '–';
    const now  = new Date();
    const vNow = c.notBefore && c.notAfter && c.notBefore <= now && now <= c.notAfter;

    container.innerHTML = `
      <div style="margin-bottom:16px">
        <button class="btn btn-secondary" style="margin-bottom:12px" onclick="app.navigateTo('overview')">← Übersicht</button>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <span style="font-size:20px">🔐</span>
          <span style="padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;color:${tc};background:${tb};border:1px solid ${tc}40">${_esc(certTypeLabel)}</span>
          <span style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis">${_esc(bn)}</span>
          <span style="margin-left:auto;display:flex;gap:6px">
            ${fails>0?`<span class="status-badge sb-fail">✗ ${fails}</span>`:''}
            ${warns>0?`<span class="status-badge sb-warn">⚠ ${warns}</span>`:''}
            ${fails===0&&warns===0?'<span class="status-badge sb-pass">✓ OK</span>':''}
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
            ${_kv('Issuer CN',  `<code>${_esc(c.issuerDN?.CN || c.issuerDN?.O || '–')}</code>`)}
            ${_kv('Gültig ab', `<code>${fmtD(c.notBefore)}</code>`)}
            ${_kv('Gültig bis', `<code style="color:${vNow?'var(--pass)':'var(--warn)'}">${fmtD(c.notAfter)}${vNow?'':' ⚠'}</code>`)}
            ${c.pkupNotAfter ? _kv('Private Key bis', `<code>${fmtD(c.pkupNotAfter)}</code>`) : ''}
            ${_kv('Signaturalgorithmus', _esc(c.sigAlgName || c.signatureAlgorithm || '–'))}
            ${_kv('Schlüsselkurve', _esc(c.curveName || c.publicKeyCurve || '–'))}
            ${_kv('Basic Constraints', `<code>CA:${c.isCA ? 'TRUE' : 'FALSE'}${c.pathLen !== undefined ? `, pathlen:${c.pathLen}` : ''}</code>`)}
            ${_kv('SKI', `<code style="font-size:10px;word-break:break-all">${_esc(c.skiValue || '–')}</code>`)}
            ${c.akiValue ? _kv('AKI', `<code style="font-size:10px;word-break:break-all">${_esc(c.akiValue)}</code>`) : ''}
            ${(c.crlDistPoints||[]).length > 0 ? _kv('CRL Distribution Point', `<a href="${_esc(c.crlDistPoints[0])}" style="font-size:11px;color:var(--accent)" target="_blank">${_esc(c.crlDistPoints[0])}</a>`) : ''}
            ${c.bsiTseOID ? _kv('BSI-TSE-OID', `<code>${_esc(c.bsiTseOID)}</code>`) : ''}
          </div>
        </div>
      `}

      <div class="card">
        <div style="padding:14px 16px 0;display:flex;justify-content:space-between;align-items:center">
          <div style="font-size:13px;font-weight:700;color:var(--text)">BSI TR-Prüfungen (${checkResults.length})</div>
          <div style="display:flex;gap:6px">
            ${fails>0?`<span class="status-badge sb-fail">✗ ${fails}</span>`:''}
            ${warns>0?`<span class="status-badge sb-warn">⚠ ${warns}</span>`:''}
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
    const REQUIRED = ['manufacturer','model','version','certification-id'];

    const panel = document.createElement('div');
    panel.style.marginBottom = '16px';

    // Components table
    const compRows = components.map(c => {
      const fldCell = (v, key) => {
        const ok = !!v;
        return `<td style="${ok?'':'color:var(--fail);font-weight:600;background:var(--fail-bg)'}">
          ${ok ? _esc(v) : `✗ leer`}</td>`;
      };
      return `<tr>
        <td class="td-key">${_esc(c.component)}${c.validComponent ? '' : ' <span style="color:var(--fail)">✗</span>'}</td>
        ${fldCell(c.manufacturer)}
        ${fldCell(c.model)}
        ${fldCell(c.version)}
        <td style="font-family:var(--mono);font-size:10px${c['certification-id']?'':';color:var(--fail);font-weight:600;background:var(--fail-bg)'}">
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
          <div style="padding:10px 14px;font-family:var(--mono);font-size:11px;white-space:pre-wrap;word-break:break-all;color:var(--text-muted);max-height:160px;overflow-y:auto">
            ${_esc(raw || '(nicht gefunden)')}
          </div>
        </div>
      </div>
    `;
    return panel;
  }

  function _buildCatCard(catName, catResults) {
    const card = Utils.cloneTemplate('tpl-ov-cat-card');
    const fails  = catResults.filter(r => r.status === 'FAIL').length;
    const warns  = catResults.filter(r => r.status === 'WARN').length;
    const passes = catResults.filter(r => r.status === 'PASS').length;
    const skips  = catResults.filter(r => r.status === 'SKIP').length;

    card.dataset.cat = catName;
    card.style.cursor = 'pointer';

    if (fails > 0)       { card.style.borderLeft = '4px solid var(--fail)'; card.style.background = '#fff8f8'; }
    else if (warns > 0)  { card.style.borderLeft = '4px solid var(--warn)'; card.style.background = '#fffdf5'; }
    else if (passes > 0) { card.style.borderLeft = '4px solid var(--pass)'; }
    else                 { card.style.borderLeft = '4px solid var(--info)'; }

    const nameEl = card.querySelector('.overview-cat-name');
    if (nameEl) nameEl.textContent = catName;

    const idEl = card.querySelector('.overview-cat-id');
    if (idEl) {
      idEl.innerHTML = [
        fails  > 0 ? `<span style="color:var(--fail);font-weight:700">✗ ${fails}</span>` : '',
        warns  > 0 ? `<span style="color:var(--warn);font-weight:700">⚠ ${warns}</span>` : '',
        passes > 0 ? `<span style="color:var(--pass)">✓ ${passes}</span>` : '',
        skips  > 0 ? `<span style="color:var(--skip)">– ${skips}</span>` : '',
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
    const s   = result.status;
    row.dataset.checkId = result.id;
    row.classList.add(`status-${s.toLowerCase()}`);

    _setQ(row, '.check-id',   result.id);
    _setQ(row, '.check-name', result.name);

    const short = (result.detail || '').split('\n')[0].slice(0, 120);
    _setQ(row, '.check-short-detail', short);

    const dot = row.querySelector('.check-dot');
    if (dot) dot.className = `check-dot cd-${s.toLowerCase()}`;

    const badge = row.querySelector('.status-badge');
    if (badge) {
      badge.textContent = s;
      badge.className   = `status-badge sb-${s.toLowerCase()}`;
    }

    // Rule text: from result OR from rulesDB
    const ruleInfo = _rulesDB[result.id];
    const ruleText = result.ruleText || (ruleInfo && ruleInfo.rule) || '';
    const refText  = result.ref || (ruleInfo && ruleInfo.ref) || '';

    _setQ(row, '.check-rule-body',  ruleText);
    _setQ(row, '.check-detail-box', result.detail || '–');
    _setQ(row, '.check-ref',        refText ? `📎 ${refText}` : '');

    // If we have extra rule info from DB, add it
    if (ruleInfo) {
      const extras = [];
      if (ruleInfo.pass_text) extras.push(`✓ Bestanden: ${ruleInfo.pass_text}`);
      if (ruleInfo.fail_text) extras.push(`✗ Fehler: ${ruleInfo.fail_text}`);
      if (ruleInfo.warn_text) extras.push(`⚠ Warnung: ${ruleInfo.warn_text}`);
      if (ruleInfo.regex)     extras.push(`Regex: ${ruleInfo.regex}`);
      if (ruleInfo.allowed)   extras.push(`Erlaubte Werte: ${ruleInfo.allowed}`);
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
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  return { renderWelcome, renderAnalyzing, renderOverview, renderCategory, renderSidebar, renderFileDetail, renderCertDetail };
})();
