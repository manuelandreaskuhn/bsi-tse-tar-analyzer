// ─── asn1-viewer.js  ──────────────────────────────────────────────────────
// Interaktiver ASN.1-Struktur-Viewer für die Datei-Detailansicht.
// Mappt die geparsten Log-Felder auf die ASN1Definitions-Schemata und
// rendert eine detaillierte, aufklappbare Baumdarstellung.
'use strict';

window.ASN1Viewer = (() => {

  // ── Werteextraktion aus dem geparsten Log-Eintrag ─────────────────────

  function _fmtUnix(t) {
    if (t == null) return null;
    if (typeof t === 'object' && t instanceof Date) {
      return t.toISOString().replace('T', ' ').replace('Z', ' UTC');
    }
    if (t < 1000000) return `${t} (Unix-Timestamp)`;
    try { return new Date(t * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC'); }
    catch (e) { return String(t); }
  }

  function _getValue(fieldName, logEntry) {
    if (!logEntry) return { value: null, status: 'absent' };
    const f = logEntry;
    const absent = { value: null, status: 'absent' };
    const rfu    = { value: null, status: 'rfu' };

    switch (fieldName) {
      case 'version':
        return f.version != null ? { value: String(f.version), status: 'present' } : absent;

      case 'certifiedDataType':
        return (f.certifiedDataType || f.oid)
          ? { value: f.certifiedDataType || f.oid, status: 'present' } : absent;

      case 'certifiedData':
        return f.logType ? { value: `${f.logTypeLabel || f.logType} (eingebettet)`, status: 'present' } : absent;

      case 'serialNumber':
        return f.serialNumber
          ? { value: f.serialNumber.length > 64 ? f.serialNumber.slice(0,64)+'…' : f.serialNumber, status: 'present' }
          : absent;

      case 'signatureAlgorithm':
        return (f.sigAlgOID || f.signatureAlgorithm)
          ? { value: f.sigAlgName || f.sigAlgOID || f.signatureAlgorithm, status: 'present' } : absent;

      case 'seAuditData':
        return f.seAuditDataLen != null
          ? { value: `${f.seAuditDataLen} Byte` + (f.seAuditDataHex ? ` · 0x${f.seAuditDataHex.slice(0,16)}…` : ''), status: 'present' }
          : absent;

      case 'signatureCounter':
        return f.signatureCounter != null ? { value: String(f.signatureCounter), status: 'present' } : absent;

      case 'signatureCreationTime':
        return f.signatureCreationTime != null ? { value: _fmtUnix(f.signatureCreationTime), status: 'present' } : absent;

      case 'signatureValue':
        return f.signatureValueHex
          ? { value: `${f.signatureValueLen} Byte · 0x${f.signatureValueHex.slice(0,16)}…`, status: 'present' } : absent;

      // TransactionLogMessage
      case 'operationType':
        return f.operationType != null ? { value: f.operationType, status: 'present' } : absent;

      case 'clientId':
        return f.clientId != null ? { value: String(f.clientId), status: 'present' } : absent;

      case 'processData':
        return f.processDataLen != null
          ? { value: `${f.processDataLen} Byte` +
              (f.processDataText ? ` · "${f.processDataText.slice(0,60)}"` : '') +
              (f.processDataHex  ? ` · 0x${f.processDataHex.slice(0,16)}…` : ''), status: 'present' }
          : absent;

      case 'processType':
        return f.processType != null ? { value: f.processType || '(leer)', status: 'present' } : absent;

      case 'additionalExternalData':
        return f.additionalExternalDataPresent
          ? { value: `${f.additionalExternalDataLen} Byte` +
              (f.additionalExternalDataText ? ` · "${f.additionalExternalDataText.slice(0,60)}"` : ''), status: 'present' }
          : absent;

      case 'transactionNumber':
        return f.transactionNumber != null ? { value: `Nr. ${f.transactionNumber}`, status: 'present' } : absent;

      case 'additionalInternalData':
        return f.additionalInternalDataPresent
          ? { value: `${f.additionalInternalDataLen} Byte (RFU!)`, status: 'present' } : rfu;

      // SystemLogMessage
      case 'eventType':
        return f.eventType != null ? { value: f.eventType, status: 'present' } : absent;

      case 'eventOrigin':
        return f.eventOrigin != null ? { value: f.eventOrigin, status: 'present' } : absent;

      case 'eventTriggeredByUser':
        return f.eventTriggeredByUser != null ? { value: f.eventTriggeredByUser, status: 'present' } : absent;

      case 'eventData':
        return _getEventDataValue(f);

      // ── EventData sub-fields ────────────────────────────────────────

      // selfTest
      case 'selfTestResults':
        return f.selfTestResultCount != null
          ? { value: `${f.selfTestResultCount} Ergebnisse · ${f.selfTestResultsSummary || ''}`, status: 'present' }
          : absent;
      case 'allTestsArePositive':
        return f.selfTestAllPassed != null
          ? { value: f.selfTestAllPassed ? 'TRUE ✓' : `FALSE ✗${f.selfTestFailedComponents ? ' – fehlgeschlagen: ' + f.selfTestFailedComponents : ''}`, status: 'present' }
          : absent;
      // selfTestResults sub-fields are rendered dynamically via _selfTestResultRow,
      // not via _getValue — these cases are intentionally unreachable but kept for safety.

      // updateTime
      case 'seTimeBeforeUpdate':
        return f.seTimeBeforeUpdate != null
          ? { value: _fmtUnix(f.seTimeBeforeUpdate), status: 'present' } : absent;

      case 'seTimeAfterUpdate':
        return f.seTimeAfterUpdate != null
          ? { value: _fmtUnix(f.seTimeAfterUpdate), status: 'present' } : absent;

      case 'slewSettings':
        return f.slewSettings != null
          ? { value: `${f.slewSettings.length} Byte (SEQUENCE)`, status: 'present' } : absent;

      // authenticateUser
      case 'userId':
        return f.eventDataUserId != null ? { value: f.eventDataUserId, status: 'present' } : absent;

      case 'role':
        return f.eventDataRole != null ? { value: f.eventDataRole, status: 'present' } : absent;

      case 'authenticationResult':
        return f.eventDataAuthResultStr != null
          ? { value: f.eventDataAuthResultStr, status: 'present' } : absent;

      case 'remainingRetries':
        return f.eventDataRemainingRetries != null
          ? { value: String(f.eventDataRemainingRetries), status: 'present' } : absent;

      // logOut
      case 'loggedOutUserId':
        return f.loggedOutUserId != null ? { value: f.loggedOutUserId, status: 'present' } : absent;

      case 'logOutCause':
        return f.logOutCaseStr != null ? { value: f.logOutCaseStr, status: 'present' } : absent;

      // registerClient / deregisterClient
      case 'eventDataClientId':
        return f.eventDataClientId != null ? { value: f.eventDataClientId, status: 'present' } : absent;

      default:
        return absent;
    }
  }

  function _getEventDataValue(f) {
    if (f.eventDataLen == null) return { value: null, status: 'absent' };
    if (f.eventDataLen === 0)   return { value: 'leer (SEQUENCE {}) ✓', status: 'present' };
    const parts = [];
    if (f.eventType === 'updateTime') {
      if (f.seTimeBeforeUpdate != null) parts.push(`before: ${_fmtUnix(f.seTimeBeforeUpdate)}`);
      if (f.seTimeAfterUpdate  != null) parts.push(`after: ${_fmtUnix(f.seTimeAfterUpdate)}`);
    } else if (f.eventType === 'selfTest') {
      if (f.selfTestResultCount != null) parts.push(`${f.selfTestResultCount} Komponenten`);
      if (f.selfTestAllPassed != null)
        parts.push(f.selfTestAllPassed ? 'allTestsArePositive: TRUE ✓' : `allTestsArePositive: FALSE ✗${f.selfTestFailedComponents ? ' ('+f.selfTestFailedComponents+')' : ''}`);
      if (f.selfTestResultsSummary) parts.push(f.selfTestResultsSummary);
    } else if (f.eventType === 'authenticateUser') {
      if (f.eventDataUserId)        parts.push(`userId: ${f.eventDataUserId}`);
      if (f.eventDataAuthResultStr) parts.push(`result: ${f.eventDataAuthResultStr}`);
      if (f.eventDataRemainingRetries != null) parts.push(`retries: ${f.eventDataRemainingRetries}`);
    } else if (f.eventType === 'logOut') {
      if (f.loggedOutUserId) parts.push(`userId: ${f.loggedOutUserId}`);
      if (f.logOutCaseStr)   parts.push(`cause: ${f.logOutCaseStr}`);
    } else if (f.eventType === 'registerClient' || f.eventType === 'deregisterClient') {
      if (f.eventDataClientId) parts.push(`clientId: ${f.eventDataClientId}`);
    } else {
      if (f.eventDataDecoded) parts.push(f.eventDataDecoded.slice(0, 120));
    }
    return { value: parts.length ? parts.join(' · ') : `${f.eventDataLen} Byte`, status: 'present' };
  }

  // ── HTML-Hilfsfunktionen ──────────────────────────────────────────────

  function _esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').trim();
  }

  function _tagBadge(tag) {
    return tag ? `<span class="asn1-tag-badge">${_esc(tag)}</span>` : '';
  }

  function _typeBadge(type) {
    const color =
      type.startsWith('INTEGER')         ? '#2563eb' :
      type.startsWith('OCTET STRING')    ? '#9333ea' :
      type.startsWith('PrintableString') ? '#0891b2' :
      type.startsWith('BOOLEAN')         ? '#d97706' :
      type.startsWith('OBJECT IDENT')    ? '#059669' :
      type.startsWith('Time')            ? '#c026d3' :
      '#6b7280';
    return `<span class="asn1-type-badge" style="color:${color};border-color:${color}30;background:${color}08">${_esc(type)}</span>`;
  }

  /** Prüft rekursiv ob ein Pflicht-Kind-Feld fehlt. */
  function _childStatus(children, logEntry, fieldName) {
    if (!children || !children.length || !logEntry) return 'ok';
    // SEQUENCE OF fields (e.g. selfTestResults) use dynamic rendering – no static child check
    if (fieldName === 'selfTestResults') return 'ok';
    for (const child of children) {
      const { status } = _getValue(child.name, logEntry);
      if (child.required && status !== 'present') return 'error';
      if (child.children && _childStatus(child.children, logEntry, child.name) === 'error') return 'error';
    }
    return 'ok';
  }

  function _statusDot(status, required, hasChildError) {
    if (hasChildError && status === 'present')
      return `<span class="asn1-dot asn1-dot-child-err" title="Vorhanden, aber Pflicht-Unterfeld fehlt">!</span>`;
    if (status === 'rfu')     return `<span class="asn1-dot asn1-dot-rfu"  title="RFU">–</span>`;
    if (status === 'present') return `<span class="asn1-dot asn1-dot-ok"   title="Vorhanden">✓</span>`;
    if (required)             return `<span class="asn1-dot asn1-dot-miss" title="Pflichtfeld fehlt">✗</span>`;
    return `<span class="asn1-dot asn1-dot-opt" title="Optional, nicht vorhanden">○</span>`;
  }

  // ── Dynamische Zeile für einen SelfTestResult-Eintrag ───────────────
  // Rendert { component, passed, errorCode } für einen einzelnen Eintrag
  // aus logEntry.selfTestResults[] als aufgeräumte Zeile.

  function _selfTestResultRow(entry, idx, depth) {
    const indent = depth * 20;
    const passed = entry.passed;
    const dotHtml = passed
      ? `<span class="asn1-dot asn1-dot-ok" title="Test bestanden">✓</span>`
      : `<span class="asn1-dot asn1-dot-miss" title="Test fehlgeschlagen">✗</span>`;

    const errHtml = entry.errorCode !== 0
      ? `<span class="asn1-field-note">errorCode: ${entry.errorCode}</span>`
      : '';

    const passedBadge = passed
      ? `<span style="font-size:10px;font-weight:700;background:var(--pass-bg);color:var(--pass);border:1px solid var(--pass-border);border-radius:3px;padding:0 5px">passed: TRUE</span>`
      : `<span style="font-size:10px;font-weight:700;background:var(--fail-bg);color:var(--fail);border:1px solid var(--fail-border);border-radius:3px;padding:0 5px">passed: FALSE</span>`;

    return `
      <div class="asn1-field-row asn1-depth-${Math.min(depth, 3)}" data-depth="${depth}" style="padding-left:${indent + 8}px">
        <div class="asn1-field-main">
          <span class="asn1-expand-spacer"></span>
          ${dotHtml}
          <span class="asn1-field-name" style="color:var(--accent)">${_esc(entry.component)}</span>
          <span class="asn1-type-badge" style="color:#6b7280;border-color:#6b728030;background:#6b72800a">SelfTestResult[${idx}]</span>
          ${passedBadge}
          <span class="asn1-field-value" style="${passed ? '' : 'background:var(--fail-bg);border-color:var(--fail-border)'}">
            ${_esc(entry.component)}${entry.errorCode !== 0 ? ` · errorCode=${entry.errorCode}` : ''}
          </span>
          ${errHtml}
        </div>
        <div class="asn1-field-desc">SelfTestResult: component="${_esc(entry.component)}", passed=${passed}, errorCode=${entry.errorCode}</div>
      </div>`;
  }

  // ── Feldzeile rendern ─────────────────────────────────────────────────

  function _fieldRow(field, logEntry, depth) {
    const { name, type, tag, required, desc, note, children } = field;
    const indent = depth * 20;
    const { value, status } = _getValue(name, logEntry);
    const hasChildren   = children && children.length > 0;
    const hasChildError = hasChildren && _childStatus(children, logEntry, name) === 'error';

    const valueHtml = value
      ? `<span class="asn1-field-value">${_esc(value)}</span>`
      : `<span class="asn1-field-empty">${required ? '– (Pflichtfeld fehlt!)' : '– (nicht vorhanden)'}</span>`;

    const noteHtml = note ? `<span class="asn1-field-note">${_esc(note)}</span>` : '';

    const expandBtn = hasChildren
      ? `<button class="asn1-expand-btn" aria-expanded="false" onclick="ASN1Viewer.toggleChildren(this)">▶</button>`
      : `<span class="asn1-expand-spacer"></span>`;

    // Pass logEntry down to children.
    // Special case: selfTestResults is SEQUENCE OF → render one row per array entry dynamically.
    let childrenHtml = '';
    if (hasChildren) {
      let innerHtml;
      if (name === 'selfTestResults' && logEntry && Array.isArray(logEntry.selfTestResults) && logEntry.selfTestResults.length > 0) {
        innerHtml = logEntry.selfTestResults.map((entry, idx) =>
          _selfTestResultRow(entry, idx, depth + 1)
        ).join('');
      } else {
        innerHtml = children.map(c => _fieldRow(c, logEntry, depth + 1)).join('');
      }
      childrenHtml = `<div class="asn1-children" style="display:none">${innerHtml}</div>`;
    }

    const rowCls = (status !== 'present' && required)
      ? 'asn1-field-row asn1-row-error'
      : hasChildError
        ? 'asn1-field-row asn1-row-child-error'
        : 'asn1-field-row';

    return `
      <div class="${rowCls} asn1-depth-${Math.min(depth, 3)}" data-depth="${depth}" style="padding-left:${indent + 8}px">
        <div class="asn1-field-main">
          ${expandBtn}
          ${_statusDot(status, required, hasChildError)}
          <span class="asn1-field-name">${_esc(name)}</span>
          ${_tagBadge(tag)}
          ${_typeBadge(type)}
          ${required ? '<span class="asn1-req-badge">Pflicht</span>' : '<span class="asn1-opt-badge">Optional</span>'}
          ${valueHtml}
          ${noteHtml}
        </div>
        <div class="asn1-field-desc">${_esc(desc || '')}</div>
        ${childrenHtml}
      </div>`;
  }

  // ── Struktur-Block ────────────────────────────────────────────────────

  function _structBlock(title, structName, fields, logEntry, accentColor) {
    const rowsHtml = fields.map(f => _fieldRow(f, logEntry, 0)).join('');
    const totalFields   = fields.length;
    const presentFields = fields.filter(f => _getValue(f.name, logEntry || {}).status === 'present').length;
    return `
      <div class="asn1-struct-block" style="border-top:3px solid ${accentColor}">
        <div class="asn1-struct-header" onclick="ASN1Viewer.toggleBlock(this)">
          <div style="display:flex;align-items:center;gap:8px;min-width:0">
            <span class="asn1-block-caret">▼</span>
            <span class="asn1-struct-title">${_esc(title)}</span>
            <code class="asn1-struct-name" style="color:${accentColor}">${_esc(structName)}</code>
          </div>
          <span class="asn1-field-counter">${presentFields}/${totalFields} Felder vorhanden</span>
        </div>
        <div class="asn1-struct-body">
          <div class="asn1-fields-table">${rowsHtml}</div>
        </div>
      </div>`;
  }

  function _legend() {
    return `<div class="asn1-legend">
      <span class="asn1-dot asn1-dot-ok">✓</span><span>Vorhanden</span>
      <span class="asn1-dot asn1-dot-miss">✗</span><span>Fehlt (Pflicht)</span>
      <span class="asn1-dot asn1-dot-opt">○</span><span>Optional, nicht vorhanden</span>
      <span class="asn1-dot asn1-dot-child-err">!</span><span>Pflicht-Unterfeld fehlt</span>
      <span class="asn1-dot asn1-dot-rfu">–</span><span>RFU</span>
    </div>`;
  }

  // ── Haupt-Render ──────────────────────────────────────────────────────

  function render(logEntry) {
    if (!logEntry) return null;
    const def = ASN1Definitions.getDefinition(logEntry);
    if (!def) return _renderUnknown(logEntry);

    const isTxn = def.logType === 'txn';
    const outerColor = isTxn ? '#7c3aed' : '#0369a1';
    const innerColor = isTxn ? '#9333ea' : '#0284c7';

    const wrap = document.createElement('div');
    wrap.className = 'asn1-viewer-panel card';
    wrap.innerHTML = `
      <div class="asn1-viewer-header" onclick="ASN1Viewer.togglePanel(this)">
        <div style="display:flex;align-items:center;gap:10px;min-width:0">
          <span class="asn1-panel-caret">▼</span>
          <span style="font-size:14px">🔬</span>
          <span class="asn1-panel-title">ASN.1 Struktur</span>
          <code class="asn1-panel-func" style="color:${outerColor}">${_esc(def.title)}</code>
        </div>
        <span class="asn1-spec-ref">BSI TR-03151-1</span>
      </div>
      <div class="asn1-viewer-body">
        ${_legend()}
        <div class="asn1-struct-list">
          ${_structBlock('① LogMessage-Hülle', def.outerStruct, def.outerFields, logEntry, outerColor)}
          ${_structBlock('② ' + (isTxn ? 'TransactionLogMessage (certifiedData)' : 'SystemLogMessage (certifiedData)'),
                          def.innerStruct, def.innerFields, logEntry, innerColor)}
        </div>
      </div>`;
    return wrap;
  }

  function _renderUnknown(logEntry) {
    const wrap = document.createElement('div');
    wrap.className = 'asn1-viewer-panel card';
    wrap.innerHTML = `
      <div class="asn1-viewer-header" onclick="ASN1Viewer.togglePanel(this)">
        <div style="display:flex;align-items:center;gap:10px">
          <span class="asn1-panel-caret">▼</span>
          <span style="font-size:14px">🔬</span>
          <span class="asn1-panel-title">ASN.1 Struktur</span>
          <span style="font-size:12px;color:var(--text-muted)">(Kein Schema für diesen Log-Typ)</span>
        </div>
      </div>
      <div class="asn1-viewer-body">
        <div style="padding:16px;font-size:13px;color:var(--text-muted)">
          Kein Schema für operationType <code>${_esc(logEntry.operationType||'–')}</code> /
          eventType <code>${_esc(logEntry.eventType||'–')}</code>.<br>
          Rohwerte sind im Abschnitt „Log-Felder" sichtbar.
        </div>
      </div>`;
    return wrap;
  }

  // ── Toggle-Handler ────────────────────────────────────────────────────

  function togglePanel(headerEl) {
    const body  = headerEl.closest('.asn1-viewer-panel').querySelector('.asn1-viewer-body');
    const caret = headerEl.querySelector('.asn1-panel-caret');
    const open  = body.style.display !== 'none';
    body.style.display = open ? 'none' : '';
    if (caret) caret.textContent = open ? '▶' : '▼';
  }

  function toggleBlock(headerEl) {
    const body  = headerEl.closest('.asn1-struct-block').querySelector('.asn1-struct-body');
    const caret = headerEl.querySelector('.asn1-block-caret');
    const open  = body.style.display !== 'none';
    body.style.display = open ? 'none' : '';
    if (caret) caret.textContent = open ? '▶' : '▼';
  }

  function toggleChildren(btnEl) {
    const children = btnEl.closest('.asn1-field-row').querySelector('.asn1-children');
    if (!children) return;
    const open = children.style.display !== 'none';
    children.style.display = open ? 'none' : '';
    btnEl.textContent = open ? '▶' : '▼';
    btnEl.setAttribute('aria-expanded', String(!open));
  }

  return { render, togglePanel, toggleBlock, toggleChildren };
})();
