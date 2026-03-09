// ─── r11-audit-log.js – AuditLog (LOG_AUDIT) ─────────────────────────────
'use strict';

window.RulesCat11 = (function() {
  const CAT = 'AuditLog (LOG_AUDIT)';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;

    if (archiveType === 'cert-export') {
      ['LOG_AUDIT_DATA','LOG_AUDIT_NOTEMPTY','LOG_AUDIT_NOEVT','LOG_AUDIT_FNAME'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine AuditLogs.', '', 'BSI TR-03151-1')));
      return results;
    }

    const auditLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'audit');

    if (auditLogs.length === 0) {
      ['LOG_AUDIT_DATA','LOG_AUDIT_NOTEMPTY','LOG_AUDIT_NOEVT','LOG_AUDIT_FNAME'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine AuditLog-Nachrichten im Archiv.', '', 'BSI TR-03151-1')));
      return results;
    }

    // LOG_AUDIT_DATA
    const noData = auditLogs.filter(l => !l.seAuditData);
    results.push(noData.length === 0
      ? Utils.pass('LOG_AUDIT_DATA', 'seAuditData vorhanden', CAT,
          `Alle ${auditLogs.length} AuditLogs: seAuditData vorhanden.`,
          'Das Feld `seAuditData` (OCTET STRING) ist ein Pflichtfeld der AuditLogMessage.', 'BSI TR-03151-1 AuditLogMessage')
      : Utils.fail('LOG_AUDIT_DATA', 'seAuditData vorhanden', CAT,
          `${noData.length} AuditLogs ohne seAuditData:\n${noData.map(l=>l._filename).join('\n')}`,
          'Das Feld `seAuditData` (OCTET STRING) ist ein Pflichtfeld der AuditLogMessage.', 'BSI TR-03151-1 AuditLogMessage'));

    // LOG_AUDIT_NOTEMPTY
    const emptyData = auditLogs.filter(l => l.seAuditData && l.seAuditData.length === 0);
    results.push(emptyData.length === 0
      ? Utils.pass('LOG_AUDIT_NOTEMPTY', 'seAuditData nicht leer', CAT,
          `Alle AuditLogs: seAuditData > 0 Byte.`,
          'Das seAuditData-Feld muss mindestens 1 Byte enthalten.', 'BSI TR-03151-1 AuditLogMessage')
      : Utils.fail('LOG_AUDIT_NOTEMPTY', 'seAuditData nicht leer', CAT,
          `${emptyData.length} AuditLogs mit leером seAuditData.`,
          'Das seAuditData-Feld muss mindestens 1 Byte enthalten.', 'BSI TR-03151-1 AuditLogMessage'));

    // LOG_AUDIT_NOEVT
    const withEvt = auditLogs.filter(l => l.eventType || l.eventOrigin);
    results.push(withEvt.length === 0
      ? Utils.pass('LOG_AUDIT_NOEVT', 'Kein certifiedData-Platzhalter', CAT,
          `Kein AuditLog enthält unerwartete eventType/eventOrigin-Felder.`,
          'Die AuditLogMessage enthält KEIN eventType- oder eventOrigin-Feld.', 'BSI TR-03151-1 AuditLogMessage')
      : Utils.warn('LOG_AUDIT_NOEVT', 'Kein certifiedData-Platzhalter', CAT,
          `${withEvt.length} AuditLogs mit unerwarteten eventType/eventOrigin-Feldern:\n${withEvt.map(l=>l._filename).join('\n')}`,
          'Die AuditLogMessage darf KEIN eventType- oder eventOrigin-Feld enthalten.', 'BSI TR-03151-1 AuditLogMessage'));

    // LOG_AUDIT_FNAME
    const fnameFails = auditLogs.filter(l => !Utils.LOG_AUD_PATTERN.test(l._filename));
    results.push(fnameFails.length === 0
      ? Utils.pass('LOG_AUDIT_FNAME', 'Dateiname-Schema AuditLog', CAT,
          `Alle ${auditLogs.length} AuditLog-Dateien entsprechen dem Schema.`,
          'Regex: ^(Gent|Utc|Unixt)_[^_]+_Sig-\\d+_Log-Aud\\.log$', 'BSI TR-03151-1 Dateinamenkonvention AuditLog')
      : Utils.warn('LOG_AUDIT_FNAME', 'Dateiname-Schema AuditLog', CAT,
          `${fnameFails.length} Dateien weichen vom Schema ab:\n${fnameFails.map(l=>l._filename).join('\n')}`,
          'Regex: ^(Gent|Utc|Unixt)_[^_]+_Sig-\\d+_Log-Aud\\.log$', 'BSI TR-03151-1 Dateinamenkonvention AuditLog'));

    return results;
  }

  return { run, CAT };
})();
