// ─── r16-aggregation.js – Aggregation (AGG / SM_AGG) ─────────────────────
'use strict';
window.RulesCat16 = (function() {
  const CAT = 'Aggregation (AGG / SM_AGG)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['AGG_UPDATE_ABSENT','AGG_PDATA_CONCAT','AGG_ADD_CONCAT',
      'SM_AGG_LOG_AFTER_DELAY','SM_AGG_LOG_LAST_PARAMS','SM_AGG_FORCE_SIGN_LOG'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.3')));
      return results;
    }
    const txnLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'txn');
    const updateLogs = txnLogs.filter(l => l.operationType === 'updateTransaction');

    // AGG_UPDATE_ABSENT
    results.push(Utils.info('AGG_UPDATE_ABSENT', 'Keine Log-Nachricht für nicht-signierte Zwischenupdates', CAT,
      `${updateLogs.length} updateTransaction-Logs im Archiv. Bei aktivem SM_AGG-Modus dürfen Zwischenupdates ohne forceSignature=TRUE keine eigenen Log-Dateien erzeugen. Prüfung erfordert Laufzeit-Metadaten (forceSignature-Parameter).`,
      'Bei Aggregation darf für updateTransaction-Aufrufe ohne forceSignature=TRUE kein eigener Log-Eintrag entstehen.',
      'BSI TR-03151-1 §4.3'));

    // AGG_PDATA_CONCAT
    const aggLogs = updateLogs.filter(l => l.indefiniteLengthUsed);
    if (aggLogs.length > 0) {
      results.push(Utils.info('AGG_PDATA_CONCAT', 'processData einer aggregierten Nachricht ist Konkatenation', CAT,
        `${aggLogs.length} Update-Logs mit indefinite length encoding (aggregiert). processData sollte die Konkatenation aller aggregierten updateTransaction-processData-Werte enthalten.`,
        'processData einer aggregierten Log-Nachricht muss die Konkatenation aller aggregierten updateTransaction-processData-Werte sein.',
        'BSI TR-03151-1 §4.3'));
    } else {
      results.push(Utils.info('AGG_PDATA_CONCAT', 'processData einer aggregierten Nachricht ist Konkatenation', CAT,
        'Keine aggregierten Update-Logs (mit indefinite length encoding) erkannt.',
        '', 'BSI TR-03151-1 §4.3'));
    }

    // AGG_ADD_CONCAT
    results.push(Utils.info('AGG_ADD_CONCAT', 'additionalExternalData einer aggregierten Nachricht ist Konkatenation', CAT,
      'additionalExternalData-Konkatenationsprüfung für aggregierte Nachrichten erfordert Laufzeit-Kontext.',
      'additionalExternalData einer aggregierten Log-Nachricht muss die Konkatenation der jeweiligen Werte sein.',
      'BSI TR-03151-1 §4.3'));

    // SM_AGG checks
    for (const [id, name, desc] of [
      ['SM_AGG_LOG_AFTER_DELAY', 'Aggregierter Update-Log erscheint nach MAX_PROTECTION_DELAY',
       'Prüfung erfordert Zeitstempel-Analyse und Konfiguration des MAX_PROTECTION_DELAY-Werts.'],
      ['SM_AGG_LOG_LAST_PARAMS', 'Aggregierter Log enthält zuletzt übergebene Parameter',
       'Prüfung erfordert Laufzeit-Kontext der updateTransaction-Aufrufe.'],
      ['SM_AGG_FORCE_SIGN_LOG', 'Log nach forceSignature=TRUE sofort vorhanden',
       'Prüfung erfordert Laufzeit-Kontext (forceSignature-Parameter).'],
    ]) {
      results.push(Utils.info(id, name, CAT, desc, name, 'BSI TR-03151-1 §4.3'));
    }

    return results;
  }
  return { run, CAT };
})();
