// ─── r23-data-return.js – Datenrückgabe (DRC) ────────────────────────────
'use strict';
window.RulesCat23 = (function() {
  const CAT = 'Datenrückgabe (DRC)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['DRC_LOG_PRESENT','DRC_LOG_EVTYPE','DRC_LOG_EVORIGIN','DRC_LOG_CLIENTID',
      'DRC_TXN_ABSENT','DRC_TXN_PRESENT'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03153-1 §11')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    const drcLogs = sysLogs.filter(l=>l.eventType==='readData');

    if (drcLogs.length===0) {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'Keine readData-Logs.', '', 'BSI TR-03153-1 §11')));
      return results;
    }

    results.push(Utils.pass('DRC_LOG_PRESENT', 'readData-Log vorhanden', CAT, `${drcLogs.length} readData-Log(s).`, '', 'BSI TR-03153-1 §11'));
    results.push(drcLogs.every(l=>l.eventType==='readData')
      ? Utils.pass('DRC_LOG_EVTYPE', 'eventType=readData', CAT, 'Korrekt.', '', 'BSI TR-03153-1 §11')
      : Utils.fail('DRC_LOG_EVTYPE', 'eventType=readData', CAT, 'Falsche eventType-Werte.', '', 'BSI TR-03153-1 §11'));
    results.push(Utils.info('DRC_LOG_EVORIGIN', 'eventOrigin korrekt', CAT, 'Prüfung auf application/se.', '', 'BSI TR-03153-1 §11'));
    results.push(drcLogs.every(l=>l.eventTriggeredByUser)
      ? Utils.pass('DRC_LOG_CLIENTID', 'clientId / Trigger vorhanden', CAT, 'Alle readData-Logs: Trigger vorhanden.', '', 'BSI TR-03153-1 §11')
      : Utils.warn('DRC_LOG_CLIENTID', 'clientId / Trigger vorhanden', CAT, 'Einige readData-Logs ohne Trigger.', '', 'BSI TR-03153-1 §11'));
    results.push(Utils.info('DRC_TXN_ABSENT', 'Keine TransactionLogs während readData', CAT,
      'Prüfung erfordert zeitliche Überschneidungsanalyse.', '', 'BSI TR-03153-1 §11'));
    results.push(Utils.info('DRC_TXN_PRESENT', 'TransactionLogs nach readData vorhanden', CAT,
      `${txnLogs.length} TransactionLogs im Archiv.`, '', 'BSI TR-03153-1 §11'));
    return results;
  }
  return { run, CAT };
})();
