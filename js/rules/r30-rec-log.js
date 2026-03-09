'use strict';
window.RulesCat30 = (function() {
  const CAT = 'Re-Zertifizierungs-Log (REC_LOG)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['REC_LOG_PRESENT','REC_LOG_EVTYPE','REC_LOG_EVORIGIN','REC_TXN_FNAME_CLIENT','REC_TXN_CLIENTID_FIELD'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.9')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const recLogs = sysLogs.filter(l=>l.eventType==='recertification');

    results.push(recLogs.length > 0
      ? Utils.pass('REC_LOG_PRESENT','recertification-Log vorhanden',CAT,`${recLogs.length} recertification-Log(s).`,'','BSI TR-03151-1 §4.9')
      : Utils.info('REC_LOG_PRESENT','recertification-Log vorhanden',CAT,'Kein recertification-Log.','','BSI TR-03151-1 §4.9'));

    results.push(recLogs.every(l=>l.eventType==='recertification')
      ? Utils.pass('REC_LOG_EVTYPE','eventType=recertification',CAT,'Korrekt.','','BSI TR-03151-1 §4.9')
      : Utils.fail('REC_LOG_EVTYPE','eventType=recertification',CAT,'Falscher eventType.','','BSI TR-03151-1 §4.9'));

    results.push(Utils.info('REC_LOG_EVORIGIN','eventOrigin korrekt',CAT,'Bei recertification muss eventOrigin=se sein.','','BSI TR-03151-1 §4.9'));
    results.push(Utils.info('REC_TXN_FNAME_CLIENT','TransactionLog nach Rezertifizierung: Client korrekt',CAT,'Prüfung erfordert zeitliche Analyse nach recertification-Log.','','BSI TR-03151-1 §4.9'));
    results.push(Utils.info('REC_TXN_CLIENTID_FIELD','clientId in recertification-Log vorhanden',CAT,'recertification-Log muss clientId-Feld enthalten.','','BSI TR-03151-1 §4.9'));

    return results;
  }
  return { run, CAT };
})();

