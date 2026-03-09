'use strict';
window.RulesCat31 = (function() {
  const CAT = 'Sperr- & Entsperr-Log (LTL / UTL)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['LTL_LOG_PRESENT','LTL_LOG_EVTYPE','LTL_LOG_EVORIGIN','LTL_LOG_EVDATA_EMPTY','LTL_NEG_TXN',
       'UTL_LOG_PRESENT','UTL_LOG_EVTYPE','UTL_LOG_EVORIGIN','UTL_LOG_EVDATA_EMPTY','UTL_TXN_PRESENT'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.10')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    const lockLogs   = sysLogs.filter(l=>l.eventType==='lockDevice');
    const unlockLogs = sysLogs.filter(l=>l.eventType==='unlockDevice');

    results.push(lockLogs.length>0
      ? Utils.pass('LTL_LOG_PRESENT','lockDevice-Log vorhanden',CAT,`${lockLogs.length} lockDevice-Log(s).`,'','BSI TR-03151-1 §4.10')
      : Utils.info('LTL_LOG_PRESENT','lockDevice-Log vorhanden',CAT,'Kein lockDevice-Log.','','BSI TR-03151-1 §4.10'));
    results.push(Utils.pass('LTL_LOG_EVTYPE','eventType=lockDevice',CAT,'Korrekt (gefiltert).','','BSI TR-03151-1 §4.10'));
    results.push(Utils.info('LTL_LOG_EVORIGIN','eventOrigin bei lockDevice',CAT,'Erfordert eventData-Analyse.','','BSI TR-03151-1 §4.10'));
    results.push(Utils.info('LTL_LOG_EVDATA_EMPTY','eventData bei lockDevice leer',CAT,'lockDevice-eventData sollte leer sein.','','BSI TR-03151-1 §4.10'));

    // LTL_NEG_TXN
    if (lockLogs.length > 0) {
      const firstLock = lockLogs.reduce((m,l)=>l.signatureCounter<m.signatureCounter?l:m);
      const txnAfterLock = txnLogs.filter(l=>l.signatureCounter>firstLock.signatureCounter && l.operationType==='startTransaction');
      const unlockAfterLock = unlockLogs.filter(l=>l.signatureCounter>firstLock.signatureCounter);
      const badTxn = txnAfterLock.filter(l=>unlockAfterLock.length===0||unlockAfterLock[0].signatureCounter>l.signatureCounter);
      results.push(badTxn.length===0
        ? Utils.pass('LTL_NEG_TXN','Keine neuen Transaktionen während Sperre',CAT,'Keine Transaktionen während gesperrtem Zustand.','','BSI TR-03151-1 §4.10')
        : Utils.warn('LTL_NEG_TXN','Keine neuen Transaktionen während Sperre',CAT,`${badTxn.length} Transaktionen während möglicher Sperre.`,'','BSI TR-03151-1 §4.10'));
    } else {
      results.push(Utils.skip('LTL_NEG_TXN','Keine neuen Transaktionen während Sperre',CAT,'Kein lockDevice-Log.','','BSI TR-03151-1 §4.10'));
    }

    results.push(unlockLogs.length>0
      ? Utils.pass('UTL_LOG_PRESENT','unlockDevice-Log vorhanden',CAT,`${unlockLogs.length} unlockDevice-Log(s).`,'','BSI TR-03151-1 §4.10')
      : Utils.info('UTL_LOG_PRESENT','unlockDevice-Log vorhanden',CAT,'Kein unlockDevice-Log.','','BSI TR-03151-1 §4.10'));
    results.push(Utils.pass('UTL_LOG_EVTYPE','eventType=unlockDevice',CAT,'Korrekt (gefiltert).','','BSI TR-03151-1 §4.10'));
    results.push(Utils.info('UTL_LOG_EVORIGIN','eventOrigin bei unlockDevice',CAT,'Erfordert eventData-Analyse.','','BSI TR-03151-1 §4.10'));
    results.push(Utils.info('UTL_LOG_EVDATA_EMPTY','eventData bei unlockDevice leer',CAT,'unlockDevice-eventData sollte leer sein.','','BSI TR-03151-1 §4.10'));

    if (lockLogs.length>0 && unlockLogs.length===0) {
      results.push(Utils.warn('UTL_TXN_PRESENT','Transaktionen nach unlockDevice möglich',CAT,'lockDevice vorhanden, aber kein unlockDevice.','','BSI TR-03151-1 §4.10'));
    } else {
      results.push(Utils.info('UTL_TXN_PRESENT','Transaktionen nach unlockDevice möglich',CAT,`${txnLogs.length} Transaktionen im Archiv.`,'','BSI TR-03151-1 §4.10'));
    }

    return results;
  }
  return { run, CAT };
})();

