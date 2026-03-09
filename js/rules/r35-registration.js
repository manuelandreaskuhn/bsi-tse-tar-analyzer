'use strict';
window.RulesCat35 = (function() {
  const CAT = 'Registrierung (REG / DEREG)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['REG_LOG_CLIENTID_PRESENT','REG_LOG_NO_UNKNOWN_CLIENTS','DEREG_LOG_NO_NEW_TXN'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.11')));
      return results;
    }

    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    const regLogs   = sysLogs.filter(l=>l.eventType==='registerClient');
    const deregLogs = sysLogs.filter(l=>l.eventType==='deregisterClient');

    // REG_LOG_CLIENTID_PRESENT
    const noClientReg = regLogs.filter(l=>!l.eventTriggeredByUser && !l.clientId);
    results.push(regLogs.length===0
      ? Utils.info('REG_LOG_CLIENTID_PRESENT','registerClient-Log mit clientId',CAT,'Kein registerClient-Log.','','BSI TR-03151-1 §4.11')
      : noClientReg.length===0
        ? Utils.pass('REG_LOG_CLIENTID_PRESENT','registerClient-Log mit clientId',CAT,`${regLogs.length} registerClient-Log(s): clientId/Trigger vorhanden.`,'','BSI TR-03151-1 §4.11')
        : Utils.warn('REG_LOG_CLIENTID_PRESENT','registerClient-Log mit clientId',CAT,`${noClientReg.length} registerClient-Logs ohne clientId/Trigger.`,'','BSI TR-03151-1 §4.11'));

    // REG_LOG_NO_UNKNOWN_CLIENTS
    const registeredClients = new Set(regLogs.map(l=>l.eventTriggeredByUser||l.clientId).filter(Boolean));
    const txnClients = new Set(txnLogs.map(l=>l.clientId).filter(Boolean));
    const unknownClients = regLogs.length>0 ? [...txnClients].filter(c=>!registeredClients.has(c)) : [];
    results.push(regLogs.length===0
      ? Utils.info('REG_LOG_NO_UNKNOWN_CLIENTS','Alle Clients registriert',CAT,'Kein registerClient-Log (keine Registrierungspflicht erkennbar).','','BSI TR-03151-1 §4.11')
      : unknownClients.length===0
        ? Utils.pass('REG_LOG_NO_UNKNOWN_CLIENTS','Alle Clients registriert',CAT,`Alle ${txnClients.size} TXN-Clients sind registriert.`,'','BSI TR-03151-1 §4.11')
        : Utils.warn('REG_LOG_NO_UNKNOWN_CLIENTS','Alle Clients registriert',CAT,`${unknownClients.length} unregistrierte Clients: ${unknownClients.join(', ')}`,
            'Jeder clientId-Wert muss durch einen registerClient-Log-Eintrag gedeckt sein.','BSI TR-03151-1 §4.11'));

    // DEREG_LOG_NO_NEW_TXN
    if (deregLogs.length===0) {
      results.push(Utils.skip('DEREG_LOG_NO_NEW_TXN','Keine Transaktionen nach deregisterClient',CAT,'Kein deregisterClient-Log.','','BSI TR-03151-1 §4.11'));
    } else {
      const lastDereg = deregLogs.reduce((m,l)=>l.signatureCounter>m.signatureCounter?l:m);
      const txnAfterDereg = txnLogs.filter(l=>l.operationType==='startTransaction'&&l.signatureCounter>lastDereg.signatureCounter);
      results.push(txnAfterDereg.length===0
        ? Utils.pass('DEREG_LOG_NO_NEW_TXN','Keine Transaktionen nach deregisterClient',CAT,`Kein startTransaction nach letztem deregisterClient (Ctr=${lastDereg.signatureCounter}).`,'','BSI TR-03151-1 §4.11')
        : Utils.warn('DEREG_LOG_NO_NEW_TXN','Keine Transaktionen nach deregisterClient',CAT,`${txnAfterDereg.length} startTransaction-Logs nach deregisterClient.`,'','BSI TR-03151-1 §4.11'));
    }

    return results;
  }
  return { run, CAT };
})();
