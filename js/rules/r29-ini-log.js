'use strict';
window.RulesCat29 = (function() {
  const CAT = 'Initialisierungs-Log (INI_LOG)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['INI_LOG_PRESENT','INI_LOG_EVTYPE','INI_LOG_EVORIGIN','INI_LOG_ONCE'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.6')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const iniLogs = sysLogs.filter(l=>l.eventType==='initialize');

    results.push(iniLogs.length > 0
      ? Utils.pass('INI_LOG_PRESENT', 'initialize-Log vorhanden', CAT, `${iniLogs.length} initialize-Log(s).`, '', 'BSI TR-03151-1 §4.6')
      : Utils.info('INI_LOG_PRESENT', 'initialize-Log vorhanden', CAT, 'Kein initialize-Log (partieller Export möglich).', '', 'BSI TR-03151-1 §4.6'));

    results.push(iniLogs.every(l=>l.eventType==='initialize')
      ? Utils.pass('INI_LOG_EVTYPE', 'eventType=initialize', CAT, 'Korrekt.', '', 'BSI TR-03151-1 §4.6')
      : Utils.fail('INI_LOG_EVTYPE', 'eventType=initialize', CAT, 'Falscher eventType.', '', 'BSI TR-03151-1 §4.6'));

    const wrongOrigin = iniLogs.filter(l=>l.eventOrigin!=='se');
    results.push(iniLogs.length===0 ? Utils.skip('INI_LOG_EVORIGIN','eventOrigin=se',CAT,'Kein initialize-Log.','','BSI TR-03151-1 §4.6')
      : wrongOrigin.length===0
        ? Utils.pass('INI_LOG_EVORIGIN','eventOrigin=se',CAT,'Korrekt.','','BSI TR-03151-1 §4.6')
        : Utils.fail('INI_LOG_EVORIGIN','eventOrigin=se',CAT,`${wrongOrigin.length} Logs mit falschem eventOrigin.`,'','BSI TR-03151-1 §4.6'));

    results.push(iniLogs.length <= 1
      ? Utils.pass('INI_LOG_ONCE','initialize-Log höchstens einmal',CAT,`${iniLogs.length} initialize-Log(s).`,'','BSI TR-03151-1 §4.6')
      : Utils.warn('INI_LOG_ONCE','initialize-Log höchstens einmal',CAT,`${iniLogs.length} initialize-Logs (max. 1 erwartet).`,'','BSI TR-03151-1 §4.6'));

    return results;
  }
  return { run, CAT };
})();

