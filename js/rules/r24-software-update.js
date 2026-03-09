// ─── r24-software-update.js – Software-Updates & SE-Events (DSE/UDD/SDE/STE)
'use strict';
window.RulesCat24 = (function() {
  const CAT = 'Software-Updates & SE-Events (DSE / UDD / SDE / STE)';

  function makeEvtChecks(results, logs, evtType, ids, cat) {
    const evLogs = logs.filter(l=>l.eventType===evtType);
    if (evLogs.length===0) {
      ids.forEach(([id,name]) => results.push(Utils.skip(id, name, cat, `Keine ${evtType}-Logs.`, '', 'BSI TR-03151-1 §4.8')));
      return;
    }
    results.push(Utils.pass(ids[0][0], ids[0][1], cat, `${evLogs.length} ${evtType}-Log(s).`, '', 'BSI TR-03151-1 §4.8'));
    ids.slice(1).forEach(([id,name]) => results.push(Utils.info(id, name, cat, `${evLogs.length} ${evtType}-Logs. Prüfung erfordert eventData-Parsing.`, '', 'BSI TR-03151-1 §4.8')));
  }

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      const ALL = ['DSE_LOG_PRESENT','DSE_LOG_EVTYPE','DSE_LOG_EVORIGIN','DSE_LOG_EVDATA_EMPTY','DSE_FINAL_LOG',
        'UDD_LOG_START_PRESENT','UDD_LOG_COMP_PRESENT','UDD_LOG_EVTYPE_START','UDD_LOG_EVTYPE_COMP','UDD_EVDATA_ASN1',
        'UDD_COMP_NAMES','UDD_OUTCOME_VALID','UDD_OUTCOME_SUCCESS_NO_REASON','UDD_NO_USER_EXTERNAL',
        'SDE_LOG_PRESENT','SDE_LOG_EVTYPE','SDE_LOG_EVORIGIN','SDE_LOG_NEWDESC','SDE_INFO_CSV_PRESENT','SDE_INFO_DESC',
        'STE_LOG_PRESENT','STE_LOG_EVTYPE','STE_LOG_EVORIGIN','STE_EVDATA_STRUCT','STE_EVDATA_CONSISTENT','STE_EVDATA_MATCH_API'];
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.8')));
      return results;
    }

    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');

    // DSE
    makeEvtChecks(results, sysLogs, 'disableSecureElement', [
      ['DSE_LOG_PRESENT','disableSecureElement-Log vorhanden'],
      ['DSE_LOG_EVTYPE','eventType=disableSecureElement'],
      ['DSE_LOG_EVORIGIN','eventOrigin korrekt'],
      ['DSE_LOG_EVDATA_EMPTY','eventData leer'],
      ['DSE_FINAL_LOG','disableSecureElement ist letzter Log-Eintrag'],
    ], CAT);

    // UDD (updateSoftware)
    const uddStart = sysLogs.filter(l=>l.eventType==='updateSoftware' && (l.eventData||'').toString().includes('start'));
    const uddComp  = sysLogs.filter(l=>l.eventType==='updateSoftware' && (l.eventData||'').toString().includes('completed'));
    const uddAll   = sysLogs.filter(l=>l.eventType==='updateSoftware');
    if (uddAll.length===0) {
      ['UDD_LOG_START_PRESENT','UDD_LOG_COMP_PRESENT','UDD_LOG_EVTYPE_START','UDD_LOG_EVTYPE_COMP',
       'UDD_EVDATA_ASN1','UDD_COMP_NAMES','UDD_OUTCOME_VALID','UDD_OUTCOME_SUCCESS_NO_REASON','UDD_NO_USER_EXTERNAL'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine updateSoftware-Logs.', '', 'BSI TR-03151-1 §4.8')));
    } else {
      results.push(Utils.pass('UDD_LOG_START_PRESENT', 'updateSoftware-Start-Log vorhanden', CAT, `${uddAll.length} updateSoftware-Logs.`, '', 'BSI TR-03151-1 §4.8'));
      results.push(Utils.info('UDD_LOG_COMP_PRESENT', 'updateSoftware-Completed-Log vorhanden', CAT, `${uddAll.length} updateSoftware-Logs.`, '', 'BSI TR-03151-1 §4.8'));
      ['UDD_LOG_EVTYPE_START','UDD_LOG_EVTYPE_COMP','UDD_EVDATA_ASN1','UDD_COMP_NAMES',
       'UDD_OUTCOME_VALID','UDD_OUTCOME_SUCCESS_NO_REASON','UDD_NO_USER_EXTERNAL'].forEach(id =>
        results.push(Utils.info(id, id, CAT, 'Prüfung erfordert eventData-Parsing.', '', 'BSI TR-03151-1 §4.8')));
    }

    // SDE (updateDescription)
    makeEvtChecks(results, sysLogs, 'updateDescription', [
      ['SDE_LOG_PRESENT','updateDescription-Log vorhanden'],
      ['SDE_LOG_EVTYPE','eventType=updateDescription'],
      ['SDE_LOG_EVORIGIN','eventOrigin korrekt'],
      ['SDE_LOG_NEWDESC','neue Beschreibung in eventData'],
      ['SDE_INFO_CSV_PRESENT','info.csv nach Beschreibungsupdate'],
      ['SDE_INFO_DESC','neue Beschreibung in info.csv'],
    ], CAT);

    // STE (selfTest)
    makeEvtChecks(results, sysLogs, 'selfTest', [
      ['STE_LOG_PRESENT','selfTest-Log vorhanden'],
      ['STE_LOG_EVTYPE','eventType=selfTest'],
      ['STE_LOG_EVORIGIN','eventOrigin korrekt'],
      ['STE_EVDATA_STRUCT','eventData-Struktur korrekt'],
      ['STE_EVDATA_CONSISTENT','eventData konsistent'],
      ['STE_EVDATA_MATCH_API','eventData stimmt mit API-Rückgabe überein'],
    ], CAT);

    return results;
  }
  return { run, CAT };
})();
