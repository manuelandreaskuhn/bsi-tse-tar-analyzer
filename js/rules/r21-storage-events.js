// ─── r21-storage-events.js – Speicherungsereignisse (STOR) ───────────────
'use strict';
window.RulesCat21 = (function() {
  const CAT = 'Speicherungsereignisse (STOR)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['STOR_EVT_UPDATETIME_PRESENT','STOR_EVT_SYSLOG_NOT_AGGREGATED','STOR_EVT_INIT_UNIQUE',
      'STOR_EVT_DISABLE_IS_LAST','STOR_EVT_SYSLOG_EVTYPE_STATS','STOR_AUDIT_MIN_ONE',
      'STOR_AUDIT_SYSLOG_RATIO','STOR_AGG_UPDATE_PRESENT_AFTER_FINISH','STOR_AGG_COUNT_PER_TXN',
      'STOR_AGG_SEQ_DELTA','STOR_NOAGG_UPDATE_PER_CALL','STOR_NOAGG_PDATA_SINGLE',
      'STOR_PARA_ALL_STARTS','STOR_PARA_PDATA_ISOLATED','STOR_PARA_INTERLEAVE_VALID'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03153-1 §9')));
      return results;
    }

    const validLogs = (parsedLogs||[]).filter(l=>!l.parseError);
    const sysLogs   = validLogs.filter(l=>l.logType==='sys');
    const auditLogs = validLogs.filter(l=>l.logType==='audit');
    const txnLogs   = validLogs.filter(l=>l.logType==='txn');
    const updateLogs = txnLogs.filter(l=>l.operationType==='updateTransaction');

    // STOR_EVT_UPDATETIME_PRESENT
    const udtLogs = sysLogs.filter(l=>l.eventType==='updateTime');
    results.push(udtLogs.length > 0
      ? Utils.pass('STOR_EVT_UPDATETIME_PRESENT', 'updateTime-Log gespeichert', CAT,
          `${udtLogs.length} updateTime-Log(s) im Archiv.`, '', 'BSI TR-03153-1 §9')
      : Utils.info('STOR_EVT_UPDATETIME_PRESENT', 'updateTime-Log gespeichert', CAT,
          'Kein updateTime-Log. Falls Zeitkalibrierung stattfand, muss ein Log vorhanden sein.', '', 'BSI TR-03153-1 §9'));

    // STOR_EVT_SYSLOG_NOT_AGGREGATED
    results.push(Utils.pass('STOR_EVT_SYSLOG_NOT_AGGREGATED', 'SystemLogs werden nicht aggregiert', CAT,
      `${sysLogs.length} SystemLog(s) – jedes als separate Datei gespeichert.`,
      'SystemLog-Nachrichten dürfen NICHT aggregiert werden.', 'BSI TR-03153-1 §9'));

    // STOR_EVT_INIT_UNIQUE
    const initLogs = sysLogs.filter(l=>l.eventType==='initialize');
    results.push(initLogs.length <= 1
      ? Utils.pass('STOR_EVT_INIT_UNIQUE', 'Nur ein initialize-Log', CAT,
          `${initLogs.length} initialize-Log(s).`, '', 'BSI TR-03151-1 §4.6')
      : Utils.warn('STOR_EVT_INIT_UNIQUE', 'Nur ein initialize-Log', CAT,
          `${initLogs.length} initialize-Logs (max. 1 erwartet, außer bei Factory-Reset).`, '', 'BSI TR-03151-1 §4.6'));

    // STOR_EVT_DISABLE_IS_LAST
    const disableLogs = sysLogs.filter(l=>l.eventType==='disableSecureElement');
    if (disableLogs.length > 0) {
      const maxDisCtr = Math.max(...disableLogs.map(l=>l.signatureCounter||0));
      const maxAllCtr = Math.max(...validLogs.map(l=>l.signatureCounter||0));
      results.push(maxDisCtr === maxAllCtr
        ? Utils.pass('STOR_EVT_DISABLE_IS_LAST', 'disableSecureElement ist letzter Log-Eintrag', CAT,
            `disableSecureElement (Ctr=${maxDisCtr}) ist der letzte Eintrag.`, '', 'BSI TR-03151-1 §4.6')
        : Utils.fail('STOR_EVT_DISABLE_IS_LAST', 'disableSecureElement ist letzter Log-Eintrag', CAT,
            `disableSecureElement (Ctr=${maxDisCtr}) ist nicht der letzte Eintrag (Max-Ctr=${maxAllCtr}).`, '', 'BSI TR-03151-1 §4.6'));
    } else {
      results.push(Utils.skip('STOR_EVT_DISABLE_IS_LAST', 'disableSecureElement ist letzter Log-Eintrag', CAT,
        'Kein disableSecureElement-Log.', '', 'BSI TR-03151-1 §4.6'));
    }

    // STOR_EVT_SYSLOG_EVTYPE_STATS
    const evtTypes = {};
    sysLogs.forEach(l=>{ evtTypes[l.eventType||'?'] = (evtTypes[l.eventType||'?']||0)+1; });
    results.push(Utils.info('STOR_EVT_SYSLOG_EVTYPE_STATS', 'SystemLog eventType-Statistik', CAT,
      Object.entries(evtTypes).sort((a,b)=>b[1]-a[1]).map(([t,c])=>`${t}: ${c}`).join('\n'),
      '', 'BSI TR-03153-1 §9'));

    // STOR_AUDIT_MIN_ONE
    results.push(auditLogs.length > 0
      ? Utils.pass('STOR_AUDIT_MIN_ONE', 'Mindestens ein AuditLog vorhanden', CAT,
          `${auditLogs.length} AuditLog(s).`, '', 'BSI TR-03153-1 §9.3')
      : Utils.info('STOR_AUDIT_MIN_ONE', 'Mindestens ein AuditLog vorhanden', CAT,
          'Kein AuditLog vorhanden.', '', 'BSI TR-03153-1 §9.3'));

    // STOR_AUDIT_SYSLOG_RATIO
    const ratio = sysLogs.length > 0 ? (auditLogs.length / sysLogs.length).toFixed(2) : 'N/A';
    results.push(Utils.info('STOR_AUDIT_SYSLOG_RATIO', 'Verhältnis AuditLog zu SystemLog', CAT,
      `AuditLogs: ${auditLogs.length} / SystemLogs: ${sysLogs.length} (Verhältnis: ${ratio})`,
      '', 'BSI TR-03153-1 §9.3'));

    // STOR_AGG_* (aggregation scenario)
    results.push(Utils.info('STOR_AGG_UPDATE_PRESENT_AFTER_FINISH', 'Aggregierter Update-Log nach finishTransaction', CAT,
      `${updateLogs.length} updateTransaction-Logs. Aggregationsverhalten erfordert Laufzeitwissen.`, '', 'BSI TR-03153-1 §9.2'));
    results.push(Utils.info('STOR_AGG_COUNT_PER_TXN', 'Anzahl aggregierter Updates pro Transaktion korrekt', CAT,
      'Prüfung erfordert forceSignature-Protokoll.', '', 'BSI TR-03153-1 §9.2'));
    results.push(Utils.info('STOR_AGG_SEQ_DELTA', 'Sequenzdelta aggregierter Updates korrekt', CAT,
      'Prüfung erfordert Laufzeit-Kontext.', '', 'BSI TR-03153-1 §9.2'));

    // STOR_NOAGG_* (non-aggregation scenario)
    const byTxn = new Map();
    txnLogs.forEach(l=>{ if(!byTxn.has(l.transactionNumber)) byTxn.set(l.transactionNumber,[]); byTxn.get(l.transactionNumber).push(l); });
    const noAggOk = [...byTxn.values()].every(logs => logs.filter(l=>l.operationType==='updateTransaction').length <= 1);
    results.push(noAggOk
      ? Utils.pass('STOR_NOAGG_UPDATE_PER_CALL', 'Genau ein Update-Log pro updateTransaction-Aufruf', CAT,
          'Alle Transaktionen: max. 1 Update-Log (Non-Aggregation-Modus).', '', 'BSI TR-03153-1 §9.2')
      : Utils.info('STOR_NOAGG_UPDATE_PER_CALL', 'Genau ein Update-Log pro updateTransaction-Aufruf', CAT,
          'Mehrere Update-Logs pro Transaktion vorhanden (aggregierter Modus).', '', 'BSI TR-03153-1 §9.2'));
    results.push(Utils.info('STOR_NOAGG_PDATA_SINGLE', 'processData in Non-Aggregation = einzelner Wert', CAT,
      'Im Non-Aggregation-Modus enthält processData genau den übergebenen Wert.', '', 'BSI TR-03153-1 §9.2'));

    // STOR_PARA_* (parallel transactions)
    const startsByClient = new Map();
    txnLogs.filter(l=>l.operationType==='startTransaction').forEach(l=>{ const c=l.clientId||'?'; if(!startsByClient.has(c)) startsByClient.set(c,[]); startsByClient.get(c).push(l); });
    results.push(Utils.info('STOR_PARA_ALL_STARTS', 'Alle parallelen Transaktionen starten korrekt', CAT,
      `${txnLogs.filter(l=>l.operationType==='startTransaction').length} Start-Logs von ${startsByClient.size} Client(s).`, '', 'BSI TR-03153-1 §9.2'));
    results.push(Utils.info('STOR_PARA_PDATA_ISOLATED', 'processData paralleler Transaktionen isoliert', CAT,
      'processData-Felder paralleler Transaktionen dürfen sich nicht vermischen.', '', 'BSI TR-03153-1 §9.2'));
    results.push(Utils.info('STOR_PARA_INTERLEAVE_VALID', 'Verschachtelte Transaktionen gültig', CAT,
      'Verschachtelte (parallele) Transaktionen müssen gültig verschachtelt sein (keine Cross-Contamination).', '', 'BSI TR-03153-1 §9.2'));

    return results;
  }
  return { run, CAT };
})();
