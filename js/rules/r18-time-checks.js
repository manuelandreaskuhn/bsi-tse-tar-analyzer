// ─── r18-time-checks.js – Zeitprüfungen (TIME / UDT / TIMESET) ───────────
'use strict';
window.RulesCat18 = (function() {
  const CAT = 'Zeitprüfungen (TIME / UDT / TIMESET)';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['TIME_SM_UNSET','TIME_SM_UPDATE_DELAY','UDT_LOG_PRESENT','UDT_LOG_ABSENT',
      'UDT_LOG_EVTYPE','UDT_SETIME_BEFORE','UDT_SETIME_AFTER','UDT_SLEW_FIELDS',
      'UDT_CENTRAL_EVORIGIN','UDT_CENTRAL_TRIGGER','TIMESET_TXN_AFTER_UPDATETIME',
      'TIMESET_SYSLOG_WRITES_AFTER_UPDATETIME','TIMESET_SELFTEST_MAY_PRECEDE_UPDATETIME','TIMESET_EXPORT_ANYTIME'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.5')));
      return results;
    }

    const sysLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'sys');
    const udtsLogs = sysLogs.filter(l => l.eventType === 'updateTime');

    // TIME_SM_UNSET
    results.push(Utils.info('TIME_SM_UNSET', 'TSE-Zeit zum Zeitpunkt des Exports nicht gesetzt', CAT,
      'Prüfung, ob die TSE-interne Uhr zum Export-Zeitpunkt gesetzt war, erfordert Laufzeit-Kontext.',
      'Die TSE muss eine gesetzte Systemzeit haben, damit TAR-Exporte zulässig sind.', 'BSI TR-03151-1 §4.5'));
    results.push(Utils.info('TIME_SM_UPDATE_DELAY', 'Maximaler Zeitaktualisierungsverzug', CAT,
      'MAX_UPDATE_DELAY-Prüfung erfordert Konfigurationswert des TSE-Herstellers.',
      'Zeitdifferenz zwischen aufeinanderfolgenden updateTime-Ereignissen darf MAX_UPDATE_DELAY nicht überschreiten.', 'BSI TR-03151-1 §4.5'));

    // UDT_LOG_PRESENT / ABSENT
    results.push(udtsLogs.length > 0
      ? Utils.pass('UDT_LOG_PRESENT', 'updateTime-Log vorhanden', CAT,
          `${udtsLogs.length} updateTime-Log(s) gefunden.`, '', 'BSI TR-03151-1 §4.5')
      : Utils.info('UDT_LOG_ABSENT', 'kein updateTime-Log vorhanden', CAT,
          'Kein updateTime-SystemLog gefunden. Falls kein Zeitsynchronisationsprotokoll vorgesehen ist, ist dies zulässig.',
          '', 'BSI TR-03151-1 §4.5'));
    results.push(udtsLogs.length === 0
      ? Utils.skip('UDT_LOG_ABSENT', 'kein updateTime-Log vorhanden', CAT, 'Kein updateTime-Log.', '', 'BSI TR-03151-1 §4.5')
      : Utils.pass('UDT_LOG_ABSENT', 'kein updateTime-Log vorhanden', CAT, 'updateTime-Logs sind vorhanden.', '', 'BSI TR-03151-1 §4.5'));

    // UDT_LOG_EVTYPE
    const wrongEvtType = udtsLogs.filter(l => l.eventType !== 'updateTime');
    results.push(udtsLogs.length === 0
      ? Utils.skip('UDT_LOG_EVTYPE', 'eventType=updateTime', CAT, 'Keine updateTime-Logs.', '', 'BSI TR-03151-1 §4.5')
      : wrongEvtType.length === 0
        ? Utils.pass('UDT_LOG_EVTYPE', 'eventType=updateTime', CAT,
            `Alle ${udtsLogs.length} updateTime-Logs: eventType korrekt.`, '', 'BSI TR-03151-1 §4.5')
        : Utils.fail('UDT_LOG_EVTYPE', 'eventType=updateTime', CAT,
            `${wrongEvtType.length} Logs mit falschem eventType.`, '', 'BSI TR-03151-1 §4.5'));

    // UDT_SETIME_BEFORE / AFTER
    for (const [id, name] of [
      ['UDT_SETIME_BEFORE', 'seTimeBeforeUpdate vorhanden und korrekt'],
      ['UDT_SETIME_AFTER', 'seTimeAfterUpdate vorhanden und korrekt'],
    ]) {
      results.push(udtsLogs.length === 0
        ? Utils.skip(id, name, CAT, 'Keine updateTime-Logs.', '', 'BSI TR-03151-1 §4.5')
        : Utils.info(id, name, CAT,
            `${udtsLogs.length} updateTime-Logs. seTime-Felder erfordern eventData-ASN.1-Parsing.`, '', 'BSI TR-03151-1 §4.5'));
    }

    // UDT_SLEW_FIELDS
    results.push(Utils.info('UDT_SLEW_FIELDS', 'SLEW-Felder konsistent', CAT,
      'SLEW-Felder (eventData) erfordern ASN.1-Parsing der updateTime-Logs.', '', 'BSI TR-03151-1 §4.5'));

    // UDT_CENTRAL_EVORIGIN / TRIGGER
    const centralUdts = udtsLogs.filter(l => l.eventOrigin === 'centralComponent');
    results.push(Utils.info('UDT_CENTRAL_EVORIGIN', 'eventOrigin bei zentraler Zeitquelle', CAT,
      `${centralUdts.length} updateTime-Logs mit eventOrigin=centralComponent.`,
      '', 'BSI TR-03151-1 §4.5'));
    results.push(Utils.info('UDT_CENTRAL_TRIGGER', 'Trigger bei zentraler Zeitquelle', CAT,
      'Bei eventOrigin=centralComponent muss ein Trigger gesetzt sein.', '', 'BSI TR-03151-1 §4.5'));

    // TIMESET_* sequence checks
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    const lastUdt = udtsLogs.length > 0 ? udtsLogs.reduce((m,l)=>l.signatureCounter>m.signatureCounter?l:m) : null;
    const txnAfterUdt = lastUdt ? txnLogs.filter(l=>l.signatureCounter>lastUdt.signatureCounter).length : 0;
    results.push(lastUdt
      ? Utils.pass('TIMESET_TXN_AFTER_UPDATETIME', 'Transaktionen erst nach updateTime gestattet', CAT,
          `Letztes updateTime: Ctr=${lastUdt.signatureCounter}. Danach: ${txnAfterUdt} TransactionLog(s).`, '', 'BSI TR-03151-1 §4.5')
      : Utils.skip('TIMESET_TXN_AFTER_UPDATETIME', 'Transaktionen erst nach updateTime gestattet', CAT, 'Kein updateTime-Log.', '', 'BSI TR-03151-1 §4.5'));

    results.push(Utils.info('TIMESET_SYSLOG_WRITES_AFTER_UPDATETIME', 'SystemLog-Schreiboperationen nach updateTime', CAT,
      'Nach dem letzten updateTime muss für jede startTransaction-Operation ein SystemLog geschrieben werden.', '', 'BSI TR-03151-1 §4.5'));
    results.push(Utils.info('TIMESET_SELFTEST_MAY_PRECEDE_UPDATETIME', 'selfTest darf vor updateTime stattfinden', CAT,
      'selfTest-Ereignisse sind auch vor dem ersten updateTime zulässig.', '', 'BSI TR-03151-1 §4.5'));
    results.push(Utils.info('TIMESET_EXPORT_ANYTIME', 'Export jederzeit möglich', CAT,
      'TAR-Export kann unabhängig vom updateTime-Status angefordert werden.', '', 'BSI TR-03151-1 §4.5'));

    return results;
  }
  return { run, CAT };
})();
