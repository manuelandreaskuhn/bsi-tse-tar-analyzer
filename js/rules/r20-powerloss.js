// ─── r20-powerloss.js ─────────────────────────────────────────────────────
'use strict';
window.RulesCat20 = (function() {
  const CAT = 'Stromausfall-Behandlung (POWERLOSS)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['POWERLOSS_UPDATETIME_AFTER_REENTER','POWERLOSS_NO_ABANDONED_TXN_RESUME',
       'POWERLOSS_LOCK_STATE_RESET','POWERLOSS_MULTIPLE_CYCLES'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.7')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l => !l.parseError && l.logType === 'sys');
    const enterSecure = sysLogs.filter(l => l.eventType === 'enterSecureState');
    const exitSecure  = sysLogs.filter(l => l.eventType === 'exitSecureState');

    results.push(Utils.info('POWERLOSS_UPDATETIME_AFTER_REENTER', 'updateTime nach erneutem Eintritt in sicheren Zustand', CAT,
      `${enterSecure.length} enterSecureState-Log(s) gefunden. Nach Stromausfall ist ein updateTime-Eintrag erforderlich.`,
      '', 'BSI TR-03151-1 §4.7'));
    results.push(Utils.info('POWERLOSS_NO_ABANDONED_TXN_RESUME', 'Keine abgebrochene Transaktion wird fortgesetzt', CAT,
      'Nach Stromausfall müssen offen gebliebene Transaktionen korrekt abgeschlossen oder verworfen werden.',
      '', 'BSI TR-03151-1 §4.7'));
    results.push(Utils.info('POWERLOSS_LOCK_STATE_RESET', 'Lock-Zustand nach Stromausfall zurückgesetzt', CAT,
      `${exitSecure.length} exitSecureState-Log(s) gefunden. Lock-Zustand nach Neustart prüfbar.`,
      '', 'BSI TR-03151-1 §4.7'));

    const pairFails = [];
    const entCtrs = enterSecure.map(l=>l.signatureCounter).sort((a,b)=>a-b);
    const extCtrs  = exitSecure.map(l=>l.signatureCounter).sort((a,b)=>a-b);
    results.push(entCtrs.length === extCtrs.length
      ? Utils.pass('POWERLOSS_MULTIPLE_CYCLES', 'Mehrfache Enter/Exit-Paare symmetrisch', CAT,
          `${entCtrs.length} enterSecureState / ${extCtrs.length} exitSecureState-Paare.`, '', 'BSI TR-03151-1 §4.7')
      : Utils.warn('POWERLOSS_MULTIPLE_CYCLES', 'Mehrfache Enter/Exit-Paare symmetrisch', CAT,
          `Asymmetrisch: ${entCtrs.length} enterSecureState vs. ${extCtrs.length} exitSecureState. Möglicher offener Zyklus.`, '', 'BSI TR-03151-1 §4.7'));

    return results;
  }
  return { run, CAT };
})();
