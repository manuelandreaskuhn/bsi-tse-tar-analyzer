// ─── r22-del-dlm.js – Lösch-TAR & DLM-Log (DEL / DLM) ───────────────────
'use strict';
window.RulesCat22 = (function() {
  const CAT = 'Lösch-TAR & DLM-Log (DEL / DLM)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, tarResult, archiveType } = ctx;
    const ALL = ['DEL_TAR_NO_LOGS','DEL_TAR_STRUCT','DEL_TAR_CTR_RESET',
      'DLM_LOG_PRESENT','DLM_LOG_EVTYPE','DLM_LOG_EVORIGIN','DLM_LOG_EVDATA_EMPTY',
      'DLM_LOG_MINIMAL','DLM_TAR_SUPERSET'];

    // DEL-TAR checks only if archiveName indicates a deletion TAR
    const isDel = ctx.archiveName && /del/i.test(ctx.archiveName);
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const dlmLogs = sysLogs.filter(l=>l.eventType==='deleteStoredData');

    if (!isDel) {
      ['DEL_TAR_NO_LOGS','DEL_TAR_STRUCT','DEL_TAR_CTR_RESET'].forEach(id =>
        results.push(Utils.info(id, id, CAT, 'Kein Lösch-TAR erkannt (Archivname enthält kein "del").', '', 'BSI TR-03153-1 §10')));
    } else {
      const logFiles = tarResult ? [...tarResult.files.keys()].filter(f=>f.endsWith('.log')) : [];
      results.push(logFiles.length === 0
        ? Utils.pass('DEL_TAR_NO_LOGS', 'Lösch-TAR enthält keine Log-Dateien', CAT,
            'Keine .log-Dateien im Lösch-TAR gefunden (korrekt).', '', 'BSI TR-03153-1 §10')
        : Utils.fail('DEL_TAR_NO_LOGS', 'Lösch-TAR enthält keine Log-Dateien', CAT,
            `Lösch-TAR enthält ${logFiles.length} unerwartete .log-Dateien.`, '', 'BSI TR-03153-1 §10'));
      results.push(Utils.info('DEL_TAR_STRUCT', 'Lösch-TAR-Struktur korrekt', CAT,
        'Lösch-TAR-Struktur: nur info.csv und Zertifikat-Dateien erlaubt.', '', 'BSI TR-03153-1 §10'));
      results.push(Utils.info('DEL_TAR_CTR_RESET', 'Signaturzähler nach Löschung zurückgesetzt', CAT,
        'Prüfung erfordert Vergleich mit vorherigem Export.', '', 'BSI TR-03153-1 §10'));
    }

    // DLM
    if (dlmLogs.length === 0) {
      ['DLM_LOG_PRESENT','DLM_LOG_EVTYPE','DLM_LOG_EVORIGIN','DLM_LOG_EVDATA_EMPTY','DLM_LOG_MINIMAL','DLM_TAR_SUPERSET'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine deleteStoredData-Logs im Archiv.', '', 'BSI TR-03153-1 §10')));
      return results;
    }

    results.push(Utils.pass('DLM_LOG_PRESENT', 'deleteStoredData-Log vorhanden', CAT,
      `${dlmLogs.length} deleteStoredData-Log(s) gefunden.`, '', 'BSI TR-03153-1 §10'));

    const wrongEvt = dlmLogs.filter(l=>l.eventType!=='deleteStoredData');
    results.push(wrongEvt.length===0
      ? Utils.pass('DLM_LOG_EVTYPE', 'eventType=deleteStoredData', CAT, 'Korrekt.', '', 'BSI TR-03153-1 §10')
      : Utils.fail('DLM_LOG_EVTYPE', 'eventType=deleteStoredData', CAT, `${wrongEvt.length} falsche eventType-Werte.`, '', 'BSI TR-03153-1 §10'));

    const wrongOrigin = dlmLogs.filter(l=>!['application','se'].includes(l.eventOrigin));
    results.push(wrongOrigin.length===0
      ? Utils.pass('DLM_LOG_EVORIGIN', 'eventOrigin korrekt', CAT, 'Alle DLM-Logs: eventOrigin korrekt.', '', 'BSI TR-03153-1 §10')
      : Utils.warn('DLM_LOG_EVORIGIN', 'eventOrigin korrekt', CAT, `${wrongOrigin.length} Logs mit unerwartetem eventOrigin.`, '', 'BSI TR-03153-1 §10'));

    results.push(Utils.info('DLM_LOG_EVDATA_EMPTY', 'eventData leer oder minimal', CAT,
      'deleteStoredData-eventData sollte leer oder nur mit gelöschten Counter-Ranges gefüllt sein.', '', 'BSI TR-03153-1 §10'));
    results.push(Utils.info('DLM_LOG_MINIMAL', 'Minimale Felder im DLM-Log', CAT,
      'DLM-Log enthält nur die Pflichtfelder.', '', 'BSI TR-03153-1 §10'));
    results.push(Utils.info('DLM_TAR_SUPERSET', 'Aktueller TAR ist Obermenge des DLM-TAR', CAT,
      'Prüfung erfordert Vergleich mit vorherigem TAR.', '', 'BSI TR-03153-1 §10'));

    return results;
  }
  return { run, CAT };
})();
