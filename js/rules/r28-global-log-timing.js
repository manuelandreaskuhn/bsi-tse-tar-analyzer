'use strict';
window.RulesCat28 = (function() {
  const CAT = 'Globale Log-Zeitangaben (GCV / GLL / GLT)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, tarResult, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['GCV_INFO_MATCH','GLL_FNAME_MATCH','GLL_CONTENT_MATCH','GLT_FNAME_MATCH','GLT_CONTENT_MATCH'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03153-1 §7')));
      return results;
    }

    const validLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.signatureCreationTime!=null);
    const sortedByTime = [...validLogs].sort((a,b)=>a.signatureCreationTime-b.signatureCreationTime);
    const firstLog = sortedByTime[0];
    const lastLog  = sortedByTime[sortedByTime.length-1];

    // GCV_INFO_MATCH
    const infoCsv = tarResult ? tarResult.files.get('info.csv') : null;
    results.push(Utils.info('GCV_INFO_MATCH', 'Zeitangaben in info.csv konsistent mit Logs', CAT,
      infoCsv ? 'info.csv vorhanden. Zeitangaben-Abgleich erfordert info.csv-Feld-Parsing.' : 'Keine info.csv.',
      '', 'BSI TR-03153-1 §7'));

    // GLL / GLT
    for (const [id, name, isLast] of [
      ['GLL_FNAME_MATCH','Dateiname des ersten Logs stimmt mit Inhalt', false],
      ['GLL_CONTENT_MATCH','Zeitstempel des ersten Logs stimmt', false],
      ['GLT_FNAME_MATCH','Dateiname des letzten Logs stimmt mit Inhalt', true],
      ['GLT_CONTENT_MATCH','Zeitstempel des letzten Logs stimmt', true],
    ]) {
      const log = isLast ? lastLog : firstLog;
      results.push(log
        ? Utils.info(id, name, CAT,
            `${isLast?'Letzter':'Erster'} Log: ${log._filename} (signatureCreationTime=${Utils.unixToDate(log.signatureCreationTime)}, Ctr=${log.signatureCounter}).`,
            '', 'BSI TR-03153-1 §7')
        : Utils.skip(id, name, CAT, 'Keine Logs mit Zeitstempel.', '', 'BSI TR-03153-1 §7'));
    }
    return results;
  }
  return { run, CAT };
})();

