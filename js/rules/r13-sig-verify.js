// ─── r13-sig-verify.js – Signatur-Zähler & Verifikation (SIG) ────────────
'use strict';
window.RulesCat13 = (function() {
  const CAT = 'Signatur-Zähler & Verifikation (SIG)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['SIG_VERIFY_LOGMSG','SIG_VERIFY_CONCAT','SIG_CTR_OVERFLOW_CHECK'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine Log-Nachrichten.', '', 'BSI TR-03151-1 §5.3')));
      return results;
    }
    const validLogs = (parsedLogs || []).filter(l => !l.parseError);

    // SIG_VERIFY_LOGMSG
    results.push(Utils.info('SIG_VERIFY_LOGMSG', 'Kryptographische Signaturverifikation der Log-Nachrichten', CAT,
      `${validLogs.length} Log-Nachrichten vorhanden. Kryptographische Signaturverifikation erfordert Web Crypto API (ECDSA P-384) und den TSE-Public-Key aus dem Blatt-Zertifikat. Dieser Check ist in dieser Version als Info markiert.`,
      'Für jede Log-Nachricht wird die Signatur kryptographisch verifiziert (ECDSA-plain-SHA384/SHA256 mit TSE-Public-Key).',
      'BSI TR-03151-1 §5.3; SM_CON_01–SM_CON_12'));

    // SIG_VERIFY_CONCAT
    results.push(Utils.info('SIG_VERIFY_CONCAT', 'Korrektheit der Feldkonkatenation', CAT,
      'Prüfung der Konkatenationsreihenfolge gemäß BSI TR-03151-1 §9 (version ∥ serialNumber ∥ signatureAlgorithm ∥ signatureCounter ∥ signatureCreationTime ∥ certifiedDataType ∥ …). Vollständige Verifikation erfordert kryptographische Signaturprüfung.',
      'Die zu signierenden Felder werden gemäß BSI TR-03151-1 §9 konkateniert und mit dem signatureValue verglichen.',
      'BSI TR-03151-1 §9; SM_CON_01–SM_CON_12'));

    // SIG_CTR_OVERFLOW_CHECK
    const MAX_COUNTER = 0xFFFFFFFF;
    const nearMax = validLogs.filter(l => l.signatureCounter != null && l.signatureCounter > MAX_COUNTER - 1000);
    if (nearMax.length > 0) {
      results.push(Utils.warn('SIG_CTR_OVERFLOW_CHECK', 'Kein signatureCounter am oder über dem Maximalwert', CAT,
        `${nearMax.length} Log(s) mit signatureCounter nahe dem Maximum (${MAX_COUNTER}):\n${nearMax.map(l=>`  ${l._filename}: Ctr=${l.signatureCounter}`).join('\n')}`,
        'Kein signatureCounter darf den Maximalwert (0xFFFFFFFF) erreichen oder überschreiten.',
        'BSI TR-03153-1 §9.1'));
    } else {
      const maxCtr = validLogs.length > 0 ? Math.max(...validLogs.map(l=>l.signatureCounter||0)) : 0;
      results.push(Utils.pass('SIG_CTR_OVERFLOW_CHECK', 'Kein signatureCounter am oder über dem Maximalwert', CAT,
        `Maximaler signatureCounter: ${maxCtr} (weit unterhalb ${MAX_COUNTER}).`,
        'Kein signatureCounter darf den Maximalwert erreichen oder überschreiten.',
        'BSI TR-03153-1 §9.1'));
    }
    return results;
  }
  return { run, CAT };
})();
