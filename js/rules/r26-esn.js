'use strict';
'use strict';
window.RulesCat26 = (function() {
  const CAT = 'Externe Seriennummer (ESN)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, parsedCerts, archiveType } = ctx;
    const ALL = ['ESN_CROSS_CERT','ESN_CROSS_LOG','ESN_ASN1','ESN_CERT_HASH_MATCH'];

    const certs = parsedCerts || [];
    const validLogs = (parsedLogs||[]).filter(l=>!l.parseError);

    // ESN_CROSS_CERT
    const certSerials = certs.map(c=>Utils.hexString(c.serialNumber||new Uint8Array()));
    const certSNUniq = [...new Set(certSerials)];
    results.push(Utils.info('ESN_CROSS_CERT', 'Seriennummer in Zertifikat und Logs identisch', CAT,
      certs.length > 0
        ? `${certs.length} Zertifikat(e). Öffentliche Schlüssel / Seriennummern: ${certSNUniq.map(s=>s.slice(0,16)).join(', ')}`
        : 'Keine Zertifikate im Archiv.',
      '', 'BSI TR-03153-1 §9.3.2'));

    // ESN_CROSS_LOG
    const logSerials = validLogs.map(l=>l.serialNumber ? Utils.hexString(l.serialNumber) : null).filter(Boolean);
    const logSNUniq = [...new Set(logSerials)];
    results.push(logSNUniq.length === 1
      ? Utils.pass('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT,
          `Alle ${validLogs.length} Logs: serialNumber = ${logSNUniq[0].slice(0,32)}…`, '', 'BSI TR-03153-1 §9.3.2')
      : logSNUniq.length === 0
        ? Utils.skip('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT, 'Keine Logs mit serialNumber.', '', 'BSI TR-03153-1 §9.3.2')
        : Utils.fail('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT,
            `${logSNUniq.length} verschiedene serialNumbers in Logs.`, '', 'BSI TR-03153-1 §9.3.2'));

    // ESN_ASN1
    results.push(Utils.info('ESN_ASN1', 'serialNumber-ASN.1-Encoding korrekt', CAT,
      'Die serialNumber ist ein BIT STRING oder OCTET STRING mit dem öffentlichen Schlüssel-Hash.',
      '', 'BSI TR-03151-1 §3.1'));

    // ESN_CERT_HASH_MATCH
    results.push(Utils.info('ESN_CERT_HASH_MATCH', 'serialNumber = SHA-256/384 des Public Key', CAT,
      'Die serialNumber muss dem Hash des öffentlichen TSE-Schlüssels entsprechen (SHA-256 oder SHA-384).',
      '', 'BSI TR-03151-1 §3.1'));

    return results;
  }
  return { run, CAT };
})();

