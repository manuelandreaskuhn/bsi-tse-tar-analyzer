'use strict';
window.RulesCat26 = (function() {
  const CAT = 'Externe Seriennummer (ESN)';
  const REF = 'BSI TR-03151-1 §3.1';

  // Valid hash output lengths for serialNumber (SHA-256 = 32, SHA-384 = 48 bytes)
  const VALID_SN_LENGTHS = new Set([32, 48]);

  function run(ctx) {
    const results = [];
    const { parsedLogs, parsedCerts, archiveType } = ctx;
    const ALL = ['ESN_CROSS_CERT','ESN_CROSS_LOG','ESN_ASN1','ESN_CERT_HASH_MATCH'];

    const certs = parsedCerts || [];
    const validLogs = (parsedLogs||[]).filter(l=>!l.parseError);

    // ── ESN_CROSS_CERT ────────────────────────────────────────────────────
    // serialNumber in logs must match the Subject Key Identifier / serial from the leaf certificate
    const logSerials = validLogs.map(l=>l.serialNumber ? Utils.hexString(l.serialNumber) : null).filter(Boolean);
    const logSNUniq  = [...new Set(logSerials)];
    const certSKIs   = certs.map(c=>Utils.hexString(c.subjectKeyIdentifier || c.serialNumber || new Uint8Array())).filter(Boolean);
    const certSKIUniq = [...new Set(certSKIs)];

    if (logSNUniq.length === 0 || certSKIUniq.length === 0) {
      results.push(Utils.skip('ESN_CROSS_CERT', 'serialNumber in Logs stimmt mit Zertifikats-SKI überein', CAT,
        logSNUniq.length === 0 ? 'Keine Logs mit serialNumber.' : 'Keine Zertifikate im Archiv.',
        '', REF));
    } else {
      // Check if the log serialNumber appears in any cert's SKI/serial
      const matched = logSNUniq.filter(sn => certSKIUniq.some(ski => ski.startsWith(sn) || sn.startsWith(ski)));
      results.push(matched.length > 0
        ? Utils.pass('ESN_CROSS_CERT', 'serialNumber in Logs stimmt mit Zertifikats-SKI überein', CAT,
            `Log-serialNumber (${logSNUniq[0].slice(0,32)}…) in Zertifikat-SKIs gefunden. ${certs.length} Zertifikat(e) geprüft.`,
            'Die serialNumber in allen Logs muss mit dem Subject Key Identifier des Leaf-Zertifikats übereinstimmen.', REF)
        : Utils.warn('ESN_CROSS_CERT', 'serialNumber in Logs stimmt mit Zertifikats-SKI überein', CAT,
            `Log-serialNumber (${logSNUniq[0].slice(0,32)}…) konnte in keinem Zertifikats-SKI (${certSKIUniq.length} Zertifikat(e)) gefunden werden.`,
            'Die serialNumber muss mit dem Subject Key Identifier des Leaf-Zertifikats übereinstimmen.', REF));
    }

    // ── ESN_CROSS_LOG ─────────────────────────────────────────────────────
    results.push(logSNUniq.length === 1
      ? Utils.pass('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT,
          `Alle ${validLogs.length} Logs: serialNumber = ${logSNUniq[0].slice(0,32)}…`, '', 'BSI TR-03153-1 §9.3.2')
      : logSNUniq.length === 0
        ? Utils.skip('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT, 'Keine Logs mit serialNumber.', '', 'BSI TR-03153-1 §9.3.2')
        : Utils.fail('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT,
            `${logSNUniq.length} verschiedene serialNumbers in Logs:\n${logSNUniq.map(s=>s.slice(0,32)).join('\n')}`,
            'Alle Log-Nachrichten müssen dieselbe serialNumber enthalten.', 'BSI TR-03153-1 §9.3.2'));

    // ── ESN_ASN1 ──────────────────────────────────────────────────────────
    // serialNumber bytes should have a length matching a SHA-256 (32) or SHA-384 (48) hash
    const logsWithSN = validLogs.filter(l => l.serialNumber);
    if (logsWithSN.length === 0) {
      results.push(Utils.skip('ESN_ASN1', 'serialNumber-Länge plausibel (SHA-256 oder SHA-384)', CAT,
        'Keine Logs mit serialNumber.', '', REF));
    } else {
      const snLengths = [...new Set(logsWithSN.map(l => (l.serialNumber.length || l.serialNumber.byteLength || 0)))];
      const invalidLengths = snLengths.filter(len => !VALID_SN_LENGTHS.has(len));
      results.push(invalidLengths.length === 0
        ? Utils.pass('ESN_ASN1', 'serialNumber-Länge plausibel (SHA-256 oder SHA-384)', CAT,
            `serialNumber-Länge(n): ${snLengths.join(', ')} Bytes – entspricht SHA-256 (32 B) bzw. SHA-384 (48 B).`,
            'Die serialNumber muss ein SHA-256- oder SHA-384-Hash-Wert sein (32 oder 48 Bytes).', REF)
        : Utils.warn('ESN_ASN1', 'serialNumber-Länge plausibel (SHA-256 oder SHA-384)', CAT,
            `Unerwartete serialNumber-Länge(n): ${invalidLengths.join(', ')} Bytes (erwartet: 32 oder 48).`,
            'Die serialNumber muss 32 Bytes (SHA-256) oder 48 Bytes (SHA-384) lang sein.', REF));
    }

    // ── ESN_CERT_HASH_MATCH ───────────────────────────────────────────────
    // Full verification requires computing SHA-256/384 of the cert's public key → async crypto
    results.push(Utils.info('ESN_CERT_HASH_MATCH', 'serialNumber = SHA-256/384 des TSE-Public-Keys', CAT,
      'Die kryptographische Verifikation (SHA-256/384-Hash des öffentlichen Schlüssels aus dem Leaf-Zertifikat) erfordert async Web Crypto API und liegt außerhalb des synchronen Regelmoduls.',
      'Die serialNumber muss dem SHA-256- oder SHA-384-Hash des öffentlichen TSE-Schlüssels entsprechen.', REF));

    return results;
  }
  return { run, CAT };
})();

