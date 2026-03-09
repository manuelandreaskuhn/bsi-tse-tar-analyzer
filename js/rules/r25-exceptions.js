// ─── r25-exceptions.js – Ausnahme-Dateien (EXC) ──────────────────────────
'use strict';
window.RulesCat25 = (function() {
  const CAT = 'Ausnahme-Dateien (EXC)';
  function run(ctx) {
    const results = [];
    const { tarResult, archiveType } = ctx;
    const ALL = ['EXC_FNAME_SERIAL','EXC_FNAME_TYPE','EXC_FNAME_EXT','EXC_CERT_X509','EXC_NO_EXTRA_FILES'];
    if (!tarResult) {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'Kein TAR-Ergebnis.', '', 'BSI TR-03153-1 §12')));
      return results;
    }

    const files = [...tarResult.files.keys()];
    // Exception files: files that don't fit standard patterns but are allowed
    const EXC_PATTERN = /^exception_[A-Fa-f0-9]+\.(log|sig|cert|cer|crt|pem)$/i;
    const excFiles = files.filter(f => {
      const bn = f.split('/').pop();
      return EXC_PATTERN.test(bn);
    });

    // EXC_FNAME_SERIAL
    const noSerial = excFiles.filter(f => {
      const bn = f.split('/').pop();
      return !/^exception_[A-Fa-f0-9]+/.test(bn);
    });
    results.push(noSerial.length === 0
      ? Utils.pass('EXC_FNAME_SERIAL', 'Ausnahme-Dateiname enthält Seriennummer', CAT,
          excFiles.length > 0 ? `${excFiles.length} Ausnahme-Datei(en): Seriennummer vorhanden.` : 'Keine Ausnahme-Dateien.',
          'exception_{serialNumber}.{ext}', 'BSI TR-03153-1 §12')
      : Utils.fail('EXC_FNAME_SERIAL', 'Ausnahme-Dateiname enthält Seriennummer', CAT,
          `${noSerial.length} Ausnahme-Dateien ohne Seriennummer.`, '', 'BSI TR-03153-1 §12'));

    // EXC_FNAME_TYPE
    const validExtensions = new Set(['log','sig','cert','cer','crt','pem']);
    const badExt = excFiles.filter(f => {
      const ext = f.split('.').pop().toLowerCase();
      return !validExtensions.has(ext);
    });
    results.push(badExt.length === 0
      ? Utils.pass('EXC_FNAME_TYPE', 'Ausnahme-Dateierweiterung gültig', CAT,
          excFiles.length > 0 ? `Alle ${excFiles.length} Ausnahme-Dateien: Erweiterung gültig.` : 'Keine Ausnahme-Dateien.',
          `Erlaubt: ${[...validExtensions].join(', ')}`, 'BSI TR-03153-1 §12')
      : Utils.fail('EXC_FNAME_TYPE', 'Ausnahme-Dateierweiterung gültig', CAT,
          `${badExt.length} Dateien mit ungültiger Erweiterung: ${badExt.join(', ')}`, '', 'BSI TR-03153-1 §12'));

    // EXC_FNAME_EXT
    results.push(Utils.info('EXC_FNAME_EXT', 'Erweiterung stimmt mit Dateiinhalt überein', CAT,
      excFiles.length > 0 ? `${excFiles.length} Ausnahme-Datei(en). Magic-Byte-Prüfung kann Inhalt validieren.` : 'Keine Ausnahme-Dateien.',
      '', 'BSI TR-03153-1 §12'));

    // EXC_CERT_X509
    const certExcs = excFiles.filter(f=>/\.(cert|cer|crt|pem)$/i.test(f));
    results.push(certExcs.length === 0
      ? Utils.skip('EXC_CERT_X509', 'Ausnahme-Zertifikat gültig X.509', CAT, 'Keine Ausnahme-Zertifikat-Dateien.', '', 'BSI TR-03153-1 §12')
      : Utils.info('EXC_CERT_X509', 'Ausnahme-Zertifikat gültig X.509', CAT,
          `${certExcs.length} Ausnahme-Zertifikat(e). ASN.1-Parsing zur X.509-Validierung durchführbar.`, '', 'BSI TR-03153-1 §12'));

    // EXC_NO_EXTRA_FILES
    const allowedPatterns = [
      /^info\.csv$/i,
      /\.(log)$/i,
      /\.(cert|cer|crt|pem)$/i,
      /^exception_/i,
    ];
    const extraFiles = files.filter(f => {
      const bn = f.split('/').pop();
      return !allowedPatterns.some(p => p.test(bn));
    });
    results.push(extraFiles.length === 0
      ? Utils.pass('EXC_NO_EXTRA_FILES', 'Keine unbekannten Extra-Dateien', CAT,
          'Alle Dateien im TAR haben bekannte Typen.', '', 'BSI TR-03153-1 §12')
      : Utils.warn('EXC_NO_EXTRA_FILES', 'Keine unbekannten Extra-Dateien', CAT,
          `${extraFiles.length} Dateien mit unbekanntem Typ:\n${extraFiles.join('\n')}`, '', 'BSI TR-03153-1 §12'));

    return results;
  }
  return { run, CAT };
})();
