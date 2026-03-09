'use strict';
window.RulesCat32 = (function() {
  const CAT = 'Inline-Signatur (INLINE)';
  function run(ctx) {
    return [
      Utils.info('INLINE_PARSE','Inline-Signatur parsierbar',CAT,
        'Inline-Signaturen sind TSE-Signaturwerte, die direkt in Quittungsdaten eingebettet werden. Validierung erfordert Laufzeit-Kontext (Quittungsdaten).','','BSI TR-03151-1 §5.4'),
      Utils.info('INLINE_FIELDS','Pflichtfelder in Inline-Signatur',CAT,
        'Inline-Signatur muss signatureCounter, signatureCreationTime und signatureValue enthalten.','','BSI TR-03151-1 §5.4'),
      Utils.info('INLINE_MATCH_EXPORT','Inline-Signatur stimmt mit TAR-Log überein',CAT,
        'Vergleich Inline-Signatur vs. entsprechender finishTransaction-Log erfordert externes Quittungsdaten-Input.','','BSI TR-03151-1 §5.4'),
      Utils.info('INLINE_LAST','Inline-Signatur entspricht letztem finishTransaction',CAT,
        'Der signatureCounter der Inline-Signatur muss dem des finishTransaction-Logs entsprechen.','','BSI TR-03151-1 §5.4'),
    ];
  }
  return { run, CAT };
})();

