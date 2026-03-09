// ─── r07-cert-chain.js – Zertifikatskette (CHAIN) ────────────────────────
'use strict';

window.RulesCat07 = (function() {
  const CAT = 'Zertifikatskette (CHAIN)';

  function run(ctx) {
    const results = [];
    const { parsedCerts } = ctx;

    if (!parsedCerts || parsedCerts.length === 0) {
      for (const id of ['CHAIN_COMPLETE','CHAIN_AKI_SKI','CHAIN_VALIDITY','CHAIN_ISSUER_MATCH']) {
        results.push(Utils.skip(id, id, CAT, 'Keine Zertifikate vorhanden.', '', 'BSI TR-03116-5 §10.2'));
      }
      return results;
    }

    const validCerts = parsedCerts.filter(c => !c.parseError);
    const caCerts   = validCerts.filter(c => c.isCA === true);
    const leafCerts = validCerts.filter(c => c.isCA === false);

    // CHAIN_COMPLETE
    const hasRoot = caCerts.some(c => {
      const s = JSON.stringify(c.subjectDN); const i = JSON.stringify(c.issuerDN);
      return s === i;
    });
    const hasLeaf = leafCerts.length > 0;
    if (hasRoot && hasLeaf) {
      results.push(Utils.pass('CHAIN_COMPLETE', 'Zertifikatskette vollständig', CAT,
        `Root-CA: ${caCerts.length} Zertifikat(e), Blatt-Zertifikate: ${leafCerts.length}.`,
        'Die Kette muss mindestens ein Root-CA-Zertifikat und ein TSE-Blatt-Zertifikat enthalten.',
        'BSI TR-03116-5 §10.2'));
    } else {
      results.push(Utils.warn('CHAIN_COMPLETE', 'Zertifikatskette vollständig', CAT,
        `Root-CA gefunden: ${hasRoot}, Blatt-Zertifikat gefunden: ${hasLeaf}. Kette unvollständig.`,
        'Die Kette muss mindestens ein Root-CA-Zertifikat und ein TSE-Blatt-Zertifikat enthalten.',
        'BSI TR-03116-5 §10.2'));
    }

    // CHAIN_AKI_SKI
    const akiSkiFails = [];
    for (const cert of validCerts) {
      if (cert.isCA === true && JSON.stringify(cert.subjectDN) === JSON.stringify(cert.issuerDN)) continue;
      if (!cert.akiValue) { akiSkiFails.push(`${cert._filename}: Kein AKI`); continue; }
      const issuer = validCerts.find(c => c.skiValue === cert.akiValue);
      if (!issuer) akiSkiFails.push(`${cert._filename}: AKI=${cert.akiValue} kein Aussteller mit diesem SKI`);
    }
    results.push(akiSkiFails.length === 0
      ? Utils.pass('CHAIN_AKI_SKI', 'AKI→SKI Verkettung', CAT,
          'Alle AKI→SKI-Verknüpfungen korrekt.',
          'Für jedes Nicht-Root-Zertifikat muss der AKI-Wert mit dem SKI des Ausstellers übereinstimmen.',
          'BSI TR-03116-5 §10.2.1')
      : Utils.warn('CHAIN_AKI_SKI', 'AKI→SKI Verkettung', CAT,
          `Fehlende/fehlerhafte Verknüpfungen:\n${akiSkiFails.join('\n')}`,
          'Für jedes Nicht-Root-Zertifikat muss der AKI-Wert mit dem SKI des Ausstellers übereinstimmen.',
          'BSI TR-03116-5 §10.2.1'));

    // CHAIN_VALIDITY
    const validityFails = [];
    for (const cert of validCerts) {
      if (!cert.akiValue) continue;
      const issuer = validCerts.find(c => c.skiValue === cert.akiValue);
      if (!issuer) continue;
      if (cert.notBefore && issuer.notBefore && cert.notBefore < issuer.notBefore)
        validityFails.push(`${cert._filename}: notBefore vor Aussteller-notBefore`);
      if (cert.notAfter && issuer.notAfter && cert.notAfter > issuer.notAfter)
        validityFails.push(`${cert._filename}: notAfter nach Aussteller-notAfter`);
    }
    results.push(validityFails.length === 0
      ? Utils.pass('CHAIN_VALIDITY', 'Kindsgültigkeit ≤ Ausstellergültigkeit', CAT,
          'Alle Gültigkeitszeiträume innerhalb des Ausstellers.',
          'Der Gültigkeitszeitraum eines Zertifikats darf den des Ausstellers nicht überschreiten.',
          'BSI TR-03116-5 §10.2.2')
      : Utils.warn('CHAIN_VALIDITY', 'Kindsgültigkeit ≤ Ausstellergültigkeit', CAT,
          validityFails.join('\n'),
          'Der Gültigkeitszeitraum eines Zertifikats darf den des Ausstellers nicht überschreiten.',
          'BSI TR-03116-5 §10.2.2'));

    // CHAIN_ISSUER_MATCH
    const issuerFails = [];
    for (const cert of validCerts) {
      if (!cert.akiValue) continue;
      const issuer = validCerts.find(c => c.skiValue === cert.akiValue);
      if (!issuer) continue;
      const issuerDN = JSON.stringify(issuer.subjectDN);
      const certIssuerDN = JSON.stringify(cert.issuerDN);
      if (issuerDN !== certIssuerDN)
        issuerFails.push(`${cert._filename}: Issuer DN stimmt nicht mit Subject DN des Ausstellers überein`);
    }
    results.push(issuerFails.length === 0
      ? Utils.pass('CHAIN_ISSUER_MATCH', 'Aussteller-Inhaber-Übereinstimmung', CAT,
          'Alle Issuer/Subject-DNs konsistent.',
          'Der Issuer-DN jedes Nicht-Root-Zertifikats muss mit dem Subject-DN seines direkten Ausstellers übereinstimmen.',
          'BSI TR-03116-5 §10.2.1')
      : Utils.warn('CHAIN_ISSUER_MATCH', 'Aussteller-Inhaber-Übereinstimmung', CAT,
          issuerFails.join('\n'),
          'Der Issuer-DN jedes Nicht-Root-Zertifikats muss mit dem Subject-DN seines direkten Ausstellers übereinstimmen.',
          'BSI TR-03116-5 §10.2.1'));

    return results;
  }

  return { run, CAT };
})();
