// ─── r03-info-csv.js – info.csv (EXP_INF) ────────────────────────────────
'use strict';

window.RulesCat03 = (function() {
  const CAT = 'info.csv (EXP_INF)';
  const VALID_COMPONENTS = ['device', 'storage', 'integration-interface', 'CSP', 'SMA'];
  const REQ_FIELDS = ['manufacturer', 'model', 'version', 'certification-id'];

  function run(ctx) {
    const results = [];
    const { tarResult } = ctx;

    // Find info.csv (case-insensitive search)
    let infoKey = null;
    for (const [k] of tarResult.files) {
      if (k.toLowerCase() === 'info.csv') { infoKey = k; break; }
    }

    // EXP_INF_01 – Datei info.csv vorhanden
    if (!infoKey) {
      results.push(Utils.fail('EXP_INF_01', 'Datei info.csv vorhanden', CAT,
        'Keine Datei info.csv im Archiv gefunden.',
        'Das Archiv muss genau eine Datei namens `info.csv` enthalten.',
        'BSI TR-03153-1 §6.4.2'));
      // Skip remaining checks
      for (const id of ['EXP_INF_01b', 'EXP_INF_02a', 'EXP_INF_02b', 'EXP_INF_02c', 'EXP_INF_05']) {
        results.push(Utils.skip(id, id + ' (info.csv fehlt)', CAT,
          'Nicht anwendbar: info.csv nicht vorhanden.', '', 'BSI TR-03153-1 §6.4.2'));
      }
      return results;
    }

    results.push(Utils.pass('EXP_INF_01', 'Datei info.csv vorhanden', CAT,
      `Datei "${infoKey}" gefunden (${Utils.formatBytes(tarResult.files.get(infoKey).size)}).`,
      'Das Archiv muss genau eine Datei namens `info.csv` enthalten.',
      'BSI TR-03153-1 §6.4.2'));

    // EXP_INF_01b – Dateiname info.csv (exakt)
    if (infoKey === 'info.csv') {
      results.push(Utils.pass('EXP_INF_01b', 'Dateiname info.csv (exakt)', CAT,
        'Dateiname lautet exakt "info.csv" (Kleinschreibung korrekt).',
        'Der Dateiname muss exakt `info.csv` lauten (Kleinschreibung).',
        'BSI TR-03153-1 §6.4.2'));
    } else {
      results.push(Utils.warn('EXP_INF_01b', 'Dateiname info.csv (exakt)', CAT,
        `Dateiname lautet "${infoKey}" – Abweichung von der exakten Schreibweise "info.csv".`,
        'Der Dateiname muss exakt `info.csv` lauten (Kleinschreibung).',
        'BSI TR-03153-1 §6.4.2'));
    }

    // Parse info.csv content
    const fileEntry = tarResult.files.get(infoKey);
    const rawText = new TextDecoder('utf-8').decode(fileEntry.data);
    const parsed = ASN1.parseInfoCsv(rawText);

    // EXP_INF_02a – Komponenten-Bezeichner
    if (parsed.components.length === 0) {
      results.push(Utils.fail('EXP_INF_02a', 'Komponenten-Bezeichner', CAT,
        'Keine component:-Zeilen in info.csv gefunden.',
        `Die info.csv muss mindestens eine \`component:\`-Zeile enthalten. Erlaubte Bezeichner: ${VALID_COMPONENTS.join(', ')}`,
        'BSI TR-03153-1 §5.2.4.1'));
    } else {
      const invalid = [];
      for (const comp of parsed.components) {
        const name = comp['component'] || Object.values(comp)[0];
        // component: type=device, ... – type field
        const typeVal = comp['type'] || comp['component'];
        if (typeVal && !VALID_COMPONENTS.includes(typeVal)) invalid.push(typeVal);
      }
      if (invalid.length > 0) {
        results.push(Utils.fail('EXP_INF_02a', 'Komponenten-Bezeichner', CAT,
          `Ungültige Komponenten-Bezeichner: ${invalid.join(', ')}\nErlaubt: ${VALID_COMPONENTS.join(', ')}`,
          `Die info.csv muss mindestens eine \`component:\`-Zeile enthalten. Erlaubte Bezeichner: ${VALID_COMPONENTS.join(', ')}`,
          'BSI TR-03153-1 §5.2.4.1'));
      } else {
        results.push(Utils.pass('EXP_INF_02a', 'Komponenten-Bezeichner', CAT,
          `${parsed.components.length} component:-Zeilen gefunden. Alle Bezeichner gültig.`,
          `Die info.csv muss mindestens eine \`component:\`-Zeile enthalten. Erlaubte Bezeichner: ${VALID_COMPONENTS.join(', ')}`,
          'BSI TR-03153-1 §5.2.4.1'));
      }
    }

    // EXP_INF_02b – Pflichtfelder in Komponentenzeilen
    const missingFields = [];
    for (let i = 0; i < parsed.components.length; i++) {
      const comp = parsed.components[i];
      const missing = REQ_FIELDS.filter(f => !(f in comp));
      if (missing.length > 0) missingFields.push(`Zeile ${i+1}: fehlt ${missing.join(', ')}`);
    }
    if (missingFields.length > 0) {
      results.push(Utils.warn('EXP_INF_02b', 'Pflichtfelder in Komponentenzeilen', CAT,
        `Fehlende Pflichtfelder:\n${missingFields.join('\n')}`,
        `Jede \`component:\`-Zeile muss die Felder ${REQ_FIELDS.join(', ')} enthalten.`,
        'BSI TR-03153-1 §6.4.2'));
    } else if (parsed.components.length > 0) {
      results.push(Utils.pass('EXP_INF_02b', 'Pflichtfelder in Komponentenzeilen', CAT,
        'Alle Pflichtfelder in allen component:-Zeilen vorhanden.',
        `Jede \`component:\`-Zeile muss die Felder ${REQ_FIELDS.join(', ')} enthalten.`,
        'BSI TR-03153-1 §6.4.2'));
    } else {
      results.push(Utils.skip('EXP_INF_02b', 'Pflichtfelder in Komponentenzeilen', CAT,
        'Keine component:-Zeilen vorhanden.', '', 'BSI TR-03153-1 §6.4.2'));
    }

    // EXP_INF_02c – Beschreibungszeile (description:)
    if (parsed.description !== null) {
      results.push(Utils.pass('EXP_INF_02c', 'Beschreibungszeile (description:)', CAT,
        `description:-Zeile vorhanden: "${parsed.description.slice(0, 100)}${parsed.description.length > 100 ? '…' : ''}"`,
        'Die info.csv sollte eine `description:`-Zeile enthalten.',
        'BSI TR-03153-1 §6.4.2'));
    } else {
      results.push(Utils.warn('EXP_INF_02c', 'Beschreibungszeile (description:)', CAT,
        'Keine description:-Zeile in info.csv gefunden.',
        'Die info.csv sollte eine `description:`-Zeile enthalten.',
        'BSI TR-03153-1 §6.4.2'));
    }

    // EXP_INF_05 – Keine unbekannten Zeilen
    if (parsed.unknownLines.length > 0) {
      results.push(Utils.warn('EXP_INF_05', 'Keine unbekannten Zeilen', CAT,
        `${parsed.unknownLines.length} unbekannte Zeilen gefunden:\n${parsed.unknownLines.join('\n')}`,
        'Alle Zeilen der info.csv müssen als `component:` oder `description:` erkannt werden.',
        'BSI TR-03153-1 §6.4.2'));
    } else {
      results.push(Utils.pass('EXP_INF_05', 'Keine unbekannten Zeilen', CAT,
        'Alle Zeilen der info.csv erkannt (component: oder description:).',
        'Alle Zeilen der info.csv müssen als `component:` oder `description:` erkannt werden.',
        'BSI TR-03153-1 §6.4.2'));
    }

    return results;
  }

  return { run, CAT };
})();
