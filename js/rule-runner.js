// ─── rule-runner.js – Orchestriert alle 35 RulesKat-Module ───────────────
'use strict';

window.RuleRunner = (function() {

  const ALL_CATS = [
    window.RulesCat01, window.RulesCat02, window.RulesCat03, window.RulesCat04,
    window.RulesCat05, window.RulesCat06, window.RulesCat07, window.RulesCat08,
    window.RulesCat09, window.RulesCat10, window.RulesCat11, window.RulesCat12,
    window.RulesCat13, window.RulesCat14, window.RulesCat15, window.RulesCat16,
    window.RulesCat17, window.RulesCat18, window.RulesCat19, window.RulesCat20,
    window.RulesCat21, window.RulesCat22, window.RulesCat23, window.RulesCat24,
    window.RulesCat25, window.RulesCat26, window.RulesCat27, window.RulesCat28,
    window.RulesCat29, window.RulesCat30, window.RulesCat31, window.RulesCat32,
    window.RulesCat33, window.RulesCat34, window.RulesCat35,
  ];

  /**
   * Parse all log files from a tarResult
   * @param {TarResult} tarResult
   * @returns {Array} parsedLogs
   */
  function parseAllLogs(tarResult) {
    const logs = [];
    if (!tarResult) return logs;

    for (const [name, entry] of tarResult.files) {
      if (!name.endsWith('.log')) continue;
      const basename = name.split('/').pop();

      // Classify log type from filename
      const logType = Utils.classifyFile(basename);
      if (!logType) continue;

      try {
        const parsed = ASN1Parser.parseLogMessage(entry.data);
        parsed._filename = basename;
        parsed._path = name;
        parsed._size = entry.size;
        parsed.logType = logType;
        parsed.parseError = null;
        logs.push(parsed);
      } catch (e) {
        logs.push({
          _filename: basename,
          _path: name,
          _size: entry.size,
          logType,
          parseError: e.message || String(e),
        });
      }
    }

    return logs;
  }

  /**
   * Parse all certificate files from a tarResult
   * @param {TarResult} tarResult
   * @returns {Array} parsedCerts
   */
  function parseAllCerts(tarResult) {
    const certs = [];
    if (!tarResult) return certs;

    const CERT_EXTS = ['.cert', '.cer', '.crt', '.pem'];
    for (const [name, entry] of tarResult.files) {
      const bn = name.split('/').pop().toLowerCase();
      if (!CERT_EXTS.some(ext => bn.endsWith(ext))) continue;

      try {
        const parsed = ASN1Parser.parseCertificate(entry.data);
        parsed._filename = name.split('/').pop();
        parsed._path = name;
        parsed._size = entry.size;
        parsed.parseError = null;
        certs.push(parsed);
      } catch (e) {
        certs.push({
          _filename: name.split('/').pop(),
          _path: name,
          _size: entry.size,
          parseError: e.message || String(e),
        });
      }
    }

    return certs;
  }

  /**
   * Run all rule categories against the given archive
   * @param {Object} input  { tarResult, archiveName, archiveType }
   * @returns {Object}  { results, byCategory, stats, parsedLogs, parsedCerts }
   */
  function runAll(input) {
    const { tarResult, archiveName, archiveType } = input;

    // Parse logs & certs once
    const parsedLogs  = parseAllLogs(tarResult);
    const parsedCerts = parseAllCerts(tarResult);

    // Build the context object passed to every rule module
    const ctx = {
      tarResult,
      archiveName,
      archiveType,
      parsedLogs,
      parsedCerts,
    };

    // Collect all results
    const results = [];
    const byCategory = {};

    for (const mod of ALL_CATS) {
      if (!mod || typeof mod.run !== 'function') continue;
      let catResults;
      try {
        catResults = mod.run(ctx);
      } catch (e) {
        catResults = [{
          id: 'RUNNER_ERROR',
          name: `Fehler in Kategorie "${mod.CAT}"`,
          cat: mod.CAT || '?',
          status: 'WARN',
          detail: String(e),
          ruleText: '',
          ref: '',
        }];
      }
      if (!Array.isArray(catResults)) continue;
      byCategory[mod.CAT] = catResults;
      results.push(...catResults);
    }

    // Compute statistics
    const stats = {
      total:  results.length,
      pass:   results.filter(r => r.status === 'PASS').length,
      fail:   results.filter(r => r.status === 'FAIL').length,
      warn:   results.filter(r => r.status === 'WARN').length,
      info:   results.filter(r => r.status === 'INFO').length,
      skip:   results.filter(r => r.status === 'SKIP').length,
      logCount:  parsedLogs.length,
      certCount: parsedCerts.length,
      parseErrors: parsedLogs.filter(l => l.parseError).length,
    };

    // Overall verdict
    if (stats.fail > 0) stats.verdict = 'FAIL';
    else if (stats.warn > 0) stats.verdict = 'WARN';
    else if (stats.pass > 0) stats.verdict = 'PASS';
    else stats.verdict = 'INFO';

    return { results, byCategory, stats, parsedLogs, parsedCerts };
  }

  return { runAll };
})();
