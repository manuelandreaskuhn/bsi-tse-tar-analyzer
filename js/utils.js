// ─── utils.js – Shared utility functions ───────────────────────────────────
'use strict';

const Utils = (() => {

  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  }

  function formatDate(d) {
    if (!d || isNaN(d.getTime())) return 'ungültig';
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  }

  function unixToDate(ts) {
    return new Date(ts * 1000);
  }

  function hexString(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function readUint32BE(buf, off) {
    return ((buf[off] << 24) | (buf[off+1] << 16) | (buf[off+2] << 8) | buf[off+3]) >>> 0;
  }

  function readOctal(buf, off, len) {
    const s = readString(buf, off, len).trim().replace(/\0/g, '');
    return parseInt(s, 8) || 0;
  }

  function readString(buf, off, len) {
    let end = off + len;
    while (end > off && (buf[end-1] === 0 || buf[end-1] === 32)) end--;
    return new TextDecoder('latin1').decode(buf.slice(off, end));
  }

  function cloneTemplate(id) {
    const tpl = document.getElementById(id);
    if (!tpl) throw new Error('Template not found: ' + id);
    return tpl.content.cloneNode(true).firstElementChild;
  }

  function makeResult(id, name, cat, status, detail, ruleText, ref) {
    return { id, name, cat, status, detail, ruleText, ref: ref || '' };
  }

  function skip(id, name, cat, reason, ruleText, ref) {
    return makeResult(id, name, cat, 'SKIP', reason || 'Nicht anwendbar in diesem Kontext.', ruleText, ref);
  }

  function pass(id, name, cat, detail, ruleText, ref) {
    return makeResult(id, name, cat, 'PASS', detail || 'Prüfung bestanden.', ruleText, ref);
  }

  function fail(id, name, cat, detail, ruleText, ref) {
    return makeResult(id, name, cat, 'FAIL', detail || 'Prüfung fehlgeschlagen.', ruleText, ref);
  }

  function warn(id, name, cat, detail, ruleText, ref) {
    return makeResult(id, name, cat, 'WARN', detail || 'Warnung.', ruleText, ref);
  }

  function info(id, name, cat, detail, ruleText, ref) {
    return makeResult(id, name, cat, 'INFO', detail || 'Information.', ruleText, ref);
  }

  // Filename pattern helpers
  const LOG_TIME_PREFIX = /^(Gent|Utc|Unixt)_/;
  const LOG_SYS_PATTERN = /^(Gent|Utc|Unixt)_[^_]+_Sig-\d+_Log-Sys_[^.]+\.log$/;
  const LOG_AUD_PATTERN = /^(Gent|Utc|Unixt)_[^_]+_Sig-\d+_Log-Aud\.log$/;
  const LOG_TXN_PATTERN = /^(Gent|Utc|Unixt)_[^_]+_Sig-\d+_Log-Tra_No-\d+_(Start|Update|Finish)_Client-[^_]+(_Fc-\d+)?\.log$/;
  const CERT_PATTERN    = /^[0-9a-fA-F]+_X509\.(cer|crt|der|pem)$/;
  const CERT_EXTENSIONS = ['.cer', '.crt', '.der', '.pem'];

  function classifyFile(name) {
    const lower = name.toLowerCase();
    if (lower === 'info.csv') return 'info.csv';
    if (lower.endsWith('.log')) {
      if (LOG_SYS_PATTERN.test(name)) return 'syslog';
      if (LOG_AUD_PATTERN.test(name)) return 'auditlog';
      if (LOG_TXN_PATTERN.test(name)) return 'txnlog';
      return 'log-unknown';
    }
    for (const ext of CERT_EXTENSIONS) {
      if (lower.endsWith(ext)) return 'cert';
    }
    return 'unknown';
  }

  function getExtension(name) {
    const idx = name.lastIndexOf('.');
    return idx >= 0 ? name.slice(idx).toLowerCase() : '';
  }

  function parseSigCounterFromFilename(name) {
    const m = name.match(/_Sig-(\d+)_/);
    return m ? parseInt(m[1], 10) : null;
  }

  function parseTxnNumFromFilename(name) {
    const m = name.match(/_No-(\d+)_/);
    return m ? parseInt(m[1], 10) : null;
  }

  function parseClientFromFilename(name) {
    const m = name.match(/_(Start|Update|Finish)_Client-([^_]+?)(?:_Fc-\d+)?\.log$/i);
    return m ? m[2] : null;
  }

  function parseTxnTypeFromFilename(name) {
    const m = name.match(/_Log-Tra_No-\d+_(Start|Update|Finish)_/i);
    return m ? m[1] : null;
  }

  function parseTimePrefixFromFilename(name) {
    const m = name.match(/^(Gent|Utc|Unixt)_/);
    return m ? m[1] : null;
  }

  return {
    formatBytes, formatDate, unixToDate, hexString,
    readUint32BE, readOctal, readString,
    cloneTemplate, makeResult, skip, pass, fail, warn, info,
    LOG_TIME_PREFIX, LOG_SYS_PATTERN, LOG_AUD_PATTERN,
    LOG_TXN_PATTERN, CERT_PATTERN, CERT_EXTENSIONS,
    classifyFile, getExtension,
    parseSigCounterFromFilename, parseTxnNumFromFilename,
    parseClientFromFilename, parseTxnTypeFromFilename, parseTimePrefixFromFilename
  };
})();
