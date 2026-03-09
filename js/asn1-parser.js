// ─── asn1-parser.js – Basic ASN.1 DER / BER parser ──────────────────────
'use strict';

const ASN1 = (() => {

  // ── Low-level DER reading ──────────────────────────────────────────────

  function readLength(buf, off) {
    const first = buf[off];
    if (first === 0x80) return { length: -1, nextOffset: off + 1 }; // indefinite
    if (first < 0x80) return { length: first, nextOffset: off + 1 };
    const numBytes = first & 0x7f;
    let len = 0;
    for (let i = 0; i < numBytes; i++) len = (len << 8) | buf[off + 1 + i];
    return { length: len, nextOffset: off + 1 + numBytes };
  }

  function readTLV(buf, off) {
    if (off >= buf.length) return null;
    const tag = buf[off];
    const { length, nextOffset } = readLength(buf, off + 1);
    const isIndefinite = length === -1;
    const valueStart = nextOffset;
    let valueEnd;
    if (isIndefinite) {
      // find 0x00 0x00 terminator
      let p = valueStart;
      while (p < buf.length - 1 && !(buf[p] === 0 && buf[p+1] === 0)) p++;
      valueEnd = p;
    } else {
      valueEnd = valueStart + length;
    }
    const value = buf.slice(valueStart, valueEnd);
    const totalLen = (isIndefinite ? valueEnd + 2 : valueEnd) - off;
    return { tag, length: isIndefinite ? -1 : length, isIndefinite, valueStart, valueEnd, value, offset: off, totalLen };
  }

  function parseChildren(buf, start, end) {
    const children = [];
    let off = start;
    while (off < end) {
      const tlv = readTLV(buf, off);
      if (!tlv) break;
      children.push(tlv);
      off += tlv.totalLen;
      if (off <= tlv.offset) break; // safety
    }
    return children;
  }

  function readOID(bytes) {
    const parts = [];
    const first = bytes[0];
    parts.push(Math.floor(first / 40));
    parts.push(first % 40);
    let val = 0;
    for (let i = 1; i < bytes.length; i++) {
      val = (val << 7) | (bytes[i] & 0x7f);
      if (!(bytes[i] & 0x80)) { parts.push(val); val = 0; }
    }
    return parts.join('.');
  }

  function readInteger(bytes) {
    if (bytes.length === 0) return 0;
    let val = bytes[0] & 0x80 ? -1 : 0;
    for (const b of bytes) val = (val * 256) + b;
    return val;
  }

  function readBigInt(bytes) {
    let hex = '';
    for (const b of bytes) hex += b.toString(16).padStart(2,'0');
    return hex;
  }

  function readUTF8(bytes) {
    try { return new TextDecoder('utf-8').decode(bytes); } catch { return ''; }
  }

  function readPrintable(bytes) {
    try { return new TextDecoder('ascii').decode(bytes); } catch { return ''; }
  }

  function readGeneralizedTime(bytes) {
    const s = readPrintable(bytes);
    // YYYYMMDDHHMMSSZ or similar
    if (s.length >= 14) {
      return new Date(`${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}T${s.slice(8,10)}:${s.slice(10,12)}:${s.slice(12,14)}Z`);
    }
    return null;
  }

  function readUTCTime(bytes) {
    const s = readPrintable(bytes);
    // YYMMDDHHMMSSZ
    if (s.length >= 13) {
      const yr = parseInt(s.slice(0,2),10);
      const year = yr >= 50 ? 1900 + yr : 2000 + yr;
      return new Date(`${year}-${s.slice(2,4)}-${s.slice(4,6)}T${s.slice(6,8)}:${s.slice(8,10)}:${s.slice(10,12)}Z`);
    }
    return null;
  }

  // ── TSE Log Message Parsing ────────────────────────────────────────────

  const LOG_OID_TXN    = '0.4.0.127.0.7.3.7.1.1';
  const LOG_OID_SYS    = '0.4.0.127.0.7.3.7.1.2';
  const LOG_OID_AUDIT  = '0.4.0.127.0.7.3.7.1.3';

  const SIG_OID_SHA256 = '0.4.0.127.0.7.1.1.4.1.3';
  const SIG_OID_SHA384 = '0.4.0.127.0.7.1.1.4.1.4';

  function parseLogMessage(data) {
    // TSE LogMessage is a SEQUENCE with:
    // [0] version INTEGER
    // [1] certifiedDataType OID
    // [2] certifiedData (choice by type)
    // [3] serialNumber OCTET STRING
    // [4] signatureAlgorithm OID
    // [5] seAuditData / processData / eventData (context-specific)
    // signatureCounter [context tag]
    // signatureCreationTime [context tag]
    // signatureValue [context tag]

    const result = {
      raw: data,
      version: null,
      certifiedDataType: null,
      logType: null, // 'txn' | 'sys' | 'audit' | 'unknown'
      serialNumber: null,
      signatureAlgorithm: null,
      signatureCounter: null,
      signatureCreationTime: null,
      signatureValue: null,
      // TransactionLog fields
      operationType: null,
      clientId: null,
      processData: null,
      processType: null,
      additionalExternalData: null,
      additionalInternalData: null,
      transactionNumber: null,
      // SystemLog fields
      eventType: null,
      eventOrigin: null,
      eventTriggeredByUser: null,
      eventData: null,
      // AuditLog fields
      seAuditData: null,
      parseError: null,
      hasIndefiniteLengthOutsideProcessData: false,
      indefiniteLengthUsed: false,
    };

    try {
      const outerTlv = readTLV(data, 0);
      if (!outerTlv || outerTlv.tag !== 0x30) {
        result.parseError = 'Kein SEQUENCE-Tag an Position 0 (gefunden: 0x' + (outerTlv ? outerTlv.tag.toString(16) : 'EOF') + ')';
        return result;
      }

      const fields = parseChildren(data, outerTlv.valueStart, outerTlv.valueEnd);

      for (const f of fields) {
        const tag = f.tag;

        if (tag === 0x02) { // INTEGER – version
          if (result.version === null) result.version = readInteger(f.value);
          else if (result.signatureCounter === null) result.signatureCounter = readInteger(f.value);
        }
        else if (tag === 0x06) { // OID
          const oid = readOID(f.value);
          if (result.certifiedDataType === null) {
            result.certifiedDataType = oid;
            if (oid === LOG_OID_TXN) result.logType = 'txn';
            else if (oid === LOG_OID_SYS) result.logType = 'sys';
            else if (oid === LOG_OID_AUDIT) result.logType = 'audit';
            else result.logType = 'unknown';
          } else if (result.signatureAlgorithm === null) {
            result.signatureAlgorithm = oid;
          }
        }
        else if (tag === 0x04) { // OCTET STRING – serialNumber or signatureValue
          if (result.serialNumber === null) result.serialNumber = f.value;
          else if (result.signatureValue === null) result.signatureValue = f.value;
        }
        // Context-specific tags for TransactionLog certified data
        else if (tag === 0xa0 || tag === 0x80) { // [0] IMPLICIT or EXPLICIT – operationType
          if (result.logType === 'txn' && result.operationType === null)
            result.operationType = readPrintable(f.value);
        }
        else if (tag === 0xa1 || tag === 0x81) { // [1] – clientId
          if (result.logType === 'txn' && result.clientId === null)
            result.clientId = readPrintable(f.value);
        }
        else if (tag === 0xa2 || tag === 0x82) { // [2] – processData
          if (result.logType === 'txn') {
            if (tag === 0xa2) { result.indefiniteLengthUsed = f.isIndefinite; }
            result.processData = f.value;
          }
        }
        else if (tag === 0xa3 || tag === 0x83) { // [3] – processType
          if (result.logType === 'txn' && result.processType === null)
            result.processType = readPrintable(f.value);
        }
        else if (tag === 0xa4 || tag === 0x84) { // [4] – additionalExternalData / eventData
          if (result.logType === 'txn') {
            if (result.additionalExternalData === null) result.additionalExternalData = f.value;
          } else if (result.logType === 'sys') {
            result.eventData = f.value;
          }
        }
        else if (tag === 0xa5 || tag === 0x85) { // [5] – transactionNumber / additionalInternalData for TXN
          if (result.logType === 'txn') {
            if (result.transactionNumber === null) result.transactionNumber = readInteger(f.value);
            else result.additionalInternalData = f.value;
          }
        }
        else if (tag === 0xa6 || tag === 0x86) { // [6] – additionalInternalData
          if (result.logType === 'txn' && result.additionalInternalData === null)
            result.additionalInternalData = f.value;
        }
        // SystemLog specific
        else if (tag === 0x0c || tag === 0x13 || tag === 0x1a || tag === 0x16) {
          // UTF8String, PrintableString, VisibleString, IA5String
          const str = readUTF8(f.value);
          if (result.logType === 'sys') {
            if (result.eventType === null) result.eventType = str;
            else if (result.eventOrigin === null) result.eventOrigin = str;
            else if (result.eventTriggeredByUser === null) result.eventTriggeredByUser = str;
          }
        }
        // signatureCreationTime – INTEGER after signatureCounter
        else if (tag === 0x02 && result.signatureCounter !== null && result.signatureCreationTime === null) {
          result.signatureCreationTime = readInteger(f.value);
        }
      }

      // Second pass for sys/audit if first pass didn't get event fields
      // Try to find context-tagged strings for SystemLog
      if (result.logType === 'sys') {
        for (const f of fields) {
          if ((f.tag & 0xe0) === 0x80 && (f.tag & 0x1f) <= 10) {
            const str = readUTF8(f.value) || readPrintable(f.value);
            if (str && result.eventType === null) result.eventType = str;
            else if (str && result.eventOrigin === null) result.eventOrigin = str;
            else if (str && result.eventTriggeredByUser === null) result.eventTriggeredByUser = str;
          }
        }
      }

      if (result.logType === 'audit') {
        for (const f of fields) {
          if (f.tag === 0x04 && result.seAuditData === null && result.serialNumber !== null) {
            result.seAuditData = f.value;
          }
        }
      }

      // Find signatureCounter and signatureCreationTime more reliably
      // They appear as tagged INTEGERs after the certified data
      let foundSerial = false;
      let foundSigAlg = false;
      for (const f of fields) {
        if (f.tag === 0x04) { if (!foundSerial) foundSerial = true; }
        if (f.tag === 0x06) { if (foundSerial) foundSigAlg = true; }
        if (f.tag === 0x02 && foundSerial && foundSigAlg) {
          if (result.signatureCounter === null) result.signatureCounter = readInteger(f.value);
          else if (result.signatureCreationTime === null) result.signatureCreationTime = readInteger(f.value);
        }
      }

    } catch(e) {
      result.parseError = 'Parsing-Fehler: ' + e.message;
    }

    return result;
  }

  // ── X.509 Certificate Parsing ─────────────────────────────────────────

  const OID_NAMES = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '2.5.29.14': 'SKI', '2.5.29.15': 'KeyUsage', '2.5.29.17': 'SAN',
    '2.5.29.19': 'BasicConstraints', '2.5.29.31': 'CRL', '2.5.29.32': 'CertPolicy',
    '2.5.29.35': 'AKI', '1.3.6.1.5.5.7.1.3': 'PrivKeyUsagePeriod',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.2.1': 'EC Public Key',
    '1.3.132.0.34': 'secp384r1 (P-384)', '1.2.840.10045.3.1.7': 'secp256r1 (P-256)',
    '0.4.0.127.0.7.3.7.2.1': 'BSI-TSE-OID (CSP)',
    '0.4.0.127.0.7.3.7.2.2': 'BSI-TSE-OID (Storage)',
    '0.4.0.127.0.7.3.7.2.3': 'BSI-TSE-OID (SecureElement)',
  };

  const BSI_TSE_OID_PREFIX = '0.4.0.127.0.7.3.7.2.';

  function parseCertificate(data) {
    const cert = {
      raw: data,
      version: null,
      serialNumber: null,
      signatureAlgorithm: null,
      issuerDN: {},
      subjectDN: {},
      notBefore: null,
      notAfter: null,
      publicKeyOID: null,
      publicKeyCurve: null,
      publicKeyBytes: null,
      extensions: {},
      isCA: null,
      pathLenConstraint: null,
      keyUsage: null,
      skiValue: null,
      akiValue: null,
      crlDP: null,
      bsiTseOID: null,
      subjectCN: null,
      parseError: null,
    };

    try {
      const outer = readTLV(data, 0);
      if (!outer || outer.tag !== 0x30) { cert.parseError = 'Kein SEQUENCE'; return cert; }
      // Certificate = SEQUENCE { TBSCertificate, signatureAlgorithm, signatureValue }
      const certFields = parseChildren(data, outer.valueStart, outer.valueEnd);
      if (certFields.length < 1) { cert.parseError = 'Leer'; return cert; }

      const tbs = certFields[0];
      if (tbs.tag !== 0x30) { cert.parseError = 'TBS ist kein SEQUENCE'; return cert; }
      const tbsFields = parseChildren(data, tbs.valueStart, tbs.valueEnd);

      let fi = 0;
      // [0] EXPLICIT version (optional)
      if (tbsFields[fi] && tbsFields[fi].tag === 0xa0) {
        const vBytes = parseChildren(data, tbsFields[fi].valueStart, tbsFields[fi].valueEnd);
        if (vBytes.length > 0) cert.version = readInteger(vBytes[0].value) + 1;
        fi++;
      }
      // serialNumber INTEGER
      if (tbsFields[fi] && tbsFields[fi].tag === 0x02) {
        cert.serialNumber = readBigInt(tbsFields[fi].value);
        fi++;
      }
      // signatureAlgorithm
      if (tbsFields[fi] && tbsFields[fi].tag === 0x30) {
        const algFields = parseChildren(data, tbsFields[fi].valueStart, tbsFields[fi].valueEnd);
        if (algFields.length > 0 && algFields[0].tag === 0x06)
          cert.signatureAlgorithm = readOID(algFields[0].value);
        fi++;
      }
      // issuer Name
      if (tbsFields[fi] && tbsFields[fi].tag === 0x30) {
        cert.issuerDN = parseDN(data, tbsFields[fi].valueStart, tbsFields[fi].valueEnd);
        fi++;
      }
      // validity Validity
      if (tbsFields[fi] && tbsFields[fi].tag === 0x30) {
        const valFields = parseChildren(data, tbsFields[fi].valueStart, tbsFields[fi].valueEnd);
        if (valFields.length >= 2) {
          cert.notBefore = parseTime(valFields[0]);
          cert.notAfter  = parseTime(valFields[1]);
        }
        fi++;
      }
      // subject Name
      if (tbsFields[fi] && tbsFields[fi].tag === 0x30) {
        cert.subjectDN = parseDN(data, tbsFields[fi].valueStart, tbsFields[fi].valueEnd);
        cert.subjectCN = cert.subjectDN['CN'] || null;
        fi++;
      }
      // subjectPublicKeyInfo
      if (tbsFields[fi] && tbsFields[fi].tag === 0x30) {
        const pkFields = parseChildren(data, tbsFields[fi].valueStart, tbsFields[fi].valueEnd);
        if (pkFields.length >= 1 && pkFields[0].tag === 0x30) {
          const algOIDs = parseChildren(data, pkFields[0].valueStart, pkFields[0].valueEnd);
          if (algOIDs.length > 0 && algOIDs[0].tag === 0x06) cert.publicKeyOID = readOID(algOIDs[0].value);
          if (algOIDs.length > 1 && algOIDs[1].tag === 0x06) cert.publicKeyCurve = readOID(algOIDs[1].value);
        }
        if (pkFields.length >= 2 && pkFields[1].tag === 0x03) cert.publicKeyBytes = pkFields[1].value;
        fi++;
      }
      // [3] EXPLICIT extensions
      for (let j = fi; j < tbsFields.length; j++) {
        if (tbsFields[j].tag === 0xa3) {
          parseExtensions(cert, data, tbsFields[j].valueStart, tbsFields[j].valueEnd);
        }
      }
    } catch(e) {
      cert.parseError = 'Parsing-Fehler: ' + e.message;
    }
    return cert;
  }

  function parseDN(buf, start, end) {
    const dn = {};
    const rdns = parseChildren(buf, start, end);
    for (const rdn of rdns) {
      const attrSets = parseChildren(buf, rdn.valueStart, rdn.valueEnd);
      for (const attrSet of attrSets) {
        const attrs = parseChildren(buf, attrSet.valueStart, attrSet.valueEnd);
        if (attrs.length >= 2 && attrs[0].tag === 0x06) {
          const oid = readOID(attrs[0].value);
          const name = OID_NAMES[oid] || oid;
          dn[name] = readUTF8(attrs[1].value) || readPrintable(attrs[1].value);
        }
      }
    }
    return dn;
  }

  function parseTime(tlv) {
    if (tlv.tag === 0x17) return readUTCTime(tlv.value);
    if (tlv.tag === 0x18) return readGeneralizedTime(tlv.value);
    return null;
  }

  function parseExtensions(cert, buf, start, end) {
    const extSeq = parseChildren(buf, start, end);
    if (extSeq.length === 0) return;
    const exts = parseChildren(buf, extSeq[0].valueStart, extSeq[0].valueEnd);
    for (const ext of exts) {
      const extFields = parseChildren(buf, ext.valueStart, ext.valueEnd);
      if (extFields.length === 0 || extFields[0].tag !== 0x06) continue;
      const oid = readOID(extFields[0].value);
      const isCritical = extFields.length > 1 && extFields[1].tag === 0x01 && extFields[1].value[0] === 0xff;
      const valueField = extFields[extFields.length - 1];
      // The extension value is wrapped in an OCTET STRING
      let extValue = valueField.value;
      if (valueField.tag === 0x04) {
        // parse inner DER
        try {
          const inner = readTLV(extValue, 0);
          if (inner) extValue = inner;
        } catch {}
      }

      if (oid === '2.5.29.19') { // BasicConstraints
        const bc = (extValue && extValue.value) ? parseChildren(buf, 0, 0) : null;
        // extValue.value for the SEQUENCE content
        try {
          const bcSeq = extValue.value ? parseChildren(extValue.value, 0, extValue.value.length) :
            (extValue.tag === 0x30 ? parseChildren(buf, extValue.valueStart, extValue.valueEnd) : []);
          const caFlag = bcSeq.find(f => f.tag === 0x01);
          cert.isCA = caFlag ? caFlag.value[0] === 0xff : false;
          const pathLen = bcSeq.find(f => f.tag === 0x02);
          if (pathLen) cert.pathLenConstraint = readInteger(pathLen.value);
        } catch { cert.isCA = false; }
      }
      else if (oid === '2.5.29.15') { // KeyUsage
        try {
          const kuBits = extValue.value ? extValue.value : (extValue.tag === 0x03 ? extValue.value : null);
          if (kuBits && kuBits.length >= 2) {
            const unusedBits = kuBits[0];
            cert.keyUsage = (kuBits[1] << 1) | (kuBits.length > 2 ? kuBits[2] >> 7 : 0);
          }
        } catch {}
      }
      else if (oid === '2.5.29.14') { // SKI
        try {
          const skiTlv = extValue.value ? readTLV(extValue.value, 0) : extValue;
          if (skiTlv && skiTlv.tag === 0x04) cert.skiValue = Utils.hexString(skiTlv.value);
          else cert.skiValue = Utils.hexString(extValue.value || extValue);
        } catch {}
      }
      else if (oid === '2.5.29.35') { // AKI
        try {
          const akiSeq = extValue.value ? readTLV(extValue.value, 0) : extValue;
          if (akiSeq && akiSeq.tag === 0x30) {
            const akiFields = parseChildren(akiSeq.value, 0, akiSeq.value.length);
            const ki = akiFields.find(f => f.tag === 0x80);
            if (ki) cert.akiValue = Utils.hexString(ki.value);
          }
        } catch {}
      }
      else if (oid === '2.5.29.31') { // CRL Distribution Point
        cert.crlDP = oid; // simplified: just mark presence
      }
      else if (oid === '2.5.29.32') { // Certificate Policies
        cert.certPolicy = oid;
      }
      else if (oid.startsWith(BSI_TSE_OID_PREFIX)) {
        cert.bsiTseOID = oid;
      }
      cert.extensions[oid] = { isCritical, rawValue: extValue };
    }
  }

  // ── Info.csv Parser ───────────────────────────────────────────────────

  function parseInfoCsv(text) {
    const lines = text.split(/\r?\n/).filter(l => l.trim());
    const components = [];
    let description = null;
    const unknownLines = [];

    for (const line of lines) {
      if (line.startsWith('component:')) {
        const rest = line.slice('component:'.length);
        const fields = {};
        for (const part of rest.split(',')) {
          const eqIdx = part.indexOf('=');
          if (eqIdx >= 0) {
            const k = part.slice(0, eqIdx).trim();
            const v = part.slice(eqIdx + 1).trim();
            fields[k] = v;
          }
        }
        components.push(fields);
      } else if (line.startsWith('description:')) {
        description = line.slice('description:'.length).trim();
      } else {
        unknownLines.push(line);
      }
    }

    return { components, description, unknownLines, rawLines: lines };
  }

  return {
    readTLV, parseChildren, readOID, readInteger, readBigInt,
    readUTF8, readPrintable, readGeneralizedTime, readUTCTime,
    parseLogMessage, parseCertificate, parseInfoCsv,
    LOG_OID_TXN, LOG_OID_SYS, LOG_OID_AUDIT,
    SIG_OID_SHA256, SIG_OID_SHA384,
    OID_NAMES, BSI_TSE_OID_PREFIX,
  };
})();
