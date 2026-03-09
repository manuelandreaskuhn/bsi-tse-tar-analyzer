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
    if (data instanceof ArrayBuffer) data = new Uint8Array(data);
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

    // ── Post-processing: compute derived fields used by rule checks ──────
    _postProcessLog(result);
    return result;
  }

  const _LOG_SIG_NAMES = {
    '0.4.0.127.0.7.1.1.4.1.1': 'ecdsa-plain-SHA1',
    '0.4.0.127.0.7.1.1.4.1.2': 'ecdsa-plain-SHA224',
    '0.4.0.127.0.7.1.1.4.1.3': 'ecdsa-plain-SHA256',
    '0.4.0.127.0.7.1.1.4.1.4': 'ecdsa-plain-SHA384',
    '0.4.0.127.0.7.1.1.4.1.5': 'ecdsa-plain-SHA512',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  };

  function _tryDecode(bytes) {
    if (!bytes || bytes.length === 0) return '';
    try { return new TextDecoder('utf-8', {fatal: true}).decode(bytes); }
    catch(e) {
      // Latin-1 fallback
      try { return new TextDecoder('latin1').decode(bytes); } catch { return null; }
    }
  }

  function _postProcessLog(r) {
    // Aliases for v1 compatibility
    r.oid        = r.certifiedDataType;
    r.sigAlgOID  = r.signatureAlgorithm;
    r.sigAlgName = _LOG_SIG_NAMES[r.signatureAlgorithm] || r.signatureAlgorithm || '–';

    // logType as human-readable string
    if (r.logType === 'txn')   r.logType = 'TransactionLog';
    else if (r.logType === 'sys')   r.logType = 'SystemLog';
    else if (r.logType === 'audit') r.logType = 'AuditLog';

    // serialNumber as hex string
    if (r.serialNumber instanceof Uint8Array) {
      r.serialNumber = Utils.hexString(r.serialNumber);
    }

    // signatureValue derived
    if (r.signatureValue instanceof Uint8Array) {
      r.signatureValueLen = r.signatureValue.length;
      r.signatureValueHex = Utils.hexString(r.signatureValue);
    } else {
      r.signatureValueLen = null;
      r.signatureValueHex = null;
    }

    // processData derived
    if (r.processData instanceof Uint8Array) {
      r.processDataLen  = r.processData.length;
      r.processDataHex  = Utils.hexString(r.processData).slice(0, 64);
      r.processDataText = _tryDecode(r.processData);
      // Store original tag info if processData is indefinite
      r.processDataTag  = r.indefiniteLengthUsed ? 0xa2 : 0x82;
    } else {
      r.processDataLen = null;
    }

    // additionalExternalData derived
    if (r.additionalExternalData instanceof Uint8Array) {
      r.additionalExternalDataPresent = true;
      r.additionalExternalDataLen  = r.additionalExternalData.length;
      r.additionalExternalDataText = _tryDecode(r.additionalExternalData);
      r.additionalExternalDataHex  = Utils.hexString(r.additionalExternalData).slice(0, 48);
    } else {
      r.additionalExternalDataPresent = false;
      r.additionalExternalDataLen = 0;
    }

    // additionalInternalData derived
    if (r.additionalInternalData instanceof Uint8Array) {
      r.additionalInternalDataPresent = true;
      r.additionalInternalDataLen = r.additionalInternalData.length;
    } else {
      r.additionalInternalDataPresent = false;
      r.additionalInternalDataLen = 0;
    }

    // seAuditData derived
    if (r.seAuditData instanceof Uint8Array) {
      r.seAuditDataLen      = r.seAuditData.length;
      r.seAuditDataHex      = Utils.hexString(r.seAuditData).slice(0, 64);
      r.seAuditDataDecoded  = _tryDecode(r.seAuditData);
      // Check if it's an ASN.1 SEQUENCE
      r.seAuditDataIsASN1   = r.seAuditData.length > 1 && r.seAuditData[0] === 0x30;
    } else {
      r.seAuditDataLen = null;
    }

    // eventData derived
    if (r.eventData instanceof Uint8Array) {
      r.eventDataLen     = r.eventData.length;
      r.eventDataDecoded = _tryDecode(r.eventData);

      // Parse eventData children (SEQUENCE wrapper)
      if (r.eventData.length > 2 && r.eventData[0] === 0x30) {
        try {
          const hdrLen = 1 + (r.eventData[1] < 0x80 ? 1 : (r.eventData[1] & 0x7f) + 1);
          const kids = parseChildren(r.eventData, hdrLen, r.eventData.length);

          // Check for time value (updateTime: seTimeAfterUpdate)
          r.eventDataHasTimeValue = kids.some(k => k.tag === 0x18 || k.tag === 0x17 ||
            (k.tag & 0x80) === 0x80);

          // ENUMERATED authenticationResult (TR-03151-1 tag 0x0A)
          const AUTH_RESULT_NAMES = { 0:'success', 1:'unknownUserId', 2:'incorrectPin', 3:'pinBlocked' };
          const enumKids = kids.filter(k => k.tag === 0x0A);
          if (enumKids.length > 0) {
            let ev = 0;
            for (const b of (enumKids[0].value || [])) ev = ev * 256 + b;
            r.eventDataAuthResultEnum = ev;
            r.eventDataAuthResultStr  = AUTH_RESULT_NAMES[ev] || ('ENUM:' + ev);
            r.eventDataAuthResult     = ev === 0; // success
          }

          // BOOLEAN authenticationResult (legacy)
          const boolKids = kids.filter(k => k.tag === 0x01);
          if (boolKids.length > 0 && r.eventDataAuthResult === undefined) {
            r.eventDataAuthResult = (boolKids[0].value && boolKids[0].value[0] !== 0);
          }

          // INTEGER remainingRetries
          const intKids = kids.filter(k => k.tag === 0x02);
          if (intKids.length > 0) {
            let rv = 0;
            for (const b of (intKids[0].value || [])) rv = rv * 256 + b;
            r.eventDataRemainingRetries = rv;
          }

          // logOut: loggedOutUserId (UTF8String / PrintableString) + logOutCase (ENUMERATED)
          if (r.eventType === 'logOut') {
            const LOGOUT_CASE = { 0:'sessionTimeout', 1:'differentUserLoggedIn', 2:'userIdleTimeout', 3:'userLoggedOut' };
            const STR_TAGS = [0x0C, 0x13, 0x16, 0x1A, 0x1B];
            const strKids  = kids.filter(k => STR_TAGS.includes(k.tag));
            const enumLO   = kids.filter(k => k.tag === 0x0A);
            if (strKids.length > 0) {
              r.loggedOutUserId = new TextDecoder('utf-8', { fatal: false }).decode(strKids[0].value || new Uint8Array());
            }
            if (enumLO.length > 0) {
              let lv = 0;
              for (const b of (enumLO[0].value || [])) lv = lv * 256 + b;
              r.logOutCaseEnum = lv;
              r.logOutCaseStr  = LOGOUT_CASE[lv] || ('ENUM:' + lv);
            } else if (strKids.length > 1) {
              r.logOutCaseStr = new TextDecoder('utf-8', { fatal: false }).decode(strKids[1].value || new Uint8Array());
            }
          }

          // unblockUser: unblockedUserId
          if (r.eventType === 'unblockUser') {
            const STR_TAGS = [0x0C, 0x13, 0x16, 0x1A, 0x1B];
            const strKids2 = kids.filter(k => STR_TAGS.includes(k.tag));
            if (strKids2.length > 0) {
              r.unblockedUserId = new TextDecoder('utf-8', { fatal: false }).decode(strKids2[0].value || new Uint8Array());
            }
          }

        } catch (e) {
          r.eventDataHasTimeValue = false;
        }
      } else {
        r.eventDataHasTimeValue = false;
      }
    } else {
      r.eventDataLen = null;
      r.eventDataHasTimeValue = false;
    }

    // hasIndefiniteEncoding alias
    r.hasIndefiniteEncoding = r.indefiniteLengthUsed || r.hasIndefiniteLengthOutsideProcessData;
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
    if (data instanceof ArrayBuffer) data = new Uint8Array(data);
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
          // X.509 BIT STRING: byte[0]=unused bits, byte[1]=key usage flags
          // bit7(0x80)=digitalSignature, bit2(0x04)=keyCertSign, bit1(0x02)=cRLSign
          const kuRaw = extValue.value ? extValue.value : null;
          if (kuRaw && kuRaw.length >= 2) {
            cert.keyUsage = kuRaw[1]; // raw byte – do NOT shift
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
        try {
          // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
          const dpSeq = extValue.value ? readTLV(extValue.value, 0) : extValue;
          const dps = parseChildren(dpSeq.value || dpSeq.value, 0, (dpSeq.value || extValue.value || []).length);
          cert.crlDistPoints = [];
          for (const dp of dps) {
            // DistributionPoint [0] = distributionPointName
            const dpFields = parseChildren(dp.value, 0, dp.value.length);
            for (const dpf of dpFields) {
              if ((dpf.tag & 0xe0) === 0xa0) { // [0] context
                // fullName [0] SEQUENCE OF GeneralName
                const gnSeq = parseChildren(dpf.value, 0, dpf.value.length);
                for (const gn of gnSeq) {
                  if (gn.tag === 0x86) { // [6] uniformResourceIdentifier
                    cert.crlDistPoints.push(new TextDecoder().decode(gn.value));
                  }
                }
              }
            }
          }
          if (cert.crlDistPoints.length === 0) cert.crlDP = oid; // fallback
        } catch { cert.crlDP = oid; cert.crlDistPoints = []; }
      }
      else if (oid === '2.5.29.32') { // Certificate Policies
        try {
          const cpSeq = extValue.value ? readTLV(extValue.value, 0) : extValue;
          const pols  = parseChildren(cpSeq.value || extValue.value || [], 0,
                         (cpSeq.value || extValue.value || []).length);
          cert.certPolicies = [];
          for (const pol of pols) {
            const polFields = parseChildren(pol.value, 0, pol.value.length);
            if (polFields.length > 0 && polFields[0].tag === 0x06) {
              cert.certPolicies.push(readOID(polFields[0].value));
            }
          }
        } catch { cert.certPolicies = []; }
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
      // Parse quoted CSV: "key:","value","key:","value",...
      const fields = [];
      let cur = '', inQ = false;
      for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (c === '"') inQ = !inQ;
        else if (c === ',' && !inQ) { fields.push(cur); cur = ''; }
        else cur += c;
      }
      fields.push(cur);
      // Clean up each field: trim + remove any remaining outer quotes
      const cl = fields.map(f => f.trim().replace(/^[""]|[""]$/g, '').trim());

      if (cl[0] === 'component:') {
        // Fields: component:, <type>, key:, val, key:, val, ...
        const obj = { component: cl[1] || '', validComponent: false };
        for (let i = 2; i + 1 < cl.length; i += 2) {
          const k = cl[i].replace(/:$/, '');
          const v = cl[i + 1] || '';
          if (k) obj[k] = v;
        }
        obj.validComponent = ['device','storage','integration-interface','CSP','SMA'].includes(obj.component);
        components.push(obj);
      } else if (cl[0] === 'description:') {
        description = cl[1] || '';
      } else {
        unknownLines.push(line);
      }
    }

    return { components, description, unknownLines, raw: text };
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
