// ─── r09-syslog.js – SystemLog (SYS_EVT / SYSLOG / EVDATA) ──────────────
'use strict';

window.RulesCat09 = (function () {
  const CAT = 'SystemLog (SYS_EVT / SYSLOG / EVDATA_START / EVDATA_ENTER / EVDATA_UPDATE)';

  const VALID_ORIGINS = ['device', 'storage', 'integration-interface', 'CSP', 'SMA'];

  // SYSLOG_RULES matrix: eventType → { origin, triggerRequired }
  const SYSLOG_MATRIX = {
    'startAudit': { origins: ['device', 'SMA', 'CSP'], trigger: false },
    'enterSecureState': { origins: ['device', 'SMA', 'CSP'], trigger: false },
    'exitSecureState': { origins: ['device', 'SMA', 'CSP'], trigger: false },
    'selfTest': { origins: ['device', 'SMA', 'CSP', 'integration-interface'], trigger: null },
    'initialize': { origins: ['integration-interface'], trigger: false },
    'updateTime': { origins: ['integration-interface', 'CSP'], trigger: null },
    'setDescription': { origins: ['integration-interface'], trigger: true },
    'disableSecureElement': { origins: ['SMA', 'device'], trigger: false },
    'getDeviceHealth': { origins: ['SMA', 'CSP', 'device', 'integration-interface'], trigger: null },
    'authenticateUser': { origins: ['integration-interface'], trigger: true },
    'logOut': { origins: ['integration-interface', 'SMA', 'CSP'], trigger: null },
    'unblockUser': { origins: ['integration-interface'], trigger: true },
  };

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;

    if (archiveType === 'cert-export' || !parsedLogs || parsedLogs.length === 0) {
      for (const id of ['LOG_EVTYPE', 'LOG_ORIGIN', 'LOG_TRIGGER', 'LOG_EVDATA', 'SYSLOG_RULES',
        'SYS_EVT_STARTAUDIT_FIRST', 'SYS_EVT_SECURE_PAIRS', 'SYS_EVT_UPDATETIME_GAP',
        'SYS_EVT_LOGOUT_PRESENT', 'SYS_EVT_SELFTEST_PRESENT', 'EVDATA_STARTAUDIT',
        'EVDATA_EXITSECURE', 'EVDATA_ENTERSTATE_TIMEOFEVENT', 'EVDATA_AUTH_RESULT', 'EVDATA_AUTH_RETRIES']) {
        results.push(Utils.skip(id, id, CAT, 'Keine SystemLog-Dateien vorhanden.', '', 'BSI TR-03151-1'));
      }
      return results;
    }

    const sysLogs = parsedLogs.filter(l => !l.parseError && l.logType === 'sys');

    if (sysLogs.length === 0) {
      for (const id of ['LOG_EVTYPE', 'LOG_ORIGIN', 'LOG_TRIGGER', 'LOG_EVDATA', 'SYSLOG_RULES',
        'SYS_EVT_STARTAUDIT_FIRST', 'SYS_EVT_SECURE_PAIRS', 'SYS_EVT_UPDATETIME_GAP']) {
        results.push(Utils.skip(id, id, CAT, 'Keine SystemLog-Nachrichten im Archiv.', '', 'BSI TR-03151-1'));
      }
    } else {
      // LOG_EVTYPE
      const noEvType = sysLogs.filter(l => !l.eventType);
      results.push(noEvType.length === 0
        ? Utils.pass('LOG_EVTYPE', 'eventType vorhanden', CAT,
          `Alle ${sysLogs.length} SystemLogs haben eventType.`,
          'Das Feld `eventType` ist in der SystemLog-Nachricht ein Pflichtfeld.',
          'BSI TR-03151-1 SystemLogMessage §3')
        : Utils.fail('LOG_EVTYPE', 'eventType vorhanden', CAT,
          `${noEvType.length} SystemLogs ohne eventType:\n${noEvType.map(l => l._filename).join('\n')}`,
          'Das Feld `eventType` ist in der SystemLog-Nachricht ein Pflichtfeld.',
          'BSI TR-03151-1 SystemLogMessage §3'));

      // LOG_ORIGIN
      const badOrigin = sysLogs.filter(l => l.eventOrigin && !VALID_ORIGINS.includes(l.eventOrigin));
      results.push(badOrigin.length === 0
        ? Utils.pass('LOG_ORIGIN', 'eventOrigin gültiger TSE-Komponentenbezeichner', CAT,
          `Alle SystemLogs haben gültige eventOrigin-Werte.`,
          `Erlaubt: ${VALID_ORIGINS.join(', ')}`,
          'BSI TR-03151-1 SystemLogMessage §4')
        : Utils.warn('LOG_ORIGIN', 'eventOrigin gültiger TSE-Komponentenbezeichner', CAT,
          `${badOrigin.length} SystemLogs mit unbekanntem eventOrigin:\n${badOrigin.map(l => `  ${l._filename}: ${l.eventOrigin}`).join('\n')}`,
          `Erlaubt: ${VALID_ORIGINS.join(', ')}`,
          'BSI TR-03151-1 SystemLogMessage §4'));

      // LOG_TRIGGER
      const triggerMissing = [];  // trigger === true but field absent
      const triggerForbidden = []; // trigger === false but field present
      for (const log of sysLogs) {
        const rule = SYSLOG_MATRIX[log.eventType];
        if (!rule) continue;
        if (rule.trigger === true && !log.eventTriggeredByUser)
          triggerMissing.push(`${log._filename} (${log.eventType})`);
        if (rule.trigger === false && log.eventTriggeredByUser)
          triggerForbidden.push(`${log._filename} (${log.eventType})`);
      }
      {
        const violations = [...triggerMissing, ...triggerForbidden];
        const withTrigger = sysLogs.filter(l => l.eventTriggeredByUser).length;
        results.push(violations.length === 0
          ? Utils.pass('LOG_TRIGGER', 'eventTriggeredByUser', CAT,
            `eventTriggeredByUser korrekt gesetzt. ${withTrigger} von ${sysLogs.length} SystemLogs haben das Feld.`,
            'Das Feld `eventTriggeredByUser` ist typabhängig (MUSS/DARF NICHT/OPTIONAL) gemäß SYSLOG-Matrix.',
            'BSI TR-03151-1 SystemLogMessage §5')
          : Utils.fail('LOG_TRIGGER', 'eventTriggeredByUser', CAT,
            (triggerMissing.length > 0 ? `Fehlendes eventTriggeredByUser (MUSS vorhanden sein):\n${triggerMissing.join('\n')}\n` : '') +
            (triggerForbidden.length > 0 ? `Unerlaubtes eventTriggeredByUser (DARF NICHT vorhanden sein):\n${triggerForbidden.join('\n')}` : ''),
            'Das Feld `eventTriggeredByUser` ist typabhängig (MUSS/DARF NICHT/OPTIONAL) gemäß SYSLOG-Matrix.',
            'BSI TR-03151-1 SystemLogMessage §5'));
      }

      // LOG_EVDATA
      const noEvData = sysLogs.filter(l => l.eventData === null || l.eventData === undefined);
      results.push(noEvData.length === 0
        ? Utils.pass('LOG_EVDATA', 'eventData vorhanden', CAT,
          `Alle ${sysLogs.length} SystemLogs haben eventData.`,
          'Das Feld `eventData` ist in der SystemLog-Nachricht vorhanden.',
          'BSI TR-03151-1 SystemLogMessage §6')
        : Utils.info('LOG_EVDATA', 'eventData vorhanden', CAT,
          `${noEvData.length} SystemLogs ohne erkanntes eventData. (Feld kann leer sein für bestimmte eventTypes)`,
          'Das Feld `eventData` ist in der SystemLog-Nachricht vorhanden.',
          'BSI TR-03151-1 SystemLogMessage §6'));

      // SYSLOG_RULES – matrix check
      const matrixFails = [];
      for (const log of sysLogs) {
        const rule = SYSLOG_MATRIX[log.eventType];
        if (!rule) continue;
        if (log.eventOrigin && !rule.origins.includes(log.eventOrigin))
          matrixFails.push(`${log._filename}: eventType=${log.eventType}, unerlaubte Origin=${log.eventOrigin} (erlaubt: ${rule.origins.join(',')})`);
        if (rule.trigger === true && !log.eventTriggeredByUser)
          matrixFails.push(`${log._filename}: eventType=${log.eventType} erfordert eventTriggeredByUser`);
        if (rule.trigger === false && log.eventTriggeredByUser)
          matrixFails.push(`${log._filename}: eventType=${log.eventType} darf KEIN eventTriggeredByUser haben (gefunden: ${log.eventTriggeredByUser})`);
      }
      results.push(matrixFails.length === 0
        ? Utils.pass('SYSLOG_RULES', 'Erlaubte Origins und Trigger-Anforderungen je eventType', CAT,
          `SYSLOG-Matrix-Prüfung bestanden. ${sysLogs.length} SystemLogs geprüft.`,
          'Für jeden eventType sind bestimmte eventOrigin-Werte und eventTriggeredByUser-Anforderungen definiert.',
          'BSI TR-03153-1 §9.4')
        : Utils.fail('SYSLOG_RULES', 'Erlaubte Origins und Trigger-Anforderungen je eventType', CAT,
          `${matrixFails.length} Verstöße:\n${matrixFails.join('\n')}`,
          'Für jeden eventType sind bestimmte eventOrigin-Werte und eventTriggeredByUser-Anforderungen definiert.',
          'BSI TR-03153-1 §9.4'));

      // SYS_EVT_STARTAUDIT_FIRST
      const startAuditLogs = sysLogs.filter(l => l.eventType === 'startAudit');
      if (startAuditLogs.length > 0) {
        const allCounters = parsedLogs.filter(l => !l.parseError && l.signatureCounter !== null).map(l => l.signatureCounter);
        const minCtr = Math.min(...allCounters);
        const saMin = Math.min(...startAuditLogs.map(l => l.signatureCounter));
        results.push(saMin === minCtr
          ? Utils.pass('SYS_EVT_STARTAUDIT_FIRST', 'startAudit ist das erste Ereignis', CAT,
            `startAudit hat signatureCounter=${saMin} (Minimum aller Logs).`,
            'startAudit muss den kleinsten signatureCounter aller Log-Nachrichten im Archiv haben.',
            'BSI TR-03153-1 §9.7')
          : Utils.fail('SYS_EVT_STARTAUDIT_FIRST', 'startAudit ist das erste Ereignis', CAT,
            `startAudit-Counter=${saMin}, Minimum aller Logs=${minCtr}. startAudit ist nicht das erste Ereignis.`,
            'startAudit muss den kleinsten signatureCounter aller Log-Nachrichten im Archiv haben.',
            'BSI TR-03153-1 §9.7'));
      } else {
        results.push(Utils.info('SYS_EVT_STARTAUDIT_FIRST', 'startAudit ist das erste Ereignis', CAT,
          'Kein startAudit-Ereignis im Archiv (partieller Export?).', '', 'BSI TR-03153-1 §9.7'));
      }

      // SYS_EVT_SECURE_PAIRS – check pairing of enterSecureState/exitSecureState
      const enterStates = sysLogs.filter(l => l.eventType === 'enterSecureState');
      const exitStates = sysLogs.filter(l => l.eventType === 'exitSecureState');
      // Check sequencing: should alternate exit then enter (power loss pattern)
      const secureEvents = [...enterStates, ...exitStates].sort((a, b) => (a.signatureCounter || 0) - (b.signatureCounter || 0));
      let pairErrors = [];
      let inSecure = false;
      for (const ev of secureEvents) {
        if (ev.eventType === 'enterSecureState') {
          if (inSecure) pairErrors.push(`enterSecureState ohne vorheriges exitSecureState: ${ev._filename}`);
          inSecure = true;
        } else {
          if (!inSecure) pairErrors.push(`exitSecureState ohne vorheriges enterSecureState: ${ev._filename}`);
          inSecure = false;
        }
      }
      results.push(pairErrors.length === 0
        ? (enterStates.length === 0 && exitStates.length === 0
          ? Utils.info('SYS_EVT_SECURE_PAIRS', 'enterSecureState / exitSecureState paarweise', CAT,
            'Keine enterSecureState / exitSecureState Ereignisse im Archiv.', '', 'BSI TR-03153-1')
          : Utils.pass('SYS_EVT_SECURE_PAIRS', 'enterSecureState / exitSecureState paarweise', CAT,
            `${enterStates.length} enterSecureState, ${exitStates.length} exitSecureState – Sequenz korrekt.`, '', 'BSI TR-03153-1'))
        : Utils.warn('SYS_EVT_SECURE_PAIRS', 'enterSecureState / exitSecureState paarweise', CAT,
          `${pairErrors.length} Sequenzfehler:\n${pairErrors.join('\n')}`,
          'enterSecureState und exitSecureState müssen paarweise und in korrekter Reihenfolge vorkommen.', 'BSI TR-03153-1'));

      // SYS_EVT_UPDATETIME_GAP
      const updateTimeLogs = sysLogs.filter(l => l.eventType === 'updateTime' && l.signatureCreationTime);
      if (updateTimeLogs.length > 1) {
        const sorted = [...updateTimeLogs].sort((a, b) => a.signatureCounter - b.signatureCounter);
        const MAX_GAP = 48 * 3600; // 48h typical max
        const gaps = [];
        for (let i = 1; i < sorted.length; i++) {
          const gap = sorted[i].signatureCreationTime - sorted[i - 1].signatureCreationTime;
          if (gap > MAX_GAP) gaps.push(`Zwischen Sig-${sorted[i - 1].signatureCounter} und Sig-${sorted[i].signatureCounter}: ${Math.round(gap / 3600)}h`);
        }
        results.push(gaps.length === 0
          ? Utils.pass('SYS_EVT_UPDATETIME_GAP', 'Maximaler Zeitabstand zwischen updateTime-Ereignissen', CAT,
            `${updateTimeLogs.length} updateTime-Ereignisse geprüft. Kein Abstand > 48h.`,
            'Der maximale Zeitabstand zwischen aufeinanderfolgenden updateTime-Ereignissen.',
            'BSI TR-03153-1')
          : Utils.warn('SYS_EVT_UPDATETIME_GAP', 'Maximaler Zeitabstand zwischen updateTime-Ereignissen', CAT,
            `Große Zeitabstände zwischen updateTime-Ereignissen:\n${gaps.join('\n')}`,
            'Der maximale Zeitabstand zwischen aufeinanderfolgenden updateTime-Ereignissen.',
            'BSI TR-03153-1'));
      } else {
        results.push(Utils.info('SYS_EVT_UPDATETIME_GAP', 'Maximaler Zeitabstand zwischen updateTime-Ereignissen', CAT,
          `${updateTimeLogs.length} updateTime-Ereignis(se) vorhanden – Abstandsprüfung erfordert mindestens 2.`,
          '', 'BSI TR-03153-1'));
      }

      // SYS_EVT_LOGOUT_PRESENT – logout must be present when auth logs exist
      const logoutLogs = sysLogs.filter(l => l.eventType === 'logOut');
      const authLogsForLogout = sysLogs.filter(l => l.eventType === 'authenticateUser' || l.eventType === 'authenticate');
      results.push(logoutLogs.length > 0
        ? Utils.pass('SYS_EVT_LOGOUT_PRESENT', 'logOut-Ereignis im Archiv vorhanden', CAT,
          `${logoutLogs.length} logOut-Ereignis(se) gefunden.`,
          '', 'BSI TR-03153-1')
        : authLogsForLogout.length > 0
          ? Utils.warn('SYS_EVT_LOGOUT_PRESENT', 'logOut-Ereignis im Archiv vorhanden', CAT,
            `${authLogsForLogout.length} Authentifizierungs-Logs vorhanden, aber kein logOut-Ereignis gefunden.`,
            'Wenn Nutzer sich anmelden, muss auch ein logOut-SystemLog vorhanden sein.', 'BSI TR-03153-1')
          : Utils.info('SYS_EVT_LOGOUT_PRESENT', 'logOut-Ereignis im Archiv vorhanden', CAT,
            'Keine Authentifizierungs- oder logOut-Ereignisse im Archiv.', '', 'BSI TR-03153-1'));

      // SYS_EVT_SELFTEST_PRESENT – at least one selfTest should be present
      const selfTestLogs = sysLogs.filter(l => l.eventType === 'selfTest');
      results.push(selfTestLogs.length > 0
        ? Utils.pass('SYS_EVT_SELFTEST_PRESENT', 'selfTest-Ereignis im Archiv vorhanden', CAT,
          `${selfTestLogs.length} selfTest-Ereignis(se) gefunden.`,
          '', 'BSI TR-03153-1')
        : Utils.info('SYS_EVT_SELFTEST_PRESENT', 'selfTest-Ereignis im Archiv vorhanden', CAT,
          'Kein selfTest-Ereignis im Archiv. Erwartet wird mindestens ein selfTest-Log im Betriebslebenszyklus.',
          'selfTest-Ereignisse dokumentieren Selbsttests der TSE.', 'BSI TR-03153-1'));
    }

    // EVDATA_* checks
    const sysLogsAll = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'sys');

    // EVDATA_STARTAUDIT – eventData must be null or empty SEQUENCE (0x30 0x00)
    const startAuditLogsAll = sysLogsAll.filter(l => l.eventType === 'startAudit');
    if (startAuditLogsAll.length === 0) {
      results.push(Utils.skip('EVDATA_STARTAUDIT', 'eventData bei startAudit ist leere ASN.1-Sequenz', CAT,
        'Keine startAudit-Logs.', '', 'BSI TR-03151-1 §5.4'));
    } else {
      const notEmpty = startAuditLogsAll.filter(l => {
        if (!l.eventData || l.eventData.length === 0) return false;
        if (l.eventData.length === 2 && l.eventData[0] === 0x30 && l.eventData[1] === 0x00) return false;
        return true;
      });
      results.push(notEmpty.length === 0
        ? Utils.pass('EVDATA_STARTAUDIT', 'eventData bei startAudit ist leere ASN.1-Sequenz', CAT,
          `Alle ${startAuditLogsAll.length} startAudit-Logs: eventData korrekt leer oder leere SEQUENCE.`,
          'Bei startAudit-Ereignissen muss eventData eine leere ASN.1-SEQUENCE (0x30 0x00) sein.',
          'BSI TR-03151-1 §5.4')
        : Utils.fail('EVDATA_STARTAUDIT', 'eventData bei startAudit ist leere ASN.1-Sequenz', CAT,
          `${notEmpty.length} startAudit-Logs mit nicht-leerem eventData: ${notEmpty.map(l => l._filename).join(', ')}`,
          'eventData muss leer oder eine leere SEQUENCE (0x30 0x00) sein.',
          'BSI TR-03151-1 §5.4'));
    }

    // EVDATA_EXITSECURE – eventData must be null or empty SEQUENCE (0x30 0x00)
    const exitLogs = sysLogsAll.filter(l => l.eventType === 'exitSecureState');
    if (exitLogs.length === 0) {
      results.push(Utils.skip('EVDATA_EXITSECURE', 'eventData bei exitSecureState ist leere ASN.1-Sequenz', CAT,
        'Keine exitSecureState-Logs.', '', 'BSI TR-03151-1 §5.4'));
    } else {
      const notEmpty = exitLogs.filter(l => {
        if (!l.eventData || l.eventData.length === 0) return false;
        if (l.eventData.length === 2 && l.eventData[0] === 0x30 && l.eventData[1] === 0x00) return false;
        return true;
      });
      results.push(notEmpty.length === 0
        ? Utils.pass('EVDATA_EXITSECURE', 'eventData bei exitSecureState ist leere ASN.1-Sequenz', CAT,
          `Alle ${exitLogs.length} exitSecureState-Logs: eventData korrekt leer oder leere SEQUENCE.`,
          'Bei exitSecureState muss eventData leer oder eine leere SEQUENCE (0x30 0x00) sein.',
          'BSI TR-03151-1 §5.4')
        : Utils.fail('EVDATA_EXITSECURE', 'eventData bei exitSecureState ist leere ASN.1-Sequenz', CAT,
          `${notEmpty.length} exitSecureState-Logs mit nicht-leerem eventData: ${notEmpty.map(l => l._filename).join(', ')}`,
          'eventData muss leer oder eine leere SEQUENCE (0x30 0x00) sein.',
          'BSI TR-03151-1 §5.4'));
    }

    // EVDATA_ENTERSTATE_TIMEOFEVENT – timeOfEvent in enterSecureState eventData
    const enterLogs = sysLogsAll.filter(l => l.eventType === 'enterSecureState');
    if (enterLogs.length === 0) {
      results.push(Utils.skip('EVDATA_ENTERSTATE_TIMEOFEVENT', 'timeOfEvent in enterSecureState-Ereignissen', CAT,
        'Keine enterSecureState-Logs.', '', 'BSI TR-03151-1 §5.4'));
    } else {
      // EnterSecureStateEventData: SEQUENCE { timeOfEvent GeneralizedTime }
      // Try to parse eventData as ASN.1: SEQUENCE containing a GeneralizedTime
      const parseErrors = [];
      const noTimeField = [];
      for (const log of enterLogs) {
        if (!log.eventData || log.eventData.length < 4) { noTimeField.push(log._filename); continue; }
        try {
          const seq = ASN1.readTLV(log.eventData, 0);
          if (!seq || seq.tag !== 0x30) { noTimeField.push(log._filename); continue; }
          const inner = ASN1.readTLV(log.eventData, seq.start + seq.headerLen);
          // GeneralizedTime tag = 0x18, UTCTime = 0x17
          if (!inner || (inner.tag !== 0x18 && inner.tag !== 0x17)) {
            noTimeField.push(log._filename);
          }
        } catch (e) { parseErrors.push(log._filename); }
      }
      results.push(noTimeField.length === 0 && parseErrors.length === 0
        ? Utils.pass('EVDATA_ENTERSTATE_TIMEOFEVENT', 'timeOfEvent in enterSecureState-Ereignissen', CAT,
          `Alle ${enterLogs.length} enterSecureState-Logs: EnterSecureStateEventData mit timeOfEvent (GeneralizedTime/UTCTime) korrekt erkannt.`,
          'EnterSecureStateEventData muss timeOfEvent als GeneralizedTime oder UTCTime enthalten.', 'BSI TR-03151-1 §5.4')
        : noTimeField.length > 0
          ? Utils.fail('EVDATA_ENTERSTATE_TIMEOFEVENT', 'timeOfEvent in enterSecureState-Ereignissen', CAT,
            `${noTimeField.length} enterSecureState-Logs ohne erkennbares timeOfEvent-Feld: ${noTimeField.join(', ')}`,
            'EnterSecureStateEventData muss timeOfEvent enthalten.', 'BSI TR-03151-1 §5.4')
          : Utils.warn('EVDATA_ENTERSTATE_TIMEOFEVENT', 'timeOfEvent in enterSecureState-Ereignissen', CAT,
            `${parseErrors.length} enterSecureState-Logs mit ASN.1-Parse-Fehler: ${parseErrors.join(', ')}`,
            'EnterSecureStateEventData muss timeOfEvent enthalten.', 'BSI TR-03151-1 §5.4'));
    }
    // EVDATA_AUTH_RESULT – AuthenticationEventData: SEQUENCE { authenticationResult BOOLEAN, remainingRetries INTEGER OPTIONAL }
    const authLogs = sysLogsAll.filter(l => l.eventType === 'authenticateUser');
    if (authLogs.length === 0) {
      results.push(Utils.skip('EVDATA_AUTH_RESULT', 'authenticationResult bei Authentifizierungsereignissen', CAT,
        'Keine authenticateUser-Logs.', '', 'BSI TR-03151-1 §5.4'));
      results.push(Utils.skip('EVDATA_AUTH_RETRIES', 'remainingRetries bei fehlgeschlagener Authentifizierung', CAT,
        'Keine authenticateUser-Logs.', '', 'BSI TR-03151-1 §5.4'));
    } else {
      // Parse AuthenticationEventData from eventData for each log
      // Result: { ok: bool, authResult: bool|null, remainingRetries: int|null, filename }
      const parsed = authLogs.map(log => {
        // Support pre-parsed fields from the log parser
        if (log.authenticationResult !== undefined && log.authenticationResult !== null) {
          return { ok: true, authResult: !!log.authenticationResult, remainingRetries: log.remainingRetries ?? null, filename: log._filename };
        }
        if (!log.eventData || log.eventData.length < 5) {
          return { ok: false, authResult: null, remainingRetries: null, filename: log._filename };
        }
        try {
          const seq = ASN1.readTLV(log.eventData, 0);
          if (!seq || seq.tag !== 0x30) return { ok: false, authResult: null, remainingRetries: null, filename: log._filename };
          const boolTlv = ASN1.readTLV(log.eventData, seq.start + seq.headerLen);
          if (!boolTlv || boolTlv.tag !== 0x01) return { ok: false, authResult: null, remainingRetries: null, filename: log._filename };
          const authResult = log.eventData[boolTlv.start + boolTlv.headerLen] !== 0x00;
          let remainingRetries = null;
          const intOffset = boolTlv.start + boolTlv.headerLen + boolTlv.length;
          if (intOffset < log.eventData.length) {
            const intTlv = ASN1.readTLV(log.eventData, intOffset);
            if (intTlv && intTlv.tag === 0x02) {
              remainingRetries = 0;
              for (let i = 0; i < intTlv.length; i++) {
                remainingRetries = (remainingRetries << 8) | log.eventData[intTlv.start + intTlv.headerLen + i];
              }
            }
          }
          return { ok: true, authResult, remainingRetries, filename: log._filename };
        } catch (e) {
          return { ok: false, authResult: null, remainingRetries: null, filename: log._filename };
        }
      });

      const missingResult = parsed.filter(p => !p.ok);
      results.push(missingResult.length === 0
        ? Utils.pass('EVDATA_AUTH_RESULT', 'authenticationResult bei Authentifizierungsereignissen', CAT,
          `Alle ${authLogs.length} authenticateUser-Logs: authenticationResult korrekt geparst ` +
          `(${parsed.filter(p => p.authResult).length} erfolgreich, ${parsed.filter(p => p.ok && !p.authResult).length} fehlgeschlagen).`,
          'AuthenticationEventData muss authenticationResult (BOOLEAN) enthalten.', 'BSI TR-03151-1 §5.4')
        : Utils.fail('EVDATA_AUTH_RESULT', 'authenticationResult bei Authentifizierungsereignissen', CAT,
          `${missingResult.length} authenticateUser-Logs ohne erkennbares authenticationResult: ${missingResult.map(p => p.filename).join(', ')}`,
          'AuthenticationEventData muss authenticationResult (BOOLEAN) enthalten.', 'BSI TR-03151-1 §5.4'));

      // EVDATA_AUTH_RETRIES – failed auth must have remainingRetries
      const failedAuth = parsed.filter(p => p.ok && p.authResult === false);
      if (failedAuth.length === 0) {
        results.push(Utils.info('EVDATA_AUTH_RETRIES', 'remainingRetries bei fehlgeschlagener Authentifizierung', CAT,
          'Keine fehlgeschlagenen Authentifizierungen im Archiv – Prüfung nicht anwendbar.',
          'Bei fehlgeschlagener Authentifizierung muss remainingRetries vorhanden sein.', 'BSI TR-03151-1 §5.4'));
      } else {
        const missingRetries = failedAuth.filter(p => p.remainingRetries === null);
        results.push(missingRetries.length === 0
          ? Utils.pass('EVDATA_AUTH_RETRIES', 'remainingRetries bei fehlgeschlagener Authentifizierung', CAT,
            `Alle ${failedAuth.length} fehlgeschlagenen Authentifizierungen haben remainingRetries.`,
            'Bei fehlgeschlagener Authentifizierung muss remainingRetries vorhanden sein.', 'BSI TR-03151-1 §5.4')
          : Utils.fail('EVDATA_AUTH_RETRIES', 'remainingRetries bei fehlgeschlagener Authentifizierung', CAT,
            `${missingRetries.length} fehlgeschlagene Authentifizierungen ohne remainingRetries: ${missingRetries.map(p => p.filename).join(', ')}`,
            'Bei fehlgeschlagener Authentifizierung muss remainingRetries vorhanden und dekrementiert sein.', 'BSI TR-03151-1 §5.4'));
      }
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
