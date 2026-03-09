// ─── r09-syslog.js – SystemLog (SYS_EVT / SYSLOG / EVDATA) ──────────────
'use strict';

window.RulesCat09 = (function() {
  const CAT = 'SystemLog (SYS_EVT / SYSLOG / EVDATA_START / EVDATA_ENTER / EVDATA_UPDATE)';

  const VALID_ORIGINS = ['device', 'storage', 'integration-interface', 'CSP', 'SMA'];

  // SYSLOG_RULES matrix: eventType → { origin, triggerRequired }
  const SYSLOG_MATRIX = {
    'startAudit':              { origins: ['device','SMA','CSP'], trigger: false },
    'enterSecureState':        { origins: ['device','SMA','CSP'], trigger: false },
    'exitSecureState':         { origins: ['device','SMA','CSP'], trigger: false },
    'selfTest':                { origins: ['device','SMA','CSP','integration-interface'], trigger: null },
    'initialize':              { origins: ['integration-interface'], trigger: false },
    'updateTime':              { origins: ['integration-interface','CSP'], trigger: null },
    'setDescription':          { origins: ['integration-interface'], trigger: true },
    'disableSecureElement':    { origins: ['SMA','device'], trigger: false },
    'getDeviceHealth':         { origins: ['SMA','CSP','device','integration-interface'], trigger: null },
    'authenticateUser':        { origins: ['integration-interface'], trigger: true },
    'logOut':                  { origins: ['integration-interface','SMA','CSP'], trigger: null },
    'unblockUser':             { origins: ['integration-interface'], trigger: true },
  };

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;

    if (archiveType === 'cert-export' || !parsedLogs || parsedLogs.length === 0) {
      for (const id of ['LOG_EVTYPE','LOG_ORIGIN','LOG_TRIGGER','LOG_EVDATA','SYSLOG_RULES',
        'SYS_EVT_STARTAUDIT_FIRST','SYS_EVT_SECURE_PAIRS','SYS_EVT_UPDATETIME_GAP',
        'SYS_EVT_LOGOUT_PRESENT','SYS_EVT_SELFTEST_PRESENT','EVDATA_STARTAUDIT',
        'EVDATA_EXITSECURE','EVDATA_UPDATETIME','EVDATA_ENTERSTATE_TIMEOFEVENT','EVDATA_AUTH_RESULT','EVDATA_AUTH_RETRIES']) {
        results.push(Utils.skip(id, id, CAT, 'Keine SystemLog-Dateien vorhanden.', '', 'BSI TR-03151-1'));
      }
      return results;
    }

    const sysLogs = parsedLogs.filter(l => !l.parseError && l.logType === 'sys');

    if (sysLogs.length === 0) {
      for (const id of ['LOG_EVTYPE','LOG_ORIGIN','LOG_TRIGGER','LOG_EVDATA','SYSLOG_RULES',
        'SYS_EVT_STARTAUDIT_FIRST','SYS_EVT_SECURE_PAIRS','SYS_EVT_UPDATETIME_GAP']) {
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
            `${noEvType.length} SystemLogs ohne eventType:\n${noEvType.map(l=>l._filename).join('\n')}`,
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
            `${badOrigin.length} SystemLogs mit unbekanntem eventOrigin:\n${badOrigin.map(l=>`  ${l._filename}: ${l.eventOrigin}`).join('\n')}`,
            `Erlaubt: ${VALID_ORIGINS.join(', ')}`,
            'BSI TR-03151-1 SystemLogMessage §4'));

      // LOG_TRIGGER
      results.push(Utils.info('LOG_TRIGGER', 'eventTriggeredByUser', CAT,
        `eventTriggeredByUser-Statistik: ${sysLogs.filter(l=>l.eventTriggeredByUser).length} von ${sysLogs.length} SystemLogs haben eventTriggeredByUser.`,
        'Das Feld `eventTriggeredByUser` ist typabhängig (MUSS/DARF NICHT/OPTIONAL) gemäß SYSLOG_RULES.',
        'BSI TR-03151-1 SystemLogMessage §5'));

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
        const allCounters = parsedLogs.filter(l=>!l.parseError && l.signatureCounter!==null).map(l=>l.signatureCounter);
        const minCtr = Math.min(...allCounters);
        const saMin  = Math.min(...startAuditLogs.map(l=>l.signatureCounter));
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

      // SYS_EVT_SECURE_PAIRS
      const enterStates = sysLogs.filter(l => l.eventType === 'enterSecureState');
      const exitStates  = sysLogs.filter(l => l.eventType === 'exitSecureState');
      results.push(Utils.info('SYS_EVT_SECURE_PAIRS', 'enterSecureState und exitSecureState paarweise', CAT,
        `enterSecureState: ${enterStates.length}, exitSecureState: ${exitStates.length}.\n` +
        (enterStates.length !== exitStates.length ? 'HINWEIS: Unterschiedliche Anzahl – ggf. unvollständiger Export.' : 'Gleiche Anzahl vorhanden.'),
        'enterSecureState und exitSecureState müssen paarweise vorkommen (Ausnahme: partieller Export).',
        'BSI TR-03153-1'));

      // SYS_EVT_UPDATETIME_GAP
      const updateTimeLogs = sysLogs.filter(l => l.eventType === 'updateTime' && l.signatureCreationTime);
      if (updateTimeLogs.length > 1) {
        const sorted = [...updateTimeLogs].sort((a,b) => a.signatureCounter - b.signatureCounter);
        const MAX_GAP = 48 * 3600; // 48h typical max
        const gaps = [];
        for (let i = 1; i < sorted.length; i++) {
          const gap = sorted[i].signatureCreationTime - sorted[i-1].signatureCreationTime;
          if (gap > MAX_GAP) gaps.push(`Zwischen Sig-${sorted[i-1].signatureCounter} und Sig-${sorted[i].signatureCounter}: ${Math.round(gap/3600)}h`);
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

      // SYS_EVT_LOGOUT_PRESENT
      const logoutLogs = sysLogs.filter(l => l.eventType === 'logOut');
      results.push(Utils.info('SYS_EVT_LOGOUT_PRESENT', 'logOut-Ereignis im Archiv vorhanden', CAT,
        `${logoutLogs.length} logOut-Ereignis(se) im Archiv.`,
        'Wenn Nutzer sich abmelden, muss ein logOut-SystemLog vorhanden sein.',
        'BSI TR-03153-1'));

      // SYS_EVT_SELFTEST_PRESENT
      const selfTestLogs = sysLogs.filter(l => l.eventType === 'selfTest');
      results.push(Utils.info('SYS_EVT_SELFTEST_PRESENT', 'selfTest-Ereignis im Archiv vorhanden', CAT,
        `${selfTestLogs.length} selfTest-Ereignis(se) im Archiv.`,
        'selfTest-Ereignisse dokumentieren automatische oder externe Selbsttests.',
        'BSI TR-03153-1'));
    }

    // EVDATA_* checks
    const sysLogsAll = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'sys');

    results.push(Utils.info('EVDATA_STARTAUDIT', 'eventData bei startAudit ist leere ASN.1-Sequenz', CAT,
      'Prüfung der ASN.1-eventData-Struktur bei startAudit-Ereignissen.',
      'Bei startAudit-Ereignissen muss eventData eine leere ASN.1-SEQUENCE sein.',
      'BSI TR-03151-1 §5.4'));
    results.push(Utils.info('EVDATA_EXITSECURE', 'eventData bei exitSecureState ist leere ASN.1-Sequenz', CAT,
      'Prüfung der ASN.1-eventData-Struktur bei exitSecureState-Ereignissen.',
      'Bei exitSecureState-Ereignissen muss eventData eine leere ASN.1-SEQUENCE sein.',
      'BSI TR-03151-1 §5.4'));
    results.push(Utils.info('EVDATA_UPDATETIME', 'seTimeAfterUpdate in updateTime-Ereignissen', CAT,
      'Prüfung ob seTimeAfterUpdate in UpdateTimeEventData vorhanden ist.',
      'Bei updateTime-Ereignissen muss seTimeAfterUpdate in den eventData vorhanden sein.',
      'BSI TR-03151-1 §5.4'));
    results.push(Utils.info('EVDATA_ENTERSTATE_TIMEOFEVENT', 'timeOfEvent bei enterSecureState', CAT,
      'Prüfung ob timeOfEvent in EnterSecureStateEventData vorhanden ist.',
      'Bei enterSecureState-Ereignissen muss timeOfEvent in den eventData vorhanden sein.',
      'BSI TR-03151-1 §5.4'));
    results.push(Utils.info('EVDATA_AUTH_RESULT', 'authenticationResult bei Authentifizierungsereignissen', CAT,
      'authenticationResult-Felder in authenticateUser-Logs.',
      'AuthenticationEventData muss authenticationResult enthalten.',
      'BSI TR-03151-1 §5.4'));
    results.push(Utils.info('EVDATA_AUTH_RETRIES', 'remainingRetries bei fehlgeschlagener Authentifizierung', CAT,
      'remainingRetries-Felder in authenticateUser-Logs bei fehlgeschlagener Authentifizierung.',
      'Bei fehlgeschlagener Authentifizierung muss remainingRetries vorhanden und dekrementiert sein.',
      'BSI TR-03151-1 §5.4'));

    return results;
  }

  return { run, CAT };
})();
