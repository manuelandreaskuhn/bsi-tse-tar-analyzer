// ─── asn1-definitions.js  ─────────────────────────────────────────────────
// ASN.1-Felddefinitionen aus den BSI TR-03151-1 Funktions-XML-Dateien.
// Jede Definition beschreibt die LogMessage-Hülle (outerFields) und den
// eingebetteten certifiedData-Block (innerFields) mit optionalen EventData-
// Feldern. Wird vom ASN1Viewer verwendet, um die Datei-Detailansicht
// anzureichern.
'use strict';

window.ASN1Definitions = (() => {

  // ── Gemeinsame Outer-LogMessage-Felder ────────────────────────────────
  const OUTER_TXN = [
    { name: 'version',               type: 'INTEGER (3)',                    tag: null,          required: true,  desc: 'Version des Log-Nachricht-Formats. MUSS 3 sein.',                          origin: 'Gerät' },
    { name: 'certifiedDataType',     type: 'OBJECT IDENTIFIER',              tag: null,          required: true,  desc: 'MUSS auf OID id-SE-API-transaction-log gesetzt sein.',                     origin: 'Gerät' },
    { name: 'certifiedData',         type: 'TransactionLogMessage',          tag: null,          required: true,  desc: 'Eingebettete Transaktions-Log-Nachricht.',                                 origin: 'Gerät' },
    { name: 'serialNumber',          type: 'OCTET STRING (SIZE (32))',        tag: null,          required: true,  desc: 'Seriennummer des Secure Element (Hash des öffentlichen Schlüssels).',      origin: 'Gerät' },
    { name: 'signatureAlgorithm',    type: 'AlgorithmIdentifier',            tag: null,          required: true,  desc: 'Informationen über die Signaturerstellung.',                               origin: 'Gerät' },
    { name: 'seAuditData',           type: 'OCTET STRING',                   tag: '[0] IMPLICIT',required: false, desc: 'RFU – für zukünftige Verwendung reserviert.',                             origin: '–' },
    { name: 'signatureCounter',      type: 'INTEGER',                        tag: null,          required: true,  desc: 'Aktueller Signaturzähler des Secure Element.',                             origin: 'Secure Element' },
    { name: 'signatureCreationTime', type: 'Time',                           tag: null,          required: true,  desc: 'Zeitpunkt der Signatur im Secure Element.',                                origin: 'Secure Element' },
    { name: 'signatureValue',        type: 'OCTET STRING',                   tag: null,          required: true,  desc: 'Ergebnis der Signaturberechnung.',                                         origin: 'Secure Element' },
  ];

  const OUTER_SYS = [
    { name: 'version',               type: 'INTEGER (3)',                    tag: null,          required: true,  desc: 'Version des Log-Nachricht-Formats. MUSS 3 sein.',                          origin: 'Gerät' },
    { name: 'certifiedDataType',     type: 'OBJECT IDENTIFIER',              tag: null,          required: true,  desc: 'MUSS auf OID id-SE-API-system-log gesetzt sein.',                          origin: 'Gerät' },
    { name: 'certifiedData',         type: 'SystemLogMessage',               tag: null,          required: true,  desc: 'Eingebettete System-Log-Nachricht.',                                       origin: 'Gerät' },
    { name: 'serialNumber',          type: 'OCTET STRING (SIZE (32))',        tag: null,          required: true,  desc: 'Seriennummer des Secure Element (Hash des öffentlichen Schlüssels).',      origin: 'Gerät' },
    { name: 'signatureAlgorithm',    type: 'AlgorithmIdentifier',            tag: null,          required: true,  desc: 'Informationen über die Signaturerstellung.',                               origin: 'Gerät' },
    { name: 'seAuditData',           type: 'OCTET STRING',                   tag: null,          required: false, desc: 'Für Auditdaten des Secure Element (optional).',                            origin: 'Secure Element' },
    { name: 'signatureCounter',      type: 'INTEGER',                        tag: null,          required: true,  desc: 'Aktueller Signaturzähler des Secure Element.',                             origin: 'Secure Element' },
    { name: 'signatureCreationTime', type: 'Time',                           tag: null,          required: true,  desc: 'Zeitpunkt der Signatur im Secure Element.',                                origin: 'Secure Element' },
    { name: 'signatureValue',        type: 'OCTET STRING',                   tag: null,          required: true,  desc: 'Ergebnis der Signaturberechnung.',                                         origin: 'Secure Element' },
  ];

  // ── Gemeinsame Inner-TransactionLogMessage-Felder ────────────────────
  function makeTxnInner(operationType) {
    return [
      { name: 'version',                  type: 'INTEGER (3)',                    tag: null,          required: true,  desc: 'Version des Log-Nachricht-Formats. MUSS 3 sein.',                              origin: 'Gerät' },
      { name: 'certifiedDataType',        type: 'OBJECT IDENTIFIER',              tag: null,          required: true,  desc: 'MUSS auf OID id-SE-API-transaction-log gesetzt sein.',                         origin: 'Gerät' },
      { name: 'operationType',            type: `PrintableString ("${operationType}")`, tag: '[0] IMPLICIT', required: true,  desc: `MUSS auf '${operationType}' gesetzt sein.`,                                    origin: 'Gerät' },
      { name: 'clientId',                 type: 'ClientId',                       tag: '[1] IMPLICIT', required: true,  desc: 'ID der Anwendung, die die Transaktion gestartet hat.',                          origin: 'Anwendung' },
      { name: 'processData',              type: 'OCTET STRING',                   tag: '[2] IMPLICIT', required: true,  desc: 'Die zu sichernden Prozessdaten.',                                              origin: 'Anwendung' },
      { name: 'processType',              type: 'PrintableString (SIZE (0..100))',  tag: '[3] IMPLICIT', required: true,  desc: 'Typ des Vorgangs (max. 100 Zeichen, z.B. DSFinV-K-Vorgangstyp).',              origin: 'Anwendung' },
      { name: 'additionalExternalData',   type: 'OCTET STRING',                   tag: '[4] IMPLICIT', required: false, desc: 'Optionale zusätzliche externe Daten der Anwendung.',                            origin: 'Anwendung' },
      { name: 'transactionNumber',        type: 'INTEGER',                        tag: '[5] IMPLICIT', required: true,  desc: 'Transaktionsnummer vom Secure Element beim Start der Transaktion.',              origin: 'Gerät' },
      { name: 'additionalInternalData',   type: 'OCTET STRING',                   tag: '[6] IMPLICIT', required: false, desc: 'RFU – DARF NICHT vorhanden sein.',                                              origin: '–',    note: 'RFU – darf nicht verwendet werden' },
      { name: 'serialNumber',             type: 'OCTET STRING (SIZE (32))',        tag: null,          required: true,  desc: 'Seriennummer des Secure Element (Hash des öffentlichen Schlüssels).',            origin: 'Gerät' },
      { name: 'signatureAlgorithm',       type: 'AlgorithmIdentifier',            tag: null,          required: true,  desc: 'Informationen über die Signaturerstellung.',                                     origin: 'Gerät' },
      { name: 'signatureCounter',         type: 'INTEGER',                        tag: null,          required: true,  desc: 'Aktueller Signaturzähler des Secure Element.',                                   origin: 'Secure Element' },
      { name: 'signatureCreationTime',    type: 'Time',                           tag: null,          required: true,  desc: 'Zeitpunkt der Signatur im Secure Element.',                                      origin: 'Secure Element' },
      { name: 'signatureValue',           type: 'OCTET STRING',                   tag: null,          required: true,  desc: 'Ergebnis der Signaturberechnung.',                                               origin: 'Secure Element' },
    ];
  }

  // ── Gemeinsame Inner-SystemLogMessage-Felder ─────────────────────────
  function makeSysInner(eventType, eventDataFields) {
    return [
      { name: 'version',               type: 'INTEGER (3)',                    tag: null,           required: true,  desc: 'Version des Log-Nachricht-Formats. MUSS 3 sein.',                          origin: 'Gerät' },
      { name: 'certifiedDataType',     type: 'OBJECT IDENTIFIER',              tag: null,           required: true,  desc: 'MUSS auf OID id-SE-API-system-log gesetzt sein.',                          origin: 'Gerät' },
      { name: 'eventType',             type: `PrintableString ("${eventType}")`,tag: '[0] IMPLICIT', required: true,  desc: `MUSS auf '${eventType}' gesetzt sein.`,                                    origin: 'Gerät' },
      { name: 'eventOrigin',           type: 'PrintableString',                tag: '[1] IMPLICIT', required: false, desc: 'Herkunft des Ereignisses (z.B. "integration-interface", "SMA").',           origin: 'Gerät' },
      { name: 'eventTriggeredByUser',  type: 'UserId',                         tag: '[2] IMPLICIT', required: false, desc: 'Nutzer-ID, der das Ereignis ausgelöst hat.',                               origin: 'Gerät' },
      {
        name: 'eventData',
        type: `${eventType.charAt(0).toUpperCase() + eventType.slice(1)}EventData`,
        tag: '[3] IMPLICIT',
        required: true,
        desc: `Ereignis-spezifische Daten für '${eventType}'.`,
        origin: 'Gerät',
        children: eventDataFields,
      },
      { name: 'additionalInternalData',type: 'OCTET STRING',                   tag: '[4] IMPLICIT', required: false, desc: 'RFU – für zukünftige Verwendung reserviert.',                              origin: '–', note: 'RFU' },
      { name: 'serialNumber',          type: 'OCTET STRING (SIZE (32))',        tag: null,           required: true,  desc: 'Seriennummer des Secure Element (Hash des öffentlichen Schlüssels).',      origin: 'Gerät' },
      { name: 'signatureAlgorithm',    type: 'AlgorithmIdentifier',            tag: null,           required: true,  desc: 'Informationen über die Signaturerstellung.',                               origin: 'Gerät' },
      { name: 'signatureCounter',      type: 'INTEGER',                        tag: null,           required: true,  desc: 'Aktueller Signaturzähler des Secure Element.',                             origin: 'Secure Element' },
      { name: 'signatureCreationTime', type: 'Time',                           tag: null,           required: true,  desc: 'Zeitpunkt der Signatur im Secure Element.',                                origin: 'Secure Element' },
      { name: 'signatureValue',        type: 'OCTET STRING',                   tag: null,           required: true,  desc: 'Ergebnis der Signaturberechnung.',                                         origin: 'Secure Element' },
    ];
  }

  // ── EventData-Felder je Funktion ─────────────────────────────────────

  const EVT_EMPTY = [];  // leere SEQUENCE (deleteLogMessages, disableSecureElement, initialize, lockTransactionLogging, unlockTransactionLogging)

  const EVT_AUTHENTICATE_USER = [
    { name: 'userId',               type: 'PrintableString',  required: true,  desc: 'ID des Nutzers, der sich authentifiziert hat.' },
    { name: 'role',                 type: 'Role',             required: true,  desc: 'Rolle des Nutzers (z.B. logger, admin, timeadmin).' },
    { name: 'authenticationResult', type: 'PinAuthenticationResult', required: true, desc: 'Ergebnis der PIN-Authentifizierung (success / incorrectPin / pinBlocked / …).' },
    { name: 'remainingRetries',     type: 'INTEGER',          required: true,  desc: 'Verbleibende Anzahl an PIN-Versuchen.' },
  ];

  const EVT_CONFIGURE_LOGGING = [
    { name: 'configuredComponents', type: 'ConfiguredComponents', required: true, desc: 'Konfigurierte Logging-Komponenten.' },
  ];

  const EVT_DEREGISTER_CLIENT = [
    { name: 'clientId', type: 'ClientId', required: true, desc: 'ID des abgemeldeten Clients.' },
  ];

  const EVT_LOG_OUT = [
    { name: 'loggedOutUserId', type: 'UserId',      required: true,  desc: 'ID des abgemeldeten Nutzers.' },
    { name: 'logOutCause',     type: 'LogOutCause', required: true,  desc: 'Ursache der Abmeldung (sessionTimeout / userLoggedOut / …).' },
  ];

  const EVT_REGISTER_CLIENT = [
    { name: 'clientId', type: 'ClientId', required: true, desc: 'ID des registrierten Clients.' },
  ];

  // SelfTestResult ::= SEQUENCE { component PrintableString, passed BOOLEAN, errorCode INTEGER (0..127) }
  // SelfTestResultSet ::= SEQUENCE OF SelfTestResult
  const SELFTEST_RESULT_FIELDS = [
    { name: 'component', type: 'PrintableString', tag: null, required: true,  desc: 'Name der getesteten TSE-Komponente (z.B. "storage", "SMA", "CSP", "integration-interface").' },
    { name: 'passed',    type: 'BOOLEAN',          tag: null, required: true,  desc: 'TRUE wenn der Selbsttest dieser Komponente erfolgreich war.' },
    { name: 'errorCode', type: 'INTEGER (0..127)', tag: null, required: true,  desc: 'Fehlercode (0 = kein Fehler).' },
  ];

  const EVT_SELF_TEST = [
    {
      name: 'selfTestResults',
      type: 'SelfTestResultSet',
      tag: null,
      required: true,
      desc: 'SEQUENCE OF SelfTestResult – Ergebnisse für jede getestete TSE-Komponente.',
      children: SELFTEST_RESULT_FIELDS,
    },
    { name: 'allTestsArePositive', type: 'BOOLEAN', tag: null, required: true,
      desc: 'TRUE wenn alle Einzeltests erfolgreich waren.' },
  ];

  const EVT_SET_DESCRIPTION = [
    { name: 'newDeviceDescription', type: 'PrintableString (SIZE (0..64))', required: true, desc: 'Neue Gerätebeschreibung (max. 64 Zeichen).' },
  ];

  const EVT_UNBLOCK_PIN = [
    { name: 'userToUnblock', type: 'UserId',       required: true, desc: 'ID des Nutzers, dessen PIN entsperrt wurde.' },
    { name: 'unblockResult', type: 'UnblockResult',required: true, desc: 'Ergebnis des PIN-Entsperrens.' },
  ];

  const EVT_UPDATE_DEVICE = [
    { name: 'deviceInformationBeforeUpdate', type: 'DeviceInformationSet', required: true, desc: 'Geräteinformationen vor dem Software-Update.' },
  ];

  const EVT_UPDATE_TIME = [
    { name: 'seTimeBeforeUpdate', type: 'Time',                    required: true,  desc: 'Zeitwert des Secure Element vor der Aktualisierung.' },
    { name: 'seTimeAfterUpdate',  type: 'Time',                    required: true,  desc: 'Zeitwert des Secure Element nach der Aktualisierung.' },
    { name: 'slewSettings',       type: 'SlewSettings',            required: false, desc: 'Optionale Slew-Rate-Einstellungen für die Zeitanpassung.' },
  ];

  // ── Definitions-Map ───────────────────────────────────────────────────
  //
  // Schlüssel für TransactionLogs: operationType-String (camelCase)
  // Schlüssel für SystemLogs:      eventType-String (camelCase)
  //
  const DEFS = {
    // ── Transaction Logs ──────────────────────────────────────────────
    startTransaction: {
      logType: 'txn',
      operationType: 'startTransaction',
      title: 'startTransaction – Transaktions-Log',
      outerStruct: 'LogMessage (TransactionLog)',
      innerStruct: 'TransactionLogMessage',
      outerFields: OUTER_TXN,
      innerFields: makeTxnInner('startTransaction'),
    },
    updateTransaction: {
      logType: 'txn',
      operationType: 'updateTransaction',
      title: 'updateTransaction – Transaktions-Log',
      outerStruct: 'LogMessage (TransactionLog)',
      innerStruct: 'TransactionLogMessage',
      outerFields: OUTER_TXN,
      innerFields: makeTxnInner('updateTransaction'),
    },
    finishTransaction: {
      logType: 'txn',
      operationType: 'finishTransaction',
      title: 'finishTransaction – Transaktions-Log',
      outerStruct: 'LogMessage (TransactionLog)',
      innerStruct: 'TransactionLogMessage',
      outerFields: OUTER_TXN,
      innerFields: makeTxnInner('finishTransaction'),
    },

    // ── System Logs ───────────────────────────────────────────────────
    authenticateUser: {
      logType: 'sys',
      eventType: 'authenticateUser',
      title: 'authenticateUser – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('authenticateUser', EVT_AUTHENTICATE_USER),
    },
    configureLogging: {
      logType: 'sys',
      eventType: 'configureLogging',
      title: 'configureLogging – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('configureLogging', EVT_CONFIGURE_LOGGING),
    },
    deleteLogMessages: {
      logType: 'sys',
      eventType: 'deleteLogMessages',
      title: 'deleteLogMessages – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('deleteLogMessages', EVT_EMPTY),
    },
    deregisterClient: {
      logType: 'sys',
      eventType: 'deregisterClient',
      title: 'deregisterClient – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('deregisterClient', EVT_DEREGISTER_CLIENT),
    },
    disableSecureElement: {
      logType: 'sys',
      eventType: 'disableSecureElement',
      title: 'disableSecureElement – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('disableSecureElement', EVT_EMPTY),
    },
    initialize: {
      logType: 'sys',
      eventType: 'initialize',
      title: 'initialize – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('initialize', EVT_EMPTY),
    },
    lockTransactionLogging: {
      logType: 'sys',
      eventType: 'lockTransactionLogging',
      title: 'lockTransactionLogging – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('lockTransactionLogging', EVT_EMPTY),
    },
    logOut: {
      logType: 'sys',
      eventType: 'logOut',
      title: 'logOut – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('logOut', EVT_LOG_OUT),
    },
    registerClient: {
      logType: 'sys',
      eventType: 'registerClient',
      title: 'registerClient – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('registerClient', EVT_REGISTER_CLIENT),
    },
    selfTest: {
      logType: 'sys',
      eventType: 'selfTest',
      title: 'selfTest – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('selfTest', EVT_SELF_TEST),
    },
    setDescription: {
      logType: 'sys',
      eventType: 'setDescription',
      title: 'setDescription – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('setDescription', EVT_SET_DESCRIPTION),
    },
    unblockPin: {
      logType: 'sys',
      eventType: 'unblockPin',
      title: 'unblockPin – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('unblockPin', EVT_UNBLOCK_PIN),
    },
    unlockTransactionLogging: {
      logType: 'sys',
      eventType: 'unlockTransactionLogging',
      title: 'unlockTransactionLogging – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('unlockTransactionLogging', EVT_EMPTY),
    },
    updateDevice: {
      logType: 'sys',
      eventType: 'updateDevice',
      title: 'updateDevice – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('updateDevice', EVT_UPDATE_DEVICE),
    },
    updateTime: {
      logType: 'sys',
      eventType: 'updateTime',
      title: 'updateTime – System-Log',
      outerStruct: 'LogMessage (SystemLog)',
      innerStruct: 'SystemLogMessage',
      outerFields: OUTER_SYS,
      innerFields: makeSysInner('updateTime', EVT_UPDATE_TIME),
    },
  };

  /**
   * Gibt die Schemadefinition für einen Log-Eintrag zurück.
   * Lookup erfolgt über operationType (Txn) oder eventType (Sys).
   */
  function getDefinition(logEntry) {
    if (!logEntry) return null;
    const key = logEntry.operationType || logEntry.eventType || null;
    if (key && DEFS[key]) return DEFS[key];

    // Fallback: Aus Dateiname ermitteln (Log-Tra_..._Start/Update/Finish bzw. Log-Sys_<evt>)
    const fn = logEntry._filename || '';
    const txnM = fn.match(/_Log-Tra_No-\d+_(Start|Update|Finish)_/i);
    if (txnM) {
      const map = { Start: 'startTransaction', Update: 'updateTransaction', Finish: 'finishTransaction' };
      const k = map[txnM[1]];
      return DEFS[k] || null;
    }
    const sysM = fn.match(/_Log-Sys_([^.]+)\.log$/i);
    if (sysM && DEFS[sysM[1]]) return DEFS[sysM[1]];

    return null;
  }

  return { DEFS, getDefinition };
})();
