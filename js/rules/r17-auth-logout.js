// ─── r17-auth-logout.js – Authentifizierung & Abmeldung (EVDATA_AUTH / EVDATA_LOGOUT)
'use strict';
window.RulesCat17 = (function() {
  const CAT = 'Authentifizierung & Abmeldung (EVDATA_AUTH / EVDATA_LOGOUT)';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['EVDATA_AUTH_RESULT_VALUES','EVDATA_AUTH_RETRIES_MAX','EVDATA_AUTH_RETRIES_DECREMENT',
      'EVDATA_AUTH_RETRIES_ZERO_BLOCKED','EVDATA_AUTH_TRIGGER','EVDATA_LOGOUT_USERID',
      'EVDATA_LOGOUT_CASE','EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT','EVDATA_LOGOUT_ORIGIN_IMPLICIT',
      'EVDATA_LOGOUT_TRIGGER_EXPLICIT','EVDATA_UNBLOCK_TRIGGER','EVDATA_SELFTEST_TRIGGER',
      'IMPLICIT_LOGOUT_PRESENT','IMPLICIT_LOGOUT_ABSENT_SAME_USER'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine SystemLogs.', '', 'BSI TR-03151-1 §4.4')));
      return results;
    }

    const sysLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'sys');
    const authLogs = sysLogs.filter(l => l.eventType === 'authenticate');
    const logoutLogs = sysLogs.filter(l => l.eventType === 'logout');
    const unblockLogs = sysLogs.filter(l => l.eventType === 'unblockUser');
    const selfTestLogs = sysLogs.filter(l => l.eventType === 'selfTest');

    // EVDATA_AUTH_RESULT_VALUES
    if (authLogs.length === 0) {
      results.push(Utils.skip('EVDATA_AUTH_RESULT_VALUES', 'authenticationResult-Werte gültig', CAT, 'Keine authenticate-Logs.', '', 'BSI TR-03151-1 §4.4.1'));
    } else {
      const VALID = ['ok', 'failed', 'failed-disabled'];
      const badResult = authLogs.filter(l => {
        try { const d = JSON.parse(new TextDecoder().decode(l.eventData)); return !VALID.includes(d.authenticationResult); } catch { return false; }
      });
      results.push(badResult.length === 0
        ? Utils.pass('EVDATA_AUTH_RESULT_VALUES', 'authenticationResult-Werte gültig', CAT,
            `${authLogs.length} authenticate-Logs: authenticationResult jeweils gültig.`,
            `Erlaubt: ${VALID.join(', ')}`, 'BSI TR-03151-1 §4.4.1')
        : Utils.fail('EVDATA_AUTH_RESULT_VALUES', 'authenticationResult-Werte gültig', CAT,
            `${badResult.length} Logs mit ungültigem authenticationResult.`, '', 'BSI TR-03151-1 §4.4.1'));
    }

    // EVDATA_AUTH_RETRIES_MAX / DECREMENT / ZERO_BLOCKED
    for (const [id, name, desc] of [
      ['EVDATA_AUTH_RETRIES_MAX', 'Maximale Wiederholungsanzahl korrekt', 'remainingRetries darf den konfigurierten Maximalwert nicht überschreiten.'],
      ['EVDATA_AUTH_RETRIES_DECREMENT', 'Wiederholungsanzahl dekrementiert', 'Nach fehlgeschlagenem Authentifizierungsversuch muss remainingRetries dekrementiert sein.'],
      ['EVDATA_AUTH_RETRIES_ZERO_BLOCKED', 'Kein Login nach remainingRetries=0', 'Nach remainingRetries=0 darf kein erfolgreicher Login-Eintrag folgen.'],
    ]) {
      results.push(Utils.info(id, name, CAT,
        `${authLogs.length} authenticate-Logs vorhanden. ${desc} Vollständige Prüfung erfordert zustandsbehaftete Auswertung.`,
        desc, 'BSI TR-03151-1 §4.4.1'));
    }

    // EVDATA_AUTH_TRIGGER
    const authNoTrigger = authLogs.filter(l => !l.eventTriggeredByUser);
    results.push(authLogs.length === 0
      ? Utils.skip('EVDATA_AUTH_TRIGGER', 'authenticate-Trigger vorhanden', CAT, 'Keine authenticate-Logs.', '', 'BSI TR-03151-1 §4.4.1')
      : authNoTrigger.length === 0
        ? Utils.pass('EVDATA_AUTH_TRIGGER', 'authenticate-Trigger vorhanden', CAT,
            `Alle ${authLogs.length} authenticate-Logs enthalten eventTriggeredByUser.`, '', 'BSI TR-03151-1 §4.4.1')
        : Utils.warn('EVDATA_AUTH_TRIGGER', 'authenticate-Trigger vorhanden', CAT,
            `${authNoTrigger.length} authenticate-Logs ohne eventTriggeredByUser.`, '', 'BSI TR-03151-1 §4.4.1'));

    // EVDATA_LOGOUT_USERID / CASE
    if (logoutLogs.length === 0) {
      ['EVDATA_LOGOUT_USERID','EVDATA_LOGOUT_CASE','EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT',
       'EVDATA_LOGOUT_ORIGIN_IMPLICIT','EVDATA_LOGOUT_TRIGGER_EXPLICIT'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine logout-Logs.', '', 'BSI TR-03151-1 §4.4.2')));
    } else {
      const noUser = logoutLogs.filter(l => !l.eventTriggeredByUser);
      results.push(noUser.length === 0
        ? Utils.pass('EVDATA_LOGOUT_USERID', 'userId in logout vorhanden', CAT, `Alle ${logoutLogs.length} logout-Logs: userId vorhanden.`, '', 'BSI TR-03151-1 §4.4.2')
        : Utils.warn('EVDATA_LOGOUT_USERID', 'userId in logout vorhanden', CAT, `${noUser.length} Logs ohne userId.`, '', 'BSI TR-03151-1 §4.4.2'));

      results.push(Utils.info('EVDATA_LOGOUT_CASE', 'logoutCase vorhanden und gültig', CAT,
        `${logoutLogs.length} logout-Logs. logoutCase-Prüfung (regular/timeout/implicit) erfordert eventData-ASN.1-Parsing.`, '', 'BSI TR-03151-1 §4.4.2'));

      const implicitLogs = logoutLogs.filter(l => {
        try { const d = JSON.parse(new TextDecoder().decode(l.eventData)); return d.logoutCase === 'implicit'; } catch { return false; }
      });
      results.push(Utils.info('EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT', 'Kein Trigger bei implizitem Logout', CAT,
        `${implicitLogs.length} implizite Logout-Einträge. Bei logoutCase=implicit darf kein eventTriggeredByUser gesetzt sein.`, '', 'BSI TR-03151-1 §4.4.2'));
      results.push(Utils.info('EVDATA_LOGOUT_ORIGIN_IMPLICIT', 'eventOrigin bei implizitem Logout = SE', CAT,
        'Bei logoutCase=implicit muss eventOrigin=SE sein.', '', 'BSI TR-03151-1 §4.4.2'));
      results.push(Utils.info('EVDATA_LOGOUT_TRIGGER_EXPLICIT', 'Trigger bei explizitem Logout vorhanden', CAT,
        'Bei logoutCase=regular oder logoutCase=timeout muss eventTriggeredByUser gesetzt sein.', '', 'BSI TR-03151-1 §4.4.2'));
    }

    // EVDATA_UNBLOCK_TRIGGER
    results.push(unblockLogs.length === 0
      ? Utils.skip('EVDATA_UNBLOCK_TRIGGER', 'Trigger bei unblockUser vorhanden', CAT, 'Keine unblockUser-Logs.', '', 'BSI TR-03151-1 §4.4.3')
      : Utils.pass('EVDATA_UNBLOCK_TRIGGER', 'Trigger bei unblockUser vorhanden', CAT,
          `${unblockLogs.length} unblockUser-Logs gefunden.`, '', 'BSI TR-03151-1 §4.4.3'));

    // EVDATA_SELFTEST_TRIGGER
    results.push(selfTestLogs.length === 0
      ? Utils.skip('EVDATA_SELFTEST_TRIGGER', 'Trigger bei selfTest vorhanden', CAT, 'Keine selfTest-Logs.', '', 'BSI TR-03151-1 §4.4.4')
      : Utils.pass('EVDATA_SELFTEST_TRIGGER', 'Trigger bei selfTest vorhanden', CAT,
          `${selfTestLogs.length} selfTest-Logs gefunden.`, '', 'BSI TR-03151-1 §4.4.4'));

    // IMPLICIT_LOGOUT_PRESENT / ABSENT_SAME_USER
    results.push(Utils.info('IMPLICIT_LOGOUT_PRESENT', 'Impliziter Logout bei Nutzerwechsel vorhanden', CAT,
      'Prüfung erfordert kontextuelle Analyse: Wenn Benutzer A eingeloggt ist und Benutzer B sich anmeldet, muss ein impliziter Logout für Benutzer A vorhanden sein.',
      '', 'BSI TR-03151-1 §4.4.2'));
    results.push(Utils.info('IMPLICIT_LOGOUT_ABSENT_SAME_USER', 'Kein impliziter Logout bei erneutem Login gleichen Nutzers', CAT,
      'Bei erneutem Login desselben Benutzers darf KEIN impliziter Logout-Eintrag erscheinen.',
      '', 'BSI TR-03151-1 §4.4.2'));

    return results;
  }
  return { run, CAT };
})();
