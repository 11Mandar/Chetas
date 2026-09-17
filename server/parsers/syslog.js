/**
 * Syslog Parsers for RFC 5424 and RFC 3164
 */

const SYSLOG_FACILITIES = [
  'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'security', 'console', 'solaris-cron',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
];

const SYSLOG_SEVERITIES = [
  'EMERGENCY', 'ALERT', 'CRITICAL', 'ERROR', 'WARNING', 'NOTICE', 'INFORMATIONAL', 'DEBUG'
];

export function isSyslog(logStr) {
  return /^<\d{1,3}>/.test(logStr.trim());
}

export function parseSyslog(raw) {
  const str = raw.trim();
  const priMatch = str.match(/^<(\d{1,3})>(.*)$/s);
  if (!priMatch) {
    throw new Error('Invalid Syslog format: Missing <PRI>');
  }

  const pri = parseInt(priMatch[1], 10);
  const facilityCode = Math.floor(pri / 8);
  const severityCode = pri % 8;
  const facility = SYSLOG_FACILITIES[facilityCode] || `facility-${facilityCode}`;
  const severity = SYSLOG_SEVERITIES[severityCode] || `severity-${severityCode}`;

  const remainder = priMatch[2];

  // Try RFC 5424: begins with version digit, e.g. "1 2026-09-16T..."
  const rfc5424Match = remainder.match(/^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\[.*?\]|-))?(?:\s+(.*))?$/s);
  if (rfc5424Match) {
    const [, version, timestamp, hostname, appName, procId, msgId, structuredData, msg] = rfc5424Match;
    
    // Parse structured data if present
    const sdAttrs = {};
    if (structuredData && structuredData !== '-') {
      const paramMatches = structuredData.matchAll(/([a-zA-Z0-9_]+)="([^"]*)"/g);
      for (const m of paramMatches) {
        sdAttrs[m[1]] = m[2];
      }
    }

    return {
      format: 'Syslog-RFC5424',
      pri,
      facility,
      severity,
      severity_code: severityCode,
      version,
      timestamp: timestamp !== '-' ? timestamp : null,
      hostname: hostname !== '-' ? hostname : null,
      app_name: appName !== '-' ? appName : null,
      proc_id: procId !== '-' ? procId : null,
      msg_id: msgId !== '-' ? msgId : null,
      message: (msg || '').trim(),
      attributes: {
        ...sdAttrs,
        facility,
        appName,
        procId,
        msgId
      }
    };
  }

  // RFC 3164 (BSD syslog): e.g. "Sep 16 14:30:15 myhost tag[123]: message" or "2026-09-16T14:30:15 myhost tag: message"
  const rfc3164Match = remainder.match(/^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+([^\s:]+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$/s);
  if (rfc3164Match) {
    const [, timestamp, hostname, tag, pid, msg] = rfc3164Match;
    return {
      format: 'Syslog-RFC3164',
      pri,
      facility,
      severity,
      severity_code: severityCode,
      timestamp,
      hostname,
      tag,
      pid: pid || null,
      message: (msg || '').trim(),
      attributes: {
        facility,
        tag,
        pid
      }
    };
  }

  // Fallback syslog
  const genericMatch = remainder.match(/^([^\s]+)\s+(.*)$/s);
  return {
    format: 'Syslog-Generic',
    pri,
    facility,
    severity,
    severity_code: severityCode,
    timestamp: genericMatch ? genericMatch[1] : null,
    message: genericMatch ? genericMatch[2].trim() : remainder.trim(),
    attributes: {
      facility
    }
  };
}
