import { isCEF, parseCEF } from './cef.js';
import { isLEEF, parseLEEF } from './leef.js';
import { isSyslog, parseSyslog } from './syslog.js';
import { isJSON, parseJSON } from './json.js';
import { isWebAccess, parseWebAccess } from './webaccess.js';
import { isCiscoASA, parseCiscoASA } from './cisco.js';
import { isKeyValue, parseKeyValue } from './keyvalue.js';

/**
 * Universal Auto-Detector and Parser Router
 * Intelligently analyzes raw logs, unwraps transport headers (e.g. Syslog wrapping CEF or Cisco),
 * and dispatches to the optimal parser.
 */
export function parseLog(rawLog) {
  if (!rawLog || typeof rawLog !== 'string' || !rawLog.trim()) {
    throw new Error('Empty or invalid log payload');
  }

  const trimmed = rawLog.trim();

  // Check for Syslog transport wrapper
  if (isSyslog(trimmed)) {
    // Check if there is an embedded CEF inside the syslog line
    const cefIndex = trimmed.search(/\bCEF:\s*\d+\|/i);
    if (cefIndex !== -1) {
      const syslogPrefix = trimmed.substring(0, cefIndex).trim();
      const cefPart = trimmed.substring(cefIndex).trim();
      const cefParsed = parseCEF(cefPart);
      let transportMeta = {};
      try {
        const sysParsed = parseSyslog(syslogPrefix.endsWith(':') ? syslogPrefix + ' ' : syslogPrefix);
        transportMeta = {
          pri: sysParsed.pri,
          facility: sysParsed.facility,
          syslog_severity: sysParsed.severity,
          hostname: sysParsed.hostname
        };
      } catch (e) {
        // preserve whatever pri exists
        const m = syslogPrefix.match(/^<(\d+)>/);
        if (m) transportMeta.pri = parseInt(m[1], 10);
      }
      return {
        ...cefParsed,
        transport: 'Syslog',
        transport_meta: transportMeta
      };
    }

    // Check if there is an embedded Cisco ASA inside syslog
    const asaIndex = trimmed.search(/%(?:ASA|IOS|PIX|FTD)-\d-\d{6}:/i);
    if (asaIndex !== -1) {
      const syslogPrefix = trimmed.substring(0, asaIndex).trim();
      const asaPart = trimmed.substring(asaIndex).trim();
      const asaParsed = parseCiscoASA(asaPart);
      return {
        ...asaParsed,
        transport: 'Syslog',
        transport_meta: { prefix: syslogPrefix }
      };
    }

    const syslogParsed = parseSyslog(trimmed);
    const innerMsg = syslogParsed.message || '';

    if (isKeyValue(innerMsg)) {
      const innerKV = parseKeyValue(innerMsg);
      return {
        ...innerKV,
        transport: syslogParsed.format,
        transport_meta: {
          pri: syslogParsed.pri,
          facility: syslogParsed.facility,
          hostname: syslogParsed.hostname
        }
      };
    }

    return syslogParsed;
  }

  // Direct format detection
  if (isCEF(trimmed)) {
    return parseCEF(trimmed);
  }

  if (isLEEF(trimmed)) {
    return parseLEEF(trimmed);
  }

  if (isCiscoASA(trimmed)) {
    return parseCiscoASA(trimmed);
  }

  if (isJSON(trimmed)) {
    return parseJSON(trimmed);
  }

  if (isWebAccess(trimmed)) {
    return parseWebAccess(trimmed);
  }

  if (isKeyValue(trimmed)) {
    return parseKeyValue(trimmed);
  }

  // Fallback: Generic Unstructured Free-Text Parser
  return parseGeneric(trimmed);
}

function parseGeneric(str) {
  const attributes = {};

  // Extract IPs
  const ipMatches = str.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g);
  if (ipMatches) {
    if (ipMatches[0]) attributes.source_ip = ipMatches[0];
    if (ipMatches[1]) attributes.destination_ip = ipMatches[1];
  }

  // Extract key=value or key: value
  const kvMatches = str.matchAll(/([a-zA-Z0-9_.-]+)[=:](?:"([^"]*)"|(\S+))/g);
  for (const m of kvMatches) {
    attributes[m[1]] = m[2] !== undefined ? m[2] : m[3];
  }

  return {
    format: 'Generic-Text',
    vendor: 'Generic Host',
    product: 'System Logger',
    event_type: 'UNCLASSIFIED_EVENT',
    severity: 'INFORMATIONAL',
    message: str,
    attributes
  };
}
