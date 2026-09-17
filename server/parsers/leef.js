/**
 * Log Event Extended Format (LEEF) Parser
 * Standard specification:
 * LEEF:Version|Vendor|Product|Version|EventID|[Delimiter]|Key=Value...
 */

export function isLEEF(logStr) {
  return /^LEEF:\s*\d+(\.\d+)?\|/i.test(logStr.trim());
}

export function parseLEEF(raw) {
  const str = raw.trim();
  const parts = str.split('|');

  if (parts.length < 5) {
    throw new Error('Invalid LEEF format: requires at least 5 pipe-separated fields');
  }

  const version = parts[0].replace(/^LEEF:\s*/i, '');
  const vendor = parts[1] || 'Unknown Vendor';
  const product = parts[2] || 'Security Product';
  const devVersion = parts[3] || '';
  const eventId = parts[4] || '';

  let delimiter = '\t'; // Default delimiter for LEEF 1.0
  let extensionStr = '';

  if (parts.length >= 7) {
    // 6th field is delimiter (if single char or hex code), 7th is extensions
    if (parts[5].length === 1 || parts[5].startsWith('x')) {
      delimiter = parts[5].startsWith('x') ? String.fromCharCode(parseInt(parts[5].slice(1), 16)) : parts[5];
      extensionStr = parts.slice(6).join('|');
    } else {
      extensionStr = parts.slice(5).join('|');
    }
  } else if (parts.length === 6) {
    extensionStr = parts[5];
  }

  const attributes = {};
  if (extensionStr) {
    const pairs = extensionStr.split(delimiter);
    for (const pair of pairs) {
      const eqIdx = pair.indexOf('=');
      if (eqIdx > 0) {
        const k = pair.substring(0, eqIdx).trim();
        const v = pair.substring(eqIdx + 1).trim();
        if (k) attributes[k] = v;
      }
    }
  }

  return {
    format: 'LEEF',
    leef_version: version,
    vendor,
    product,
    version: devVersion,
    event_id: eventId,
    attributes
  };
}
