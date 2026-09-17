/**
 * Common Event Format (CEF) Parser
 * Standard specification:
 * CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
 */

export function isCEF(logStr) {
  return /^CEF:\s*\d+\|/i.test(logStr.trim());
}

export function parseCEF(raw) {
  const str = raw.trim();
  const prefixMatch = str.match(/^CEF:\s*(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$/s);

  if (!prefixMatch) {
    throw new Error('Invalid CEF format: failed to parse standard 7 header fields');
  }

  const [
    ,
    cefVersion,
    deviceVendor,
    deviceProduct,
    deviceVersion,
    deviceEventClassId,
    name,
    severity,
    extensionStr
  ] = prefixMatch;

  const extensions = parseCEFExtensions(extensionStr || '');

  return {
    format: 'CEF',
    cef_version: cefVersion,
    vendor: deviceVendor || 'Unknown Vendor',
    product: deviceProduct || 'Security Appliance',
    version: deviceVersion,
    event_class_id: deviceEventClassId,
    event_name: name,
    severity: severity,
    attributes: extensions
  };
}

function parseCEFExtensions(extStr) {
  const attrs = {};
  if (!extStr) return attrs;

  // Regex to match key=value pairs handling escaped characters and values
  // A key is preceded by whitespace or start of string and followed by '='
  const regex = /([a-zA-Z0-9_.-]+)=/g;
  let match;
  const indices = [];

  while ((match = regex.exec(extStr)) !== null) {
    indices.push({
      key: match[1],
      valStart: match.index + match[0].length,
      keyStart: match.index
    });
  }

  for (let i = 0; i < indices.length; i++) {
    const current = indices[i];
    const next = indices[i + 1];
    let val;
    if (next) {
      val = extStr.substring(current.valStart, next.keyStart).trim();
    } else {
      val = extStr.substring(current.valStart).trim();
    }
    // Unescape \=, \\, \n
    val = val.replace(/\\=/g, '=').replace(/\\\\/g, '\\').replace(/\\n/g, '\n');
    attrs[current.key] = val;
  }

  return attrs;
}
