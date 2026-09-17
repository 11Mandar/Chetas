/**
 * Key-Value / Perimeter Firewall Parser (Fortinet FortiOS, Palo Alto Networks, Check Point)
 */

export function isKeyValue(logStr) {
  const str = logStr.trim();
  // Check for presence of multiple key=value or key="value" pairs
  const kvMatches = str.match(/[a-zA-Z0-9_.-]+=(?:"[^"]*"|\S+)/g);
  return kvMatches && kvMatches.length >= 3;
}

export function parseKeyValue(raw) {
  const str = raw.trim();
  const attributes = {};

  // Matches key="quoted value" or key=unquotedValue
  const regex = /([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|(\S+))/g;
  let match;
  let vendor = 'Generic Perimeter';
  let product = 'Network Device';

  while ((match = regex.exec(str)) !== null) {
    const key = match[1];
    const val = match[2] !== undefined ? match[2] : match[3];
    attributes[key] = val;
  }

  // Detect Vendor
  if (attributes.devname && (attributes.devid?.startsWith('FG') || str.includes('FGT') || attributes.vd)) {
    vendor = 'Fortinet';
    product = 'FortiGate FortiOS';
  } else if (attributes.vsys || attributes.rule || attributes.pcap_id || str.includes('PAN-OS')) {
    vendor = 'Palo Alto Networks';
    product = 'PAN-OS Firewall';
  } else if (attributes.product?.toLowerCase().includes('vpn') || attributes.service) {
    vendor = attributes.vendor || 'Perimeter Gateway';
    product = attributes.product || 'Firewall';
  }

  return {
    format: 'Key-Value',
    vendor,
    product,
    event_type: attributes.type || attributes.subtype || 'FIREWALL_TRAFFIC',
    severity: attributes.level || attributes.severity || 'notice',
    attributes
  };
}
