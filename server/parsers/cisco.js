/**
 * Cisco ASA / IOS / PIX Firewall Parser
 * Standard pattern: %ASA-severity-message_id: message text
 */

const CISCO_SEVERITIES = {
  '0': 'EMERGENCY',
  '1': 'ALERT',
  '2': 'CRITICAL',
  '3': 'ERROR',
  '4': 'WARNING',
  '5': 'NOTICE',
  '6': 'INFORMATIONAL',
  '7': 'DEBUG'
};

export function isCiscoASA(logStr) {
  return /%(?:ASA|IOS|PIX|FTD)-\d-\d{6}:/i.test(logStr.trim());
}

export function parseCiscoASA(raw) {
  const str = raw.trim();
  const match = str.match(/%(?:ASA|IOS|PIX|FTD)-([0-7])-(\d{6}):\s*(.*)$/i);

  if (!match) {
    throw new Error('Invalid Cisco ASA message pattern');
  }

  const [, severityNum, messageId, message] = match;
  const severity = CISCO_SEVERITIES[severityNum] || 'INFORMATIONAL';

  // Extract IPs and ports if present: e.g. "src outside:198.51.100.5/4532 dst inside:192.168.1.10/80"
  const attributes = {
    cisco_code: `%ASA-${severityNum}-${messageId}`,
    message_id: messageId,
    severity_level: parseInt(severityNum, 10),
    message_body: message
  };

  const srcMatch = message.match(/src\s+([a-zA-Z0-9_-]+):([0-9.]+)(?:\/(\d+))?/i);
  if (srcMatch) {
    attributes.src_interface = srcMatch[1];
    attributes.src_ip = srcMatch[2];
    if (srcMatch[3]) attributes.src_port = parseInt(srcMatch[3], 10);
  }

  const dstMatch = message.match(/dst\s+([a-zA-Z0-9_-]+):([0-9.]+)(?:\/(\d+))?/i);
  if (dstMatch) {
    attributes.dst_interface = dstMatch[1];
    attributes.dst_ip = dstMatch[2];
    if (dstMatch[3]) attributes.dst_port = parseInt(dstMatch[3], 10);
  }

  const protoMatch = message.match(/\b(tcp|udp|icmp|gre|esp)\b/i);
  if (protoMatch) {
    attributes.protocol = protoMatch[1].toUpperCase();
  }

  const action = message.toLowerCase().includes('deny') || message.toLowerCase().includes('drop')
    ? 'DENY'
    : message.toLowerCase().includes('built') || message.toLowerCase().includes('permit')
    ? 'ALLOW'
    : 'ALERT';

  return {
    format: 'Cisco-ASA',
    vendor: 'Cisco Systems',
    product: 'Cisco Adaptive Security Appliance (ASA)',
    event_type: 'FIREWALL_EVENT',
    severity,
    action,
    attributes
  };
}
