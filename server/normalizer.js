import { aiMapper } from './aiMapping.js';

/**
 * Universal Log Normalization Engine
 * Standardizes parsed telemetry from any vendor or format into the unified Chetas schema
 * while preserving complete raw integrity and bidirectional traceability.
 */

export function normalizeLog(parsed, provenance) {
  const attrs = parsed.attributes || {};
  const mappedAttrs = { ...attrs };

  // Step 1: Apply Dynamic & Approved AI Mappings to all raw attributes
  const canonicalValues = {};
  const remainingExtra = {};

  for (const [key, val] of Object.entries(mappedAttrs)) {
    // Check if key has an approved canonical mapping
    const targetCanonical = aiMapper.resolveKey(key);
    if (targetCanonical) {
      canonicalValues[targetCanonical] = val;
    } else {
      // Evaluate with AI for possible future suggestion
      aiMapper.evaluateUnknownField(key, String(val));
      remainingExtra[key] = val;
    }
  }

  // Step 2: Timestamp Normalization
  const timestamp = normalizeTimestamp(parsed.timestamp || attrs.timestamp || attrs.date || attrs.time || provenance.ingest_timestamp);

  // Step 3: Severity Normalization
  const rawSev = parsed.severity || attrs.severity || attrs.level || attrs.priority || (parsed.transport_meta && parsed.transport_meta.syslog_severity);
  const severity = normalizeSeverity(rawSev, parsed.format);

  // Step 4: Network & Identity Attributes Resolution
  let rawSourceIp = canonicalValues.source_ip || attrs.source_ip || attrs.sourceIP || attrs.src_ip || attrs.srcip || attrs.src || attrs.client_ip || attrs.clientIp || attrs.c_ip || attrs.ip || attrs.sourceAddress || null;
  let rawDestIp = canonicalValues.destination_ip || attrs.destination_ip || attrs.destinationIP || attrs.dst_ip || attrs.dstip || attrs.dst || attrs.dest_ip || attrs.destIp || attrs.s_ip || attrs.destAddress || attrs.server_ip || null;

  // If source IP is not in payload body, extract from provenance source_id or network transport metadata
  if (!rawSourceIp && provenance?.source_id) {
    const ipMatch = provenance.source_id.match(/(?:udp|http|src)-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (ipMatch && ipMatch[1] && ipMatch[1] !== '127.0.0.1') {
      rawSourceIp = ipMatch[1];
    }
  }

  const sourceIp = rawSourceIp;
  const sourcePort = parsePort(canonicalValues.source_port || attrs.source_port || attrs.src_port || attrs.srcport || attrs.spt);

  const destinationIp = rawDestIp;
  const destinationPort = parsePort(canonicalValues.destination_port || attrs.destination_port || attrs.dst_port || attrs.dstport || attrs.dpt);

  const protocol = normalizeProtocol(canonicalValues.protocol || attrs.protocol || attrs.proto);
  const userName = canonicalValues.user_name || attrs.user_name || attrs.username || attrs.user || attrs.usr || attrs.auth_user || null;

  // Step 5: Action & Outcome Normalization
  const action = normalizeAction(canonicalValues.action || parsed.action || attrs.action || attrs.act || attrs.status);
  const outcome = normalizeOutcome(canonicalValues.outcome || attrs.outcome || attrs.result || action);

  // Step 6: Categorization
  const eventType = categorizeEventType(parsed.event_type || parsed.event_name || parsed.event_class_id || attrs.event_type || attrs.type || parsed.format, action);

  // Step 7: Summary Message
  const message = canonicalValues.message || parsed.message || attrs.message || attrs.msg || parsed.event_name || `${parsed.vendor} ${parsed.product} ${eventType}`;

  // Clean up remaining extra data so it doesn't duplicate primary mapped fields
  delete remainingExtra[sourceIp];
  delete remainingExtra[destinationIp];

  const sourceHost = attrs.source_host || attrs.hostname || attrs.host || attrs.computerName || attrs.computer || null;

  return {
    provenance_id: provenance.provenance_id,
    timestamp,
    vendor: parsed.vendor || attrs.vendor || 'Generic Vendor',
    product: parsed.product || attrs.product || 'Network Appliance',
    format: parsed.format || 'Standard',
    event_type: eventType,
    severity: severity.label,
    severity_level: severity.level,
    source_ip: sourceIp,
    source_port: sourcePort,
    source_host: sourceHost,
    destination_ip: destinationIp,
    destination_port: destinationPort,
    protocol,
    user_name: userName,
    action,
    outcome,
    message: String(message).trim(),
    extra_data: remainingExtra,
    raw_ref: {
      provenance_id: provenance.provenance_id,
      raw_sha256: provenance.raw_sha256,
      raw_bytes: provenance.raw_bytes,
      source_id: provenance.source_id,
      ingest_timestamp: provenance.ingest_timestamp
    }
  };
}

function normalizeTimestamp(raw) {
  if (!raw) return new Date().toISOString();
  try {
    const d = new Date(raw);
    if (!isNaN(d.getTime())) return d.toISOString();
  } catch (e) {
    // ignore
  }
  return new Date().toISOString();
}

function normalizeSeverity(raw, format = '') {
  if (!raw) return { label: 'INFORMATIONAL', level: 1 };
  const s = String(raw).toUpperCase().trim();

  // If format is CEF and severity is purely numeric (CEF uses 0-10 scale where 10 is highest)
  if (format === 'CEF' && /^\d+$/.test(s)) {
    const num = parseInt(s, 10);
    if (num >= 9) return { label: 'CRITICAL', level: 5 };
    if (num >= 7) return { label: 'HIGH', level: 4 };
    if (num >= 4) return { label: 'WARNING', level: 3 };
    if (num >= 1) return { label: 'LOW', level: 2 };
    return { label: 'INFORMATIONAL', level: 1 };
  }

  if (s.includes('CRIT') || s === 'EMERGENCY' || s === 'FATAL') {
    return { label: 'CRITICAL', level: 5 };
  }
  if (s.includes('ERR') || s.includes('ALERT') || s === 'HIGH') {
    return { label: 'HIGH', level: 4 };
  }
  if (s.includes('WARN') || s === 'MEDIUM') {
    return { label: 'WARNING', level: 3 };
  }
  if (s.includes('NOTICE') || s === 'LOW') {
    return { label: 'LOW', level: 2 };
  }

  // Syslog numeric scale (0-7 where 0 is highest)
  if (format.startsWith('Syslog') && /^\d+$/.test(s)) {
    const num = parseInt(s, 10);
    if (num <= 2) return { label: 'CRITICAL', level: 5 };
    if (num === 3) return { label: 'HIGH', level: 4 };
    if (num === 4) return { label: 'WARNING', level: 3 };
    if (num === 5) return { label: 'LOW', level: 2 };
    return { label: 'INFORMATIONAL', level: 1 };
  }

  return { label: 'INFORMATIONAL', level: 1 };
}

function parsePort(val) {
  if (!val) return null;
  const p = parseInt(val, 10);
  return (isNaN(p) || p <= 0 || p > 65535) ? null : p;
}

function normalizeProtocol(val) {
  if (!val) return 'IP';
  const v = String(val).toUpperCase().trim();
  if (v === '6' || v.includes('TCP')) return 'TCP';
  if (v === '17' || v.includes('UDP')) return 'UDP';
  if (v === '1' || v.includes('ICMP')) return 'ICMP';
  return v;
}

function normalizeAction(raw) {
  if (!raw) return 'UNKNOWN';
  const a = String(raw).toUpperCase().trim();
  if (a.includes('ALLOW') || a.includes('PERMIT') || a.includes('ACCEPT') || a.includes('BUILT') || a.includes('SUCCESS')) {
    return 'ALLOW';
  }
  if (a.includes('DENY') || a.includes('DROP') || a.includes('BLOCK') || a.includes('REJECT') || a.includes('TEARDOWN') || a.includes('FAIL')) {
    return 'DENY';
  }
  return a;
}

function normalizeOutcome(raw) {
  if (!raw) return 'UNKNOWN';
  const o = String(raw).toUpperCase().trim();
  if (o.includes('SUCCESS') || o === 'ALLOW' || o === 'PERMIT' || o === 'OK') return 'SUCCESS';
  if (o.includes('FAIL') || o.includes('DENY') || o.includes('ERROR') || o === 'DROP') return 'FAILURE';
  return 'UNKNOWN';
}

function categorizeEventType(rawType, action) {
  const s = String(rawType).toUpperCase();
  if (s.includes('AUTH') || s.includes('LOGIN') || s.includes('LOGON')) return 'AUTHENTICATION';
  if (s.includes('FIREWALL') || s.includes('TRAFFIC') || s.includes('FLOW') || s.includes('CONNECTION')) {
    return action === 'DENY' ? 'FIREWALL_DENY' : 'NETWORK_TRAFFIC';
  }
  if (s.includes('MALWARE') || s.includes('THREAT') || s.includes('ATTACK') || s.includes('EXPLOIT')) return 'SECURITY_ALERT';
  if (s.includes('HTTP') || s.includes('WEB') || s.includes('ACCESS')) return 'HTTP_REQUEST';
  return 'SYSTEM_LOG';
}
