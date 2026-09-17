/**
 * Structured JSON Log Parser (AWS CloudTrail, Kubernetes, Suricata EVE, CrowdStrike, Zeek)
 */

export function isJSON(logStr) {
  const str = logStr.trim();
  return (str.startsWith('{') && str.endsWith('}')) || (str.startsWith('[') && str.endsWith(']'));
}

export function parseJSON(raw) {
  const str = raw.trim();
  let parsed;
  try {
    parsed = JSON.parse(str);
  } catch (err) {
    throw new Error(`Failed to parse JSON log: ${err.message}`);
  }

  // Handle arrays by taking first element or wrapping
  const data = Array.isArray(parsed) ? parsed[0] : parsed;

  let vendor = data.vendor || 'Generic Cloud/App';
  let product = data.product || 'JSON Service';

  // Vendor heuristics
  if (data.eventSource && (data.awsRegion || data.eventVersion)) {
    vendor = 'Amazon Web Services';
    product = `AWS ${data.eventSource.replace('.amazonaws.com', '').toUpperCase()}`;
  } else if (data.event_type && data.proto && data.flow_id) {
    vendor = 'Suricata';
    product = 'Suricata IDS/EVE';
  } else if (data.kind === 'Event' && data.apiVersion?.includes('k8s')) {
    vendor = 'Kubernetes';
    product = 'K8s Audit';
  } else if (data.EventID || data.Channel || (data.System && data.EventData)) {
    vendor = data.vendor || 'Microsoft Windows';
    product = data.product || 'Windows EventLog';
  }

  return {
    format: 'JSON',
    vendor,
    product,
    attributes: data
  };
}
