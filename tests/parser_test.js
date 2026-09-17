import assert from 'assert';
import { createProvenanceRecord, verifyProvenance } from '../server/provenance.js';
import { parseCEF } from '../server/parsers/cef.js';
import { parseSyslog } from '../server/parsers/syslog.js';
import { parseLEEF } from '../server/parsers/leef.js';
import { parseKeyValue } from '../server/parsers/keyvalue.js';
import { parseJSON } from '../server/parsers/json.js';
import { parseWebAccess } from '../server/parsers/webaccess.js';
import { parseCiscoASA } from '../server/parsers/cisco.js';
import { parseLog } from '../server/parsers/index.js';
import { normalizeLog } from '../server/normalizer.js';
import { aiMapper } from '../server/aiMapping.js';

console.log('=== Chetas ULPF Component Verification Tests ===\n');

// 1. Provenance & Cryptographic Integrity
console.log('1. Testing Provenance ID Generator & Traceability...');
const rawSample = 'CEF:0|Palo Alto Networks|PAN-OS|10.0.0|TRAFFIC|allow|1|src=10.0.1.5 dst=8.8.8.8 spt=1234 dpt=53';
const prov = createProvenanceRecord(rawSample, 'test-collector');
assert(prov.provenance_id.startsWith('cht-'), 'Provenance ID must start with cht-');
assert.strictEqual(prov.raw_payload, rawSample, 'Raw payload must be preserved byte-for-byte');
assert(verifyProvenance(rawSample, prov.raw_sha256), 'SHA-256 hash must verify exactly');
console.log('  ✓ Provenance ID generated:', prov.provenance_id);

// 2. Syslog RFC 5424
console.log('2. Testing Syslog RFC 5424 Parser...');
const syslog5424 = '<34>1 2026-09-16T14:30:00.000Z edge-firewall.corp.net sshd 4122 ID47 [exampleSDID@32473 iut="3"] User root logged in';
const parsedSyslog = parseSyslog(syslog5424);
assert.strictEqual(parsedSyslog.format, 'Syslog-RFC5424');
assert.strictEqual(parsedSyslog.app_name, 'sshd');
assert.strictEqual(parsedSyslog.proc_id, '4122');
assert.strictEqual(parsedSyslog.message, 'User root logged in');
console.log('  ✓ Syslog RFC 5424 parsed correctly');

// 3. Syslog RFC 3164
console.log('3. Testing Syslog RFC 3164 Parser...');
const syslog3164 = '<38>Sep 16 14:30:15 gateway-gw01 kernel[512]: DROP IN=eth0 OUT= SRC=198.51.100.4 DST=203.0.113.10 PROTO=TCP';
const parsed3164 = parseSyslog(syslog3164);
assert.strictEqual(parsed3164.format, 'Syslog-RFC3164');
assert.strictEqual(parsed3164.hostname, 'gateway-gw01');
assert.strictEqual(parsed3164.tag, 'kernel');
assert.strictEqual(parsed3164.pid, '512');
console.log('  ✓ Syslog RFC 3164 parsed correctly');

// 4. CEF Parser
console.log('4. Testing CEF Parser...');
const cefRaw = 'CEF:0|Fortinet|FortiGate|6.4.2|0000000013|traffic:forward|3|src=192.168.1.10 dst=1.1.1.1 spt=54123 dpt=443 proto=TCP act=deny msg=Firewall policy violation';
const parsedCef = parseCEF(cefRaw);
assert.strictEqual(parsedCef.format, 'CEF');
assert.strictEqual(parsedCef.vendor, 'Fortinet');
assert.strictEqual(parsedCef.product, 'FortiGate');
assert.strictEqual(parsedCef.attributes.src, '192.168.1.10');
assert.strictEqual(parsedCef.attributes.dst, '1.1.1.1');
assert.strictEqual(parsedCef.attributes.dpt, '443');
assert.strictEqual(parsedCef.attributes.act, 'deny');
console.log('  ✓ CEF parsed correctly');

// 5. LEEF Parser
console.log('5. Testing LEEF Parser...');
const leefRaw = 'LEEF:1.0|Microsoft|MSExchange|2019|LogonFailed|\tsrc=10.1.2.3\tdst=10.1.2.4\tusr=admin\tstatus=failed';
const parsedLeef = parseLEEF(leefRaw);
assert.strictEqual(parsedLeef.format, 'LEEF');
assert.strictEqual(parsedLeef.vendor, 'Microsoft');
assert.strictEqual(parsedLeef.attributes.src, '10.1.2.3');
assert.strictEqual(parsedLeef.attributes.usr, 'admin');
console.log('  ✓ LEEF parsed correctly');

// 6. Key-Value / Fortinet FortiOS Parser
console.log('6. Testing Key-Value / Fortinet FortiOS Parser...');
const kvRaw = 'date=2026-09-16 time=14:22:10 devname="FGT-HQ-01" devid="FG60E1234567" logid="0000000013" type="traffic" srcip=192.168.10.45 srcport=51234 dstip=104.244.42.1 dstport=443 proto=6 action="accept" msg="Traffic allowed"';
const parsedKv = parseKeyValue(kvRaw);
assert.strictEqual(parsedKv.vendor, 'Fortinet');
assert.strictEqual(parsedKv.attributes.srcip, '192.168.10.45');
assert.strictEqual(parsedKv.attributes.dstip, '104.244.42.1');
assert.strictEqual(parsedKv.attributes.dstport, '443');
console.log('  ✓ Key-Value parsed correctly');

// 7. Structured JSON Parser
console.log('7. Testing Structured JSON Parser...');
const jsonRaw = JSON.stringify({
  eventVersion: '1.08',
  eventSource: 'iam.amazonaws.com',
  eventName: 'CreateUser',
  sourceIPAddress: '198.51.100.99',
  userName: 'secops-admin'
});
const parsedJson = parseJSON(jsonRaw);
assert.strictEqual(parsedJson.format, 'JSON');
assert.strictEqual(parsedJson.vendor, 'Amazon Web Services');
assert.strictEqual(parsedJson.attributes.eventName, 'CreateUser');
console.log('  ✓ JSON parsed correctly');

// 8. Web Access Parser
console.log('8. Testing Web Access (Nginx) Parser...');
const nginxRaw = '192.168.1.100 - frank [16/Sep/2026:14:55:36 +0000] "GET /api/v1/checkout HTTP/1.1" 200 2326 "https://corp.net" "Mozilla/5.0"';
const parsedWeb = parseWebAccess(nginxRaw);
assert.strictEqual(parsedWeb.format, 'Web-Access');
assert.strictEqual(parsedWeb.attributes.client_ip, '192.168.1.100');
assert.strictEqual(parsedWeb.attributes.status_code, 200);
assert.strictEqual(parsedWeb.attributes.http_method, 'GET');
console.log('  ✓ Web Access parsed correctly');

// 9. Cisco ASA Parser
console.log('9. Testing Cisco ASA Parser...');
const asaRaw = '%ASA-4-106023: Deny tcp src outside:198.51.100.5/4532 dst inside:192.168.1.10/80 by access-group "OUTSIDE-IN"';
const parsedAsa = parseCiscoASA(asaRaw);
assert.strictEqual(parsedAsa.format, 'Cisco-ASA');
assert.strictEqual(parsedAsa.vendor, 'Cisco Systems');
assert.strictEqual(parsedAsa.attributes.src_ip, '198.51.100.5');
assert.strictEqual(parsedAsa.attributes.src_port, 4532);
assert.strictEqual(parsedAsa.attributes.dst_ip, '192.168.1.10');
assert.strictEqual(parsedAsa.attributes.dst_port, 80);
assert.strictEqual(parsedAsa.action, 'DENY');
console.log('  ✓ Cisco ASA parsed correctly');

// 10. Auto-Detector Router
console.log('10. Testing Auto-Detection & Router on Wrapped Syslog-CEF...');
const wrappedSyslogCef = '<134>1 2026-09-16T12:00:00Z firewall.net CEF:0|Palo Alto Networks|PAN-OS|10.2.0|TRAFFIC|deny|7|src=10.0.0.1 dst=10.0.0.2';
const autoDetected = parseLog(wrappedSyslogCef);
assert.strictEqual(autoDetected.format, 'CEF');
assert.strictEqual(autoDetected.vendor, 'Palo Alto Networks');
assert(autoDetected.transport.startsWith('Syslog'));
console.log('  ✓ Auto-detection unwrapped Syslog-CEF correctly');

// 11. Universal Taxonomy Normalization
console.log('11. Testing Universal Normalizer...');
const normProv = createProvenanceRecord(cefRaw, 'edge-collector');
const normParsed = parseLog(cefRaw);
const normalized = normalizeLog(normParsed, normProv);
assert.strictEqual(normalized.provenance_id, normProv.provenance_id);
assert.strictEqual(normalized.source_ip, '192.168.1.10');
assert.strictEqual(normalized.destination_ip, '1.1.1.1');
assert.strictEqual(normalized.destination_port, 443);
assert.strictEqual(normalized.action, 'DENY');
assert.strictEqual(normalized.outcome, 'FAILURE');
assert.strictEqual(normalized.severity, 'LOW');
assert.strictEqual(normalized.raw_ref.raw_sha256, normProv.raw_sha256);
console.log('  ✓ Normalized event correctly created with complete provenance');

// 12. AI Mapping Heuristic & Dynamic Field Learning
console.log('12. Testing AI Field Mapping Engine...');
const unmappedKey = 'client_addr_v4';
const suggestion = aiMapper.evaluateUnknownField(unmappedKey, '203.0.113.88');
assert(suggestion, 'AI Engine should produce a suggestion for client_addr_v4');
assert.strictEqual(suggestion.canonical_field, 'source_ip');
assert(suggestion.confidence >= 0.8, 'Confidence should be high');
console.log(`  ✓ AI suggested: ${suggestion.raw_key} -> ${suggestion.canonical_field} (${Math.round(suggestion.confidence * 100)}%)`);

aiMapper.approveMapping(suggestion.id);
assert.strictEqual(aiMapper.resolveKey(unmappedKey), 'source_ip', 'Approved mapping must now resolve dynamically');
console.log('  ✓ Approved mapping successfully applied to dynamic registry');

console.log('\n=== ALL 12 COMPONENT TESTS PASSED SUCCESSFULLY! ===\n');
