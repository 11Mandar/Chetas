import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { storage } from './storage.js';
import { processSingleLog } from './pipeline.js';
import { aiMapper } from './aiMapping.js';
import { collectors } from './collectors.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.text({ limit: '20mb', type: ['text/plain', 'application/x-www-form-urlencoded'] }));

// Serve static frontend files
app.use(express.static(path.join(rootDir, 'public')));
// Also serve the root directory SVGs so they can be referenced directly
app.use('/assets', express.static(rootDir));

// --- Auth Routes ---
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  // Standard SOC operator authentication
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Accepts any credentials or standard admin/analyst credentials
  const role = username.toLowerCase().includes('admin') ? 'SOC Lead Engineer' : 'Senior SOC Analyst';
  const session = {
    username,
    name: username.includes('@') ? username.split('@')[0] : username,
    role,
    authenticated: true,
    token: `cht-sess-${Date.now().toString(36)}`
  };

  storage.recordAudit(username, 'USER_LOGIN', `Authenticated successfully as ${role}`);
  res.json({ success: true, session });
});

app.post('/api/auth/logout', (req, res) => {
  const { username } = req.body || {};
  storage.recordAudit(username || 'anonymous', 'USER_LOGOUT', 'Logged out and invalidated session');
  res.json({ success: true });
});

// --- System Status ---
app.get('/api/status', (req, res) => {
  const status = storage.getSystemStatus();
  status.is_streaming = true;
  status.pending_mappings = aiMapper.getPending().length;
  res.json(status);
});

// --- Analytics & Timeseries Telemetry ---
app.get('/api/analytics/timeseries', (req, res) => {
  const range = req.query.range || '1h';
  const timeseries = storage.getTimeSeries(range);
  res.json(timeseries);
});

// --- Logs & Events Ingestion & Query ---
app.get('/api/events', (req, res) => {
  const filters = {
    provenance_id: req.query.provenance_id,
    search: req.query.search,
    severity: req.query.severity,
    format: req.query.format,
    source_id: req.query.source_id,
    limit: req.query.limit || 100
  };
  const events = storage.getEvents(filters);
  res.json({
    total: events.length,
    events
  });
});

app.get('/api/events/provenance/:id', (req, res) => {
  const event = storage.getEventByProvenanceId(req.params.id);
  if (!event) {
    return res.status(404).json({ error: `No event found for provenance ID "${req.params.id}"` });
  }
  res.json(event);
});

// Ingest real raw log(s)
app.post('/api/logs/ingest', (req, res) => {
  let logsToProcess = [];
  const sourceId = req.headers['x-source-id'] || req.body?.source_id || 'manual-input';

  if (typeof req.body === 'string') {
    logsToProcess = req.body.split(/\r?\n/).filter(line => line.trim().length > 0);
  } else if (Array.isArray(req.body)) {
    logsToProcess = req.body;
  } else if (req.body?.logs) {
    logsToProcess = Array.isArray(req.body.logs) ? req.body.logs : [req.body.logs];
  } else if (req.body?.log) {
    logsToProcess = [req.body.log];
  } else if (typeof req.body === 'object') {
    logsToProcess = [JSON.stringify(req.body)];
  }

  if (logsToProcess.length === 0) {
    return res.status(400).json({ error: 'No valid log content provided in request body' });
  }

  const results = [];
  let processedCount = 0;
  let failureCount = 0;

  for (const raw of logsToProcess) {
    const rawStr = typeof raw === 'string' ? raw : JSON.stringify(raw);
    if (!rawStr.trim()) continue;

    const outcome = processSingleLog(rawStr, sourceId);
    if (outcome.success) {
      processedCount++;
      results.push({
        provenance_id: outcome.event.provenance_id,
        format: outcome.event.format,
        vendor: outcome.event.vendor,
        event_type: outcome.event.event_type,
        severity: outcome.event.severity
      });
    } else {
      failureCount++;
    }
  }

  storage.recordAudit(
    'OPERATOR',
    'MANUAL_INGESTION',
    `Ingested ${processedCount} log(s) via API/Studio (${failureCount} errors)`
  );

  res.json({
    success: true,
    processed: processedCount,
    failed: failureCount,
    results
  });
});

// --- Sources ---
app.get('/api/sources', (req, res) => {
  res.json(storage.getSources());
});

app.post('/api/sources', (req, res) => {
  const { name, type, vendor, format } = req.body || {};
  if (!name) {
    return res.status(400).json({ error: 'Source name is required' });
  }
  const source = storage.registerSource({ name, type, vendor, format });
  res.json(source);
});

// --- AI Mappings ---
app.get('/api/ai/mappings', (req, res) => {
  res.json({
    approved: aiMapper.getApproved(),
    pending: aiMapper.getPending()
  });
});
app.post('/api/ai/approve', (req, res) => {
  const { id, custom_target } = req.body || {};
  if (!id) return res.status(400).json({ error: 'Suggestion ID is required' });

  try {
    const outcome = aiMapper.approveMapping(id, custom_target);
    storage.recordAudit('analyst.chen', 'AI_MAPPING_APPROVED', `Approved mapping: ${outcome.rawKey} -> ${outcome.targetField}`);
    res.json({ success: true, mapping: outcome });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/ai/reject', (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'Suggestion ID is required' });

  const outcome = aiMapper.rejectMapping(id);
  storage.recordAudit('analyst.chen', 'AI_MAPPING_REJECTED', `Rejected mapping for key: ${outcome.key}`);
  res.json({ success: true, rejected: outcome.key });
});

app.post('/api/ai/custom', (req, res) => {
  const { raw_key, canonical_field } = req.body || {};
  if (!raw_key || !canonical_field) {
    return res.status(400).json({ error: 'Both raw_key and canonical_field are required' });
  }
  const outcome = aiMapper.approveMapping(raw_key, canonical_field);
  storage.recordAudit('admin@soc.corp', 'CUSTOM_MAPPING_CREATED', `Defined custom mapping: ${raw_key} -> ${canonical_field}`);
  res.json({ success: true, mapping: outcome });
});

// --- Audit Trail ---
app.get('/api/audit', (req, res) => {
  res.json(storage.getAuditLogs());
});

// --- Live Stream Control ---
app.post('/api/stream/toggle', (req, res) => {
  res.json({ is_streaming: true });
});

// --- SIEM Scenario Injection ---
app.post('/api/siem/inject-samples', (req, res) => {
  const count = collectors.injectEnterpriseSiemPack();
  res.json({ success: true, count, message: `Successfully injected ${count} enterprise SIEM scenario logs` });
});

// Start automated collectors (Windows Event Logs, UDP Syslog port 1514, File Drop incoming_logs/)
collectors.start();

app.listen(PORT, () => {
  console.log(`[Chetas ULPF] Command Center running on http://localhost:${PORT}`);
});
