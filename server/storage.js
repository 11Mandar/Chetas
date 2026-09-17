/**
 * In-Memory & Persistent State & Provenance Index Engine
 * Manages connected sources, processed logs, raw payloads, audit trail, and metrics.
 */

class ChetasStorage {
  constructor() {
    this.events = []; // Ordered normalized events (only real events)
    this.eventsByProvenance = new Map(); // O(1) Provenance lookup
    this.sources = new Map(); // Connected log sources
    this.auditLogs = []; // System audit activity trail
    this.metrics = {
      totalProcessed: 0,
      totalErrors: 0,
      eventsLastMinute: [],
      startTime: Date.now()
    };

    this.initAuditTrail();
  }

  initAuditTrail() {
    this.recordAudit('SYSTEM', 'SYSTEM_STARTUP', 'Chetas ULPF Engine initialized with universal taxonomy schema', '127.0.0.1');
  }

  recordAudit(actor, action, details, ip = '127.0.0.1') {
    const entry = {
      id: `aud-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      actor,
      action,
      details,
      ip_address: ip
    };
    this.auditLogs.unshift(entry);
    if (this.auditLogs.length > 500) this.auditLogs.pop();
    return entry;
  }

  getAuditLogs() {
    return this.auditLogs;
  }

  addEvent(normalizedEvent, rawPayload) {
    const record = {
      ...normalizedEvent,
      raw_payload: rawPayload
    };

    // Prepend for real-time order (newest first)
    this.events.unshift(record);
    this.eventsByProvenance.set(record.provenance_id, record);

    // Keep memory bounded to latest 5,000 events
    if (this.events.length > 5000) {
      const removed = this.events.pop();
      if (removed) this.eventsByProvenance.delete(removed.provenance_id);
    }

    // Update metrics
    this.metrics.totalProcessed++;
    const now = Date.now();
    this.metrics.eventsLastMinute.push(now);

    // Update source stats
    const sourceId = normalizedEvent.raw_ref?.source_id;
    if (sourceId && this.sources.has(sourceId)) {
      const src = this.sources.get(sourceId);
      src.total_events = (src.total_events || 0) + 1;
      src.last_seen = new Date().toISOString();
      src.status = 'active';
    }

    return record;
  }

  recordError() {
    this.metrics.totalErrors++;
  }

  getEventByProvenanceId(provenanceId) {
    if (!provenanceId) return null;
    const cleanId = provenanceId.trim().toLowerCase();

    // Exact match
    for (const [id, event] of this.eventsByProvenance.entries()) {
      if (id.toLowerCase() === cleanId) return event;
    }

    // Partial match
    for (const [id, event] of this.eventsByProvenance.entries()) {
      if (id.toLowerCase().includes(cleanId)) return event;
    }

    return null;
  }

  getEvents(filters = {}) {
    let result = [...this.events];

    if (filters.provenance_id) {
      const pid = filters.provenance_id.toLowerCase().trim();
      result = result.filter(e => e.provenance_id.toLowerCase().includes(pid));
    }

    if (filters.search) {
      const q = filters.search.toLowerCase().trim();
      result = result.filter(e => 
        e.provenance_id.toLowerCase().includes(q) ||
        (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
        (e.destination_ip && e.destination_ip.toLowerCase().includes(q)) ||
        (e.message && e.message.toLowerCase().includes(q)) ||
        (e.vendor && e.vendor.toLowerCase().includes(q)) ||
        (e.user_name && e.user_name.toLowerCase().includes(q))
      );
    }

    if (filters.severity && filters.severity !== 'ALL') {
      result = result.filter(e => e.severity.toUpperCase() === filters.severity.toUpperCase());
    }

    if (filters.format && filters.format !== 'ALL') {
      result = result.filter(e => e.format.toUpperCase() === filters.format.toUpperCase());
    }

    if (filters.source_id && filters.source_id !== 'ALL') {
      result = result.filter(e => e.raw_ref?.source_id === filters.source_id);
    }

    const limit = filters.limit ? parseInt(filters.limit, 10) : 100;
    return result.slice(0, limit);
  }

  getSources() {
    return Array.from(this.sources.values());
  }

  getSource(id) {
    return this.sources.get(id);
  }

  registerSource(sourceData) {
    const id = sourceData.id || `src-${sourceData.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}-${Date.now().toString(36)}`;
    const source = {
      id,
      name: sourceData.name,
      type: sourceData.type || 'Custom Device',
      vendor: sourceData.vendor || 'Generic',
      format: sourceData.format || 'Auto-Detect',
      status: 'active',
      eps: 0,
      total_events: 0,
      created_at: new Date().toISOString(),
      last_seen: new Date().toISOString()
    };
    this.sources.set(id, source);
    this.recordAudit('admin@soc.corp', 'SOURCE_REGISTERED', `Connected new log source: ${source.name} (${source.vendor})`);
    return source;
  }

  getTimeSeries(range = '1h') {
    const now = Date.now();
    let windowMs;
    let bucketMs;

    switch (range.toLowerCase()) {
      case '15m':
        windowMs = 15 * 60 * 1000;
        bucketMs = 60 * 1000; // 1 min buckets (15 buckets)
        break;
      case '6h':
        windowMs = 6 * 3600 * 1000;
        bucketMs = 10 * 60 * 1000; // 10 min buckets (36 buckets)
        break;
      case '24h':
        windowMs = 24 * 3600 * 1000;
        bucketMs = 30 * 60 * 1000; // 30 min buckets (48 buckets)
        break;
      case 'all': {
        const earliest = this.events.reduce((min, e) => {
          const t = new Date(e.raw_ref?.ingest_timestamp || e.timestamp).getTime();
          return !isNaN(t) && t < min ? t : min;
        }, now);
        windowMs = Math.max(now - earliest, 3600 * 1000); // at least 1h
        bucketMs = Math.max(Math.ceil(windowMs / 30), 60 * 1000);
        break;
      }
      case '1h':
      default:
        windowMs = 60 * 60 * 1000;
        bucketMs = 2 * 60 * 1000; // 2 min buckets (30 buckets)
        break;
    }

    const startTime = now - windowMs;
    const bucketCount = Math.max(1, Math.ceil(windowMs / bucketMs));
    const buckets = [];

    for (let i = 0; i < bucketCount; i++) {
      const bStart = startTime + i * bucketMs;
      const bEnd = bStart + bucketMs;
      const dateObj = new Date(bStart);
      const hours = String(dateObj.getHours()).padStart(2, '0');
      const mins = String(dateObj.getMinutes()).padStart(2, '0');
      const label = `${hours}:${mins}`;

      buckets.push({
        start_time: new Date(bStart).toISOString(),
        end_time: new Date(bEnd).toISOString(),
        label,
        count: 0,
        severities: {
          CRITICAL: 0,
          HIGH: 0,
          WARNING: 0,
          LOW: 0,
          INFORMATIONAL: 0
        },
        formats: {}
      });
    }

    let totalInWindow = 0;
    let criticalCount = 0;

    for (const ev of this.events) {
      const t = new Date(ev.raw_ref?.ingest_timestamp || ev.timestamp).getTime();
      if (isNaN(t) || t < startTime || t > now + 60000) continue;

      const idx = Math.min(bucketCount - 1, Math.max(0, Math.floor((t - startTime) / bucketMs)));
      const b = buckets[idx];
      b.count++;
      totalInWindow++;

      const sev = (ev.severity || 'INFORMATIONAL').toUpperCase();
      if (b.severities[sev] !== undefined) {
        b.severities[sev]++;
      } else {
        b.severities[sev] = 1;
      }
      if (sev === 'CRITICAL' || sev === 'HIGH') {
        criticalCount++;
      }

      const fmt = ev.format || 'Unknown';
      b.formats[fmt] = (b.formats[fmt] || 0) + 1;
    }

    const peakRate = buckets.reduce((max, b) => Math.max(max, b.count), 0);
    const avgRate = bucketCount > 0 ? (totalInWindow / bucketCount).toFixed(1) : '0.0';

    return {
      range,
      window_ms: windowMs,
      bucket_ms: bucketMs,
      bucket_count: bucketCount,
      total_logs: totalInWindow,
      peak_rate: peakRate,
      avg_rate: parseFloat(avgRate),
      critical_count: criticalCount,
      buckets
    };
  }

  getSystemStatus() {
    const now = Date.now();
    // Prune events older than 60 seconds for live EPS calculation
    this.metrics.eventsLastMinute = this.metrics.eventsLastMinute.filter(t => now - t <= 60000);
    const eps = Math.round(this.metrics.eventsLastMinute.length / 60);

    const activeSources = Array.from(this.sources.values()).filter(s => {
      if (!s.last_seen) return false;
      const diff = now - new Date(s.last_seen).getTime();
      return diff < 300000; // active in last 5 minutes
    }).length;

    return {
      sources_count: this.sources.size,
      active_sources: activeSources,
      events_per_second: eps,
      total_processed: this.metrics.totalProcessed,
      error_count: this.metrics.totalErrors,
      uptime_seconds: Math.floor((now - this.metrics.startTime) / 1000)
    };
  }
}

export const storage = new ChetasStorage();
