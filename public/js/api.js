/**
 * Chetas ULPF Client API Service
 */

export const api = {
  async getStatus() {
    const res = await fetch('/api/status');
    return res.json();
  },

  async getTimeSeries(range = '1h') {
    const res = await fetch(`/api/analytics/timeseries?range=${encodeURIComponent(range)}`);
    return res.json();
  },

  async getEvents(filters = {}) {
    const params = new URLSearchParams();
    if (filters.provenance_id) params.set('provenance_id', filters.provenance_id);
    if (filters.search) params.set('search', filters.search);
    if (filters.severity) params.set('severity', filters.severity);
    if (filters.format) params.set('format', filters.format);
    if (filters.source_id) params.set('source_id', filters.source_id);
    if (filters.limit) params.set('limit', filters.limit);

    const res = await fetch(`/api/events?${params.toString()}`);
    return res.json();
  },

  async getEventByProvenance(provenanceId) {
    const res = await fetch(`/api/events/provenance/${encodeURIComponent(provenanceId)}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `No event found for provenance ID ${provenanceId}`);
    }
    return res.json();
  },

  async ingestLogs(logsText, sourceId = 'manual-studio') {
    const res = await fetch('/api/logs/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'x-source-id': sourceId
      },
      body: logsText
    });
    return res.json();
  },

  async getSources() {
    const res = await fetch('/api/sources');
    return res.json();
  },

  async addSource(sourceData) {
    const res = await fetch('/api/sources', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sourceData)
    });
    return res.json();
  },

  async getAIMappings() {
    const res = await fetch('/api/ai/mappings');
    return res.json();
  },

  async approveMapping(id, customTarget = null) {
    const res = await fetch('/api/ai/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, custom_target: customTarget })
    });
    return res.json();
  },

  async rejectMapping(id) {
    const res = await fetch('/api/ai/reject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    return res.json();
  },

  async addCustomMapping(rawKey, canonicalField) {
    const res = await fetch('/api/ai/custom', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_key: rawKey, canonical_field: canonicalField })
    });
    return res.json();
  },

  async getAudit() {
    const res = await fetch('/api/audit');
    return res.json();
  },

  async toggleStream() {
    const res = await fetch('/api/stream/toggle', { method: 'POST' });
    return res.json();
  },

  async login(username, password) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    return res.json();
  },

  async logout(username) {
    const res = await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    return res.json();
  },

  async injectSiemSamples() {
    const res = await fetch('/api/siem/inject-samples', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    return res.json();
  }
};
