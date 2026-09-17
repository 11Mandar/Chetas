import { api } from '../api.js';
import { drawer } from '../components/drawer.js';
import { exportTableToCSV } from '../components/exporter.js';
import { toast } from '../components/toast.js';
import { formatLocalTime, formatLocalDateTime, escapeHtml } from '../utils.js';

/**
 * Logs View Controller
 * Manages live telemetry table with fade+slide animations, provenance search,
 * interactive Ingestion Studio, live streaming toggle, and CSV export.
 */

export const logsView = {
  events: [],
  filters: {
    provenance_id: '',
    severity: 'ALL',
    format: 'ALL'
  },
  isStreaming: true,

  init() {
    this.bindEvents();
    this.loadLogs();
  },

  bindEvents() {
    // Dedicated Provenance Search with live filtering and enter-key jump
    const provInput = document.getElementById('logSearchProvenance');
    provInput?.addEventListener('input', (e) => {
      this.filters.provenance_id = e.target.value.trim();
      this.loadLogs();
    });

    provInput?.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter') {
        const query = e.target.value.trim();
        if (!query) return;
        try {
          const match = await api.getEventByProvenance(query);
          drawer.openEvent(match);
        } catch (err) {
          toast.error(`No event found for provenance ID "${query}"`);
        }
      }
    });

    // Severity Filter
    document.getElementById('logFilterSeverity')?.addEventListener('change', (e) => {
      this.filters.severity = e.target.value;
      this.loadLogs();
    });

    // Format Filter
    document.getElementById('logFilterFormat')?.addEventListener('change', (e) => {
      this.filters.format = e.target.value;
      this.loadLogs();
    });

    // Inject SIEM Telemetry Pack
    document.getElementById('btnLoadSamplePack')?.addEventListener('click', async () => {
      const btn = document.getElementById('btnLoadSamplePack');
      try {
        if (btn) btn.disabled = true;
        const res = await api.injectSiemSamples();
        toast.success(`Injected ${res.count || 17} enterprise SIEM events (Firewall, Auth, Web, EDR)!`);
        await this.loadLogs();
      } catch (err) {
        toast.error(`Injection failed: ${err.message}`);
      } finally {
        if (btn) btn.disabled = false;
      }
    });

    // Export CSV
    document.getElementById('btnExportLogs')?.addEventListener('click', () => {
      exportTableToCSV('logs', this.events);
    });

    // Toggle Stream
    document.getElementById('btnToggleStream')?.addEventListener('click', async () => {
      const res = await api.toggleStream();
      this.isStreaming = res.is_streaming;
      const btn = document.getElementById('btnToggleStream');
      if (btn) {
        btn.innerHTML = this.isStreaming
          ? '<span>⏸</span><span>Pause Stream</span>'
          : '<span>▶</span><span>Resume Stream</span>';
      }
      toast.info(`Live perimeter traffic stream ${this.isStreaming ? 'resumed' : 'paused'}`);
    });

    // Ingestion Studio Modal
    document.getElementById('btnOpenIngestModal')?.addEventListener('click', () => {
      document.getElementById('ingestModal')?.classList.add('open');
    });

    document.getElementById('btnCloseIngestModal')?.addEventListener('click', () => {
      document.getElementById('ingestModal')?.classList.remove('open');
    });

    // File upload handler
    document.getElementById('ingestFileInput')?.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (evt) => {
        document.getElementById('ingestRawTextarea').value = evt.target.result;
        toast.info(`Loaded file: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
      };
      reader.readAsText(file);
    });

    // Process Raw Log Form Submit
    document.getElementById('ingestLogForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const rawText = document.getElementById('ingestRawTextarea').value.trim();
      const sourceId = document.getElementById('ingestSourceSelect').value;

      if (!rawText) {
        toast.error('Please enter raw log content');
        return;
      }

      try {
        const res = await api.ingestLogs(rawText, sourceId);
        if (res.success) {
          toast.success(`Successfully parsed & normalized ${res.processed} log(s) with lossless provenance!`);
          document.getElementById('ingestModal')?.classList.remove('open');
          document.getElementById('ingestRawTextarea').value = '';
          await this.loadLogs();

          // If single log ingested, open right drawer immediately for inspection
          if (res.results && res.results.length === 1) {
            const first = await api.getEventByProvenance(res.results[0].provenance_id);
            drawer.openEvent(first);
          }
        }
      } catch (err) {
        toast.error(`Ingestion error: ${err.message}`);
      }
    });

    // Row Click -> Open Right Drawer (Split View)
    document.getElementById('logsTableBody')?.addEventListener('click', (e) => {
      const row = e.target.closest('tr');
      if (!row) return;
      const provId = row.getAttribute('data-prov');
      const event = this.events.find(ev => ev.provenance_id === provId);
      if (event) {
        drawer.openEvent(event);
      }
    });
  },

  async loadLogs() {
    try {
      const queryParams = { ...this.filters, limit: 250 };
      const data = await api.getEvents(queryParams);
      this.events = data.events || [];
      this.render();
    } catch (e) {
      console.error('Error fetching logs', e);
    }
  },

  render() {
    const tbody = document.getElementById('logsTableBody');
    if (!tbody) return;

    if (this.events.length === 0) {
      const query = this.filters.provenance_id;
      if (query) {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" style="text-align:center; color: var(--text-secondary); padding: 32px;">
              <div style="font-size: 14px; color: var(--status-amber); margin-bottom: 6px;">⚠ No event found for provenance ID "${escapeHtml(query)}"</div>
              <div style="font-size: 11px; color: var(--text-muted);">Ensure the trace identifier is exact or clear the search filter.</div>
            </td>
          </tr>
        `;
      } else {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" style="text-align:center; color: var(--text-muted); padding: 32px;">
              No matching log records found for the selected filter criteria.
            </td>
          </tr>
        `;
      }
      return;
    }

    tbody.innerHTML = this.events.map((e, idx) => {
      const sourceDisplay = e.source_ip 
        ? `${escapeHtml(e.source_ip)} → ${escapeHtml(e.destination_ip || '-')}`
        : `<span class="source-host-tag" title="${escapeHtml(e.vendor || '')}">${escapeHtml(e.source_host || e.product || e.vendor || 'Host')}</span>`;

      return `
        <tr class="${idx === 0 ? 'new-row' : ''}" data-prov="${e.provenance_id}" style="cursor: pointer;">
          <td class="timestamp" title="${formatLocalDateTime(e.timestamp)}">${formatLocalTime(e.timestamp)}</td>
          <td class="provenance-cell mono">${e.provenance_id}</td>
          <td><span class="format-badge">${e.format}</span></td>
          <td><span class="severity-pill ${e.severity}">${e.severity}</span></td>
          <td class="mono">${sourceDisplay}</td>
          <td class="mono"><span class="action-pill ${e.action}">${e.action || '-'}</span></td>
          <td class="mono" style="color: var(--text-secondary);">${e.user_name || '-'}</td>
          <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-secondary);">
            ${escapeHtml(e.message)}
          </td>
        </tr>
      `;
    }).join('');
  }
};
