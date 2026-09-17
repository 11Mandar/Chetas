import { api } from '../api.js';
import { drawer } from '../components/drawer.js';
import { exportTableToCSV } from '../components/exporter.js';
import { toast } from '../components/toast.js';
import { formatLocalTime, formatLocalDateTime } from '../utils.js';

/**
 * Sources View Controller
 */

export const sourcesView = {
  sources: [],

  init() {
    this.bindEvents();
    this.loadSources();
  },

  bindEvents() {
    document.getElementById('btnExportSources')?.addEventListener('click', () => {
      exportTableToCSV('sources', this.sources);
    });

    document.getElementById('btnAddSourceModalOpen')?.addEventListener('click', () => {
      document.getElementById('addSourceModal')?.classList.add('open');
    });

    document.getElementById('btnAddSourceModalClose')?.addEventListener('click', () => {
      document.getElementById('addSourceModal')?.classList.remove('open');
    });

    document.getElementById('addSourceForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('newSourceName').value.trim();
      const type = document.getElementById('newSourceType').value.trim();
      const vendor = document.getElementById('newSourceVendor').value.trim();
      const format = document.getElementById('newSourceFormat').value;

      if (!name) return;

      try {
        const newSrc = await api.addSource({ name, type, vendor, format });
        toast.success(`Connected source: ${newSrc.name}`);
        document.getElementById('addSourceModal')?.classList.remove('open');
        document.getElementById('addSourceForm')?.reset();
        await this.loadSources();
      } catch (err) {
        toast.error(`Failed to add source: ${err.message}`);
      }
    });

    // Row click -> Right Drawer
    document.getElementById('sourcesTableBody')?.addEventListener('click', (e) => {
      const row = e.target.closest('tr');
      if (!row) return;
      const srcId = row.getAttribute('data-id');
      const src = this.sources.find(s => s.id === srcId);
      if (src) {
        drawer.openSource(src);
      }
    });
  },

  async loadSources() {
    try {
      this.sources = await api.getSources();
      this.render();
    } catch (e) {
      console.error('Error loading sources', e);
    }
  },

  render() {
    const tbody = document.getElementById('sourcesTableBody');
    if (!tbody) return;

    if (this.sources.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted); padding: 24px;">No log sources connected. Click "Add Source" to register one.</td></tr>`;
      return;
    }

    tbody.innerHTML = this.sources.map(s => `
      <tr data-id="${s.id}">
        <td class="mono" style="font-weight: 600; color: var(--text-highlight);">${s.name}</td>
        <td>${s.type}</td>
        <td class="mono">${s.vendor}</td>
        <td><span class="format-badge">${s.format}</span></td>
        <td>
          <span class="status-dot green" style="margin-right: 6px;"></span>
          <span class="mono" style="font-size: 11px; text-transform: uppercase;">${s.status}</span>
        </td>
        <td class="mono" style="color: var(--status-green);">${s.eps || 0} EPS</td>
        <td class="mono">${(s.total_events || 0).toLocaleString()}</td>
        <td class="timestamp" title="${formatLocalDateTime(s.last_seen)}">${s.last_seen ? formatLocalTime(s.last_seen) : 'Active'}</td>
      </tr>
    `).join('');
  }
};
