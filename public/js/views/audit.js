import { api } from '../api.js';
import { exportTableToCSV } from '../components/exporter.js';
import { formatLocalDateTime, escapeHtml } from '../utils.js';

/**
 * Audit Trail View Controller
 * Clean, dense, monospace-heavy activity log table with CSV export.
 */

export const auditView = {
  logs: [],

  init() {
    this.bindEvents();
    this.loadAudit();
  },

  bindEvents() {
    document.getElementById('btnExportAudit')?.addEventListener('click', () => {
      exportTableToCSV('audit', this.logs);
    });
  },

  async loadAudit() {
    try {
      this.logs = await api.getAudit();
      this.render();
    } catch (e) {
      console.error('Error loading audit log', e);
    }
  },

  render() {
    const tbody = document.getElementById('auditTableBody');
    if (!tbody) return;

    if (this.logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">No audit events recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = this.logs.map(log => `
      <tr>
        <td class="timestamp">${formatLocalDateTime(log.timestamp)}</td>
        <td class="mono" style="color: var(--accent-cyan); font-weight: 600;">${escapeHtml(log.actor)}</td>
        <td>
          <span class="mono badge-mono" style="font-size: 10px; padding: 2px 6px; border-radius: 3px; background: var(--bg-surface-elevated); border: 1px solid var(--border-subtle); color: var(--text-primary);">
            ${escapeHtml(log.action)}
          </span>
        </td>
        <td class="mono" style="color: var(--text-secondary); max-width: 400px; white-space: normal; word-break: break-word;">
          ${escapeHtml(log.details)}
        </td>
        <td class="mono" style="color: var(--text-muted);">${escapeHtml(log.ip_address || '127.0.0.1')}</td>
      </tr>
    `).join('');
  }
};
