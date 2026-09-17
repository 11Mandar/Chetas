import { toast } from './toast.js';
import { formatLocalDateTime, escapeHtml } from '../utils.js';

/**
 * Contextual Right Sliding Drawer Controller
 * Displays Side-by-Side Raw vs Normalized Event Records with Provenance Trace
 */

let backdropEl = null;
let drawerEl = null;

function ensureElements() {
  if (!backdropEl) {
    backdropEl = document.getElementById('drawerBackdrop');
  }
  if (!drawerEl) {
    drawerEl = document.getElementById('rightDrawer');
  }
}

export const drawer = {
  openEvent(event) {
    ensureElements();
    if (!drawerEl || !backdropEl) return;

    const titleEl = document.getElementById('drawerTitle');
    const bodyEl = document.getElementById('drawerBody');

    titleEl.innerHTML = `
      <span>EVENT DETAIL</span>
      <span class="wordmark-badge">${event.format || 'LOG'}</span>
    `;

    const rawStr = event.raw_payload || (event.raw_ref && event.raw_ref.raw_payload) || JSON.stringify(event, null, 2);
    const normalizedCopy = { ...event };
    delete normalizedCopy.raw_payload;

    bodyEl.innerHTML = `
      <div class="provenance-banner">
        <div>
          <div style="font-size: 10px; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.06em; margin-bottom: 3px;">CRYPTOGRAPHIC PROVENANCE TRACE ID</div>
          <div class="provenance-id-val">${event.provenance_id}</div>
        </div>
        <button class="btn btn-secondary btn-sm" id="btnCopyProvenance">Copy ID</button>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 16px;">
        <div class="panel" style="padding: 10px;">
          <div style="font-size: 10px; color: var(--text-secondary);">TIMESTAMP (LOCAL)</div>
          <div class="mono" style="font-weight: 600; font-size: 11px; margin-top: 4px; color: var(--accent-cyan);">${formatLocalDateTime(event.timestamp)}</div>
        </div>
        <div class="panel" style="padding: 10px;">
          <div style="font-size: 10px; color: var(--text-secondary);">SOURCE IP</div>
          <div class="mono" style="font-weight: 600; font-size: 11px; margin-top: 4px; color: #10B981;">${event.source_ip || (event.source_host ? `${event.source_host}` : '-')}</div>
        </div>
        <div class="panel" style="padding: 10px;">
          <div style="font-size: 10px; color: var(--text-secondary);">DESTINATION IP</div>
          <div class="mono" style="font-weight: 600; font-size: 11px; margin-top: 4px; color: var(--accent-cyan);">${event.destination_ip || '-'}</div>
        </div>
        <div class="panel" style="padding: 10px;">
          <div style="font-size: 10px; color: var(--text-secondary);">VENDOR</div>
          <div class="mono" style="font-weight: 600; font-size: 11px; margin-top: 4px;">${event.vendor || 'Unknown'}</div>
        </div>
        <div class="panel" style="padding: 10px;">
          <div style="font-size: 10px; color: var(--text-secondary);">PRODUCT</div>
          <div class="mono" style="font-weight: 600; font-size: 11px; margin-top: 4px;">${event.product || 'Appliance'}</div>
        </div>
        <div class="panel" style="padding: 10px;">
          <div style="font-size: 10px; color: var(--text-secondary);">SEVERITY</div>
          <div style="margin-top: 4px;"><span class="severity-pill ${event.severity}">${event.severity}</span></div>
        </div>
        <div class="panel" style="padding: 10px;">
          <div style="font-size: 10px; color: var(--text-secondary);">ACTION</div>
          <div class="mono" style="font-weight: 600; font-size: 11px; margin-top: 4px;"><span class="action-pill ${event.action}">${event.action || 'UNKNOWN'}</span></div>
        </div>
      </div>

      <div class="split-view-container">
        <!-- Raw Payload -->
        <div class="split-col">
          <div class="split-col-header">
            <span class="split-col-title">Original Raw Payload (Lossless)</span>
            <button class="btn btn-secondary btn-sm" id="btnCopyRaw">Copy Raw</button>
          </div>
          <div class="raw-payload-box" id="rawContent">${escapeHtml(rawStr)}</div>
          <div style="margin-top: 10px; font-size: 10px; color: var(--text-muted); font-family: var(--font-mono);">
            SHA-256: ${event.raw_ref?.raw_sha256 || 'verified'} (${event.raw_ref?.raw_bytes || rawStr.length} bytes)
          </div>
        </div>

        <!-- Normalized Universal Schema -->
        <div class="split-col">
          <div class="split-col-header">
            <span class="split-col-title">Normalized Schema (Taxonomy)</span>
            <button class="btn btn-secondary btn-sm" id="btnCopyNorm">Copy JSON</button>
          </div>
          <pre class="json-inspector-box" id="normContent">${escapeHtml(JSON.stringify(normalizedCopy, null, 2))}</pre>
        </div>
      </div>
    `;

    // Hook up copy buttons
    document.getElementById('btnCopyProvenance')?.addEventListener('click', () => {
      navigator.clipboard.writeText(event.provenance_id);
      toast.success('Provenance ID copied to clipboard');
    });

    document.getElementById('btnCopyRaw')?.addEventListener('click', () => {
      navigator.clipboard.writeText(rawStr);
      toast.success('Raw log copied to clipboard');
    });

    document.getElementById('btnCopyNorm')?.addEventListener('click', () => {
      navigator.clipboard.writeText(JSON.stringify(normalizedCopy, null, 2));
      toast.success('Normalized JSON copied to clipboard');
    });

    this.show();
  },

  openSource(source) {
    ensureElements();
    if (!drawerEl || !backdropEl) return;

    const titleEl = document.getElementById('drawerTitle');
    const bodyEl = document.getElementById('drawerBody');

    titleEl.innerHTML = `
      <span>SOURCE PROFILE</span>
      <span class="wordmark-badge">${source.status}</span>
    `;

    bodyEl.innerHTML = `
      <div class="provenance-banner">
        <div>
          <div style="font-size: 10px; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.06em; margin-bottom: 3px;">COLLECTOR IDENTIFIER</div>
          <div class="provenance-id-val">${source.id}</div>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px;">
        <div class="panel">
          <div style="font-size: 10px; color: var(--text-secondary);">DEVICE NAME</div>
          <div class="mono" style="font-size: 13px; font-weight: 700; margin-top: 4px;">${source.name}</div>
        </div>
        <div class="panel">
          <div style="font-size: 10px; color: var(--text-secondary);">VENDOR</div>
          <div class="mono" style="font-size: 13px; font-weight: 700; margin-top: 4px;">${source.vendor}</div>
        </div>
        <div class="panel">
          <div style="font-size: 10px; color: var(--text-secondary);">FORMAT</div>
          <div class="mono" style="font-size: 13px; font-weight: 700; margin-top: 4px;">${source.format}</div>
        </div>
      </div>

      <div class="panel" style="margin-bottom: 16px;">
        <div class="panel-header">
          <span class="panel-title">Telemetry & Ingestion Metrics</span>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
          <div>
            <div style="font-size: 11px; color: var(--text-secondary);">Average Throughput</div>
            <div class="mono" style="font-size: 20px; font-weight: 700; color: var(--status-green);">${source.eps || 0} EPS</div>
          </div>
          <div>
            <div style="font-size: 11px; color: var(--text-secondary);">Lifetime Processed Events</div>
            <div class="mono" style="font-size: 20px; font-weight: 700; color: var(--accent-cyan);">${(source.total_events || 0).toLocaleString()}</div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Parser Pipeline Binding</span>
        </div>
        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.6;">
          This source is bound to the <strong>${source.format}</strong> streaming pipeline. Incoming payloads from this collector are automatically processed for cryptographic SHA-256 provenance preservation, parsed into security attributes, and mapped to the Chetas Universal Common Taxonomy.
        </p>
      </div>
    `;

    this.show();
  },

  show() {
    ensureElements();
    backdropEl.classList.add('open');
    drawerEl.classList.add('open');
    document.body.style.overflow = 'hidden';
  },

  close() {
    ensureElements();
    backdropEl.classList.remove('open');
    drawerEl.classList.remove('open');
    document.body.style.overflow = '';
  }
};

// Global click to close backdrop
document.addEventListener('DOMContentLoaded', () => {
  ensureElements();
  backdropEl?.addEventListener('click', () => drawer.close());
  document.getElementById('drawerCloseBtn')?.addEventListener('click', () => drawer.close());
});
