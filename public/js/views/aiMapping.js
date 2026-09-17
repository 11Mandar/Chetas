import { api } from '../api.js';
import { toast } from '../components/toast.js';
import { formatLocalTime, escapeHtml } from '../utils.js';

/**
 * AI Field Mapping View Controller
 * Presents pending AI proposals awaiting human approval with before/after cards,
 * confidence score badges in violet (#7C3AED), and dynamic schema update actions.
 */

export const aiMappingView = {
  pending: [],
  approved: {},

  init() {
    this.bindEvents();
    this.loadMappings();
  },

  bindEvents() {
    // Custom mapping modal
    document.getElementById('btnOpenCustomMappingModal')?.addEventListener('click', () => {
      document.getElementById('customMappingModal')?.classList.add('open');
    });

    document.getElementById('btnCloseCustomMappingModal')?.addEventListener('click', () => {
      document.getElementById('customMappingModal')?.classList.remove('open');
    });

    document.getElementById('customMappingForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const rawKey = document.getElementById('customRawKey').value.trim();
      const canonicalField = document.getElementById('customCanonicalField').value;

      if (!rawKey) return;

      try {
        await api.addCustomMapping(rawKey, canonicalField);
        toast.success(`Canonical rule registered: ${rawKey} -> ${canonicalField}`);
        document.getElementById('customMappingModal')?.classList.remove('open');
        document.getElementById('customMappingForm')?.reset();
        await this.loadMappings();
      } catch (err) {
        toast.error(`Failed to register rule: ${err.message}`);
      }
    });

    // Card Actions: Approve / Reject (Delegated)
    const cardsContainer = document.getElementById('aiCardsContainer');
    cardsContainer?.addEventListener('click', async (e) => {
      const approveBtn = e.target.closest('.btn-approve-mapping');
      const rejectBtn = e.target.closest('.btn-reject-mapping');

      if (approveBtn) {
        const id = approveBtn.getAttribute('data-id');
        try {
          const res = await api.approveMapping(id);
          toast.success(`Approved mapping: ${res.mapping.rawKey} → ${res.mapping.targetField}`);
          await this.loadMappings();
        } catch (err) {
          toast.error(`Approval failed: ${err.message}`);
        }
      } else if (rejectBtn) {
        const id = rejectBtn.getAttribute('data-id');
        try {
          await api.rejectMapping(id);
          toast.info('Suggestion rejected');
          await this.loadMappings();
        } catch (err) {
          toast.error(`Rejection failed: ${err.message}`);
        }
      }
    });
  },

  async loadMappings() {
    try {
      const data = await api.getAIMappings();
      this.pending = data.pending || [];
      this.approved = data.approved || {};
      this.render();
    } catch (e) {
      console.error('Error loading AI mappings', e);
    }
  },

  render() {
    const queueContainer = document.getElementById('aiCardsContainer');
    const approvedTableBody = document.getElementById('approvedMappingsTableBody');
    const badgeCount = document.getElementById('aiPendingBadgeCount');

    if (badgeCount) {
      badgeCount.textContent = this.pending.length;
      badgeCount.style.display = this.pending.length > 0 ? 'inline-block' : 'none';
    }

    // 1. Render Pending Review Queue Cards
    if (queueContainer) {
      if (this.pending.length === 0) {
        queueContainer.innerHTML = `
          <div style="grid-column: 1 / -1; background: var(--bg-surface); border: 1px dashed var(--border-subtle); border-radius: var(--radius-sm); padding: 32px; text-align: center; color: var(--text-secondary);">
            <div style="font-size: 14px; color: var(--status-green); margin-bottom: 6px;">✓ All Telemetry Fields Aligned</div>
            <div style="font-size: 11px; color: var(--text-muted);">No unmapped attributes currently pending review. New vendor telemetry will automatically surface here for operator confirmation.</div>
          </div>
        `;
      } else {
        queueContainer.innerHTML = this.pending.map(item => `
          <div class="ai-card">
            <div class="ai-card-header">
              <span class="ai-badge">
                <span style="font-size: 8px;">✦</span>
                AI-SUGGESTED (${Math.round((item.confidence || 0.85) * 100)}% CONFIDENCE)
              </span>
              <span class="timestamp">${item.suggested_at ? formatLocalTime(item.suggested_at) : 'Pending'}</span>
            </div>

            <div class="mapping-transformation">
              <div>
                <div style="font-size: 9px; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 2px;">RAW VENDOR KEY</div>
                <div class="mapping-key raw">${escapeHtml(item.raw_key)}</div>
              </div>
              <span class="mapping-arrow">→</span>
              <div>
                <div style="font-size: 9px; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 2px;">CANONICAL TAXONOMY</div>
                <div class="mapping-key canonical">${escapeHtml(item.canonical_field)}</div>
              </div>
            </div>

            <div class="ai-card-sample">
              <strong>Rationale:</strong> ${escapeHtml(item.rationale)}<br/>
              ${item.sample_value ? `<strong>Sample:</strong> <span class="mono" style="color: #93c5fd;">${escapeHtml(item.sample_value)}</span>` : ''}
            </div>

            <div class="ai-card-actions">
              <button class="btn btn-primary btn-sm btn-approve-mapping" data-id="${item.id}" style="flex: 1;">
                Approve Mapping
              </button>
              <button class="btn btn-danger btn-sm btn-reject-mapping" data-id="${item.id}">
                Reject
              </button>
            </div>
          </div>
        `).join('');
      }
    }

    // 2. Render Active Approved Mappings Table
    if (approvedTableBody) {
      const entries = Object.entries(this.approved);
      if (entries.length === 0) {
        approvedTableBody.innerHTML = `<tr><td colspan="3" style="text-align:center; color: var(--text-muted);">No approved mappings</td></tr>`;
      } else {
        approvedTableBody.innerHTML = entries.map(([raw, canonical]) => `
          <tr>
            <td class="mono" style="color: var(--status-amber); font-weight: 600;">${escapeHtml(raw)}</td>
            <td style="color: var(--text-muted);">→</td>
            <td class="mono" style="color: var(--accent-cyan); font-weight: 600;">${escapeHtml(canonical)}</td>
          </tr>
        `).join('');
      }
    }
  }
};
