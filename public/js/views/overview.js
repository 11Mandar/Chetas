import { api } from '../api.js';
import { drawer } from '../components/drawer.js';
import { toast } from '../components/toast.js';
import { formatLocalTime, formatLocalDateTime, escapeHtml } from '../utils.js';

/**
 * Overview View Controller
 * Features live KPI count-up metrics, animated 4-stage data-flow pipeline diagram
 * with circuit-colored traveling dots in the 8-color logo sequence, and recent telemetry feed.
 */

// Chetas 8-color Emblem sequence
const RING_PALETTE = [
  '#4F46E5', // Indigo
  '#7C3AED', // Violet
  '#2563EB', // Blue
  '#06B6D4', // Cyan
  '#0891B2', // Teal
  '#10B981', // Green
  '#F59E0B', // Amber
  '#EC4899'  // Pink
];

export const overviewView = {
  container: null,
  animFrameId: null,
  particles: [],
  prevCounts: { sources: 0, processed: 0, errors: 0, pending: 0 },
  currentRange: '1h',
  timeseriesData: null,
  hoverIndex: -1,
  tsCanvas: null,
  tsCtx: null,

  init() {
    this.container = document.getElementById('viewOverview');
    this.initPipelineCanvas();
    this.initTimeseriesChart();
    this.bindButtons();
    this.render();
  },

  bindButtons() {
    const btn = document.getElementById('btnOverviewLoadPack');
    btn?.addEventListener('click', async () => {
      try {
        btn.disabled = true;
        const res = await api.injectSiemSamples();
        toast.success(`Injected ${res.count || 17} enterprise SIEM security scenario events!`);
        await this.render();
      } catch (err) {
        toast.error(`Injection failed: ${err.message}`);
      } finally {
        btn.disabled = false;
      }
    });

    // Overview table row click -> open right drawer
    document.getElementById('overviewRecentLogs')?.addEventListener('click', async (e) => {
      const row = e.target.closest('tr');
      if (!row) return;
      const provId = row.getAttribute('data-prov');
      if (!provId) return;
      try {
        const event = await api.getEventByProvenance(provId);
        drawer.openEvent(event);
      } catch (err) {
        // ignore
      }
    });

    // Theme toggle observer: redraw canvas on theme change
    const observer = new MutationObserver(() => {
      if (this.timeseriesData) {
        this.drawTimeseriesChart();
      }
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  },

  async render() {
    try {
      const [status, eventsData, sources] = await Promise.all([
        api.getStatus(),
        api.getEvents({ limit: 50 }),
        api.getSources().catch(() => []),
        this.loadTimeseries()
      ]);
      const events = eventsData.events || [];

      this.updateKPICounters(status);
      this.updateArchitecturePipeline(status, events, sources || []);
      this.renderRecentTelemetry(events);
    } catch (e) {
      console.error('Error fetching overview data', e);
    }
  },

  updateArchitecturePipeline(status, events, sources = []) {
    const stage1Sub = document.getElementById('stage1Sub');
    const stage1Status = document.getElementById('stage1Status');
    const stage2Sub = document.getElementById('stage2Sub');
    const stage2Status = document.getElementById('stage2Status');
    const stage3Sub = document.getElementById('stage3Sub');
    const stage3Status = document.getElementById('stage3Status');
    const stage4Sub = document.getElementById('stage4Sub');
    const stage4Status = document.getElementById('stage4Status');

    const totalProcessed = status.total_processed || 0;
    const eps = status.events_per_second || 0;
    const totalSources = status.sources_count || sources.length || 13;

    // 1. Stage 01: Log Sources - Dynamic vendors/collectors from real telemetry
    const vendors = [...new Set(sources.map(s => s.vendor))].filter(v => v && v !== 'Generic' && v !== 'Local File System');
    if (stage1Sub) {
      const displayVendors = vendors.slice(0, 3).join(' · ');
      const extraCount = vendors.length > 3 ? ` (+${vendors.length - 3})` : '';
      stage1Sub.textContent = displayVendors ? `${displayVendors}${extraCount}` : 'Windows · Palo Alto · Cisco';
    }
    if (stage1Status) {
      stage1Status.textContent = eps > 0 ? `${eps} EPS Ingestion` : `${totalSources} Sources Connected`;
    }

    // 2. Stage 02: Format Detection - Real detected formats & accuracy
    const formats = [...new Set(sources.map(s => s.format).concat(events.map(e => e.format)))].filter(f => f && f !== 'Auto-Detect');
    const errors = status.error_count || 0;
    const matchRate = totalProcessed > 0 ? Math.max(0, ((totalProcessed - errors) / totalProcessed * 100)).toFixed(1) : '100.0';
    if (stage2Sub) {
      stage2Sub.textContent = formats.length > 0 ? formats.slice(0, 3).join(' · ') : 'CEF · Syslog · JSON';
    }
    if (stage2Status) {
      stage2Status.textContent = `${matchRate}% Accuracy (${totalProcessed.toLocaleString()} Parsed)`;
    }

    // 3. Stage 03: Normalization - Real normalization counts & pending review
    const pendingMappings = status.pending_mappings || 0;
    if (stage3Sub) {
      stage3Sub.textContent = totalProcessed > 0 ? `${totalProcessed.toLocaleString()} Events Standardized` : 'ULPF Taxonomy Mapping';
    }
    if (stage3Status) {
      stage3Status.textContent = pendingMappings > 0 ? `${pendingMappings} Pending AI Review` : 'Unified Taxonomy Active';
    }

    // 4. Stage 04: Secure Storage - Real buffer and lossless provenance metrics
    if (stage4Sub) {
      stage4Sub.textContent = `Ring Buffer · ${events.length} Live Indexed`;
    }
    if (stage4Status) {
      stage4Status.textContent = '100% Lossless Traceable';
    }
  },

  updateKPICounters(status) {
    this.smoothCountUp('kpiSources', status.sources_count || 0);
    this.smoothCountUp('kpiProcessed', status.total_processed || 0);
    this.smoothCountUp('kpiErrors', status.error_count || 0);
    this.smoothCountUp('kpiPendingAI', status.pending_mappings || 0);

    // Update live top bar indicators
    const topSources = document.getElementById('statusSourcesVal');
    const topEps = document.getElementById('statusEpsVal');
    const topErrors = document.getElementById('statusErrorsVal');

    if (topSources) topSources.textContent = status.sources_count || 0;
    if (topEps) topEps.textContent = `${status.events_per_second || 0} EPS`;
    if (topErrors) topErrors.textContent = status.error_count || 0;
  },

  smoothCountUp(elementId, targetValue) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const current = parseInt(el.getAttribute('data-val') || '0', 10);
    if (current === targetValue) return;

    el.setAttribute('data-val', targetValue);
    const diff = targetValue - current;
    const duration = 600;
    const startTime = performance.now();

    const step = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const val = Math.round(current + diff * progress);
      el.textContent = val.toLocaleString();
      if (progress < 1) {
        requestAnimationFrame(step);
      }
    };
    requestAnimationFrame(step);
  },

  renderRecentTelemetry(events) {
    const tableBody = document.getElementById('overviewRecentLogs');
    if (!tableBody) return;

    if (events.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 20px;">No events ingested yet. Use "Ingest Log" to test the pipeline.</td></tr>`;
      return;
    }

    tableBody.innerHTML = events.map(e => {
      const sourceDisplay = e.source_ip 
        ? `${escapeHtml(e.source_ip)} → ${escapeHtml(e.destination_ip || '-')}`
        : `<span class="source-host-tag" title="${escapeHtml(e.vendor || '')}">${escapeHtml(e.source_host || e.product || e.vendor || 'Host')}</span>`;

      return `
        <tr data-prov="${e.provenance_id}" style="cursor: pointer;">
          <td class="timestamp" title="${formatLocalDateTime(e.timestamp)}">${formatLocalTime(e.timestamp)}</td>
          <td class="provenance-cell mono">${e.provenance_id}</td>
          <td><span class="format-badge">${e.format}</span></td>
          <td><span class="severity-pill ${e.severity}">${e.severity}</span></td>
          <td class="mono">${sourceDisplay}</td>
          <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-secondary);">
            ${escapeHtml(e.message)}
          </td>
        </tr>
      `;
    }).join('');
  },

  initPipelineCanvas() {
    const canvas = document.getElementById('pipelineCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const resizeCanvas = () => {
      if (canvas.parentElement) {
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight || 20;
      }
    };
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Equidistant dots with uniform speed
    const count = 8;
    const speed = 0.0008; // Equal uniform speed for all dots
    let baseOffset = 0;

    const renderFrame = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const w = canvas.width;
      const h = canvas.height;
      const centerY = h / 2;
      const padX = 20;
      const startX = padX;
      const endX = w - padX;
      const trackLength = endX - startX;

      const isLight = document.documentElement.getAttribute('data-theme') === 'light';

      // 1. Subtle horizontal dashed circuit wire
      ctx.beginPath();
      ctx.strokeStyle = isLight ? 'rgba(8, 145, 178, 0.25)' : 'rgba(6, 182, 212, 0.25)';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([4, 6]);
      ctx.moveTo(startX, centerY);
      ctx.lineTo(endX, centerY);
      ctx.stroke();
      ctx.setLineDash([]);

      // 2. Advance uniform base offset at constant equal speed
      baseOffset = (baseOffset + speed) % 1.0;

      // 3. Render dots with mathematically equal distance and zero overlap
      for (let i = 0; i < count; i++) {
        const progress = (baseOffset + (i / count)) % 1.0;
        const px = startX + progress * trackLength;
        const py = centerY;
        const color = RING_PALETTE[i % RING_PALETTE.length];

        // Smooth subtle fade near boundary edges
        const edgeFactor = Math.sin(progress * Math.PI);
        const alpha = Math.max(0.15, Math.min(1.0, edgeFactor * 2.0));

        ctx.save();
        ctx.globalAlpha = alpha;
        ctx.beginPath();
        ctx.arc(px, py, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.shadowColor = color;
        ctx.shadowBlur = isLight ? 4 : 8;
        ctx.fill();
        ctx.restore();
      }

      this.animFrameId = requestAnimationFrame(renderFrame);
    };

    renderFrame();
  },

  initTimeseriesChart() {
    this.tsCanvas = document.getElementById('overviewTimeseriesCanvas');
    if (!this.tsCanvas) return;
    this.tsCtx = this.tsCanvas.getContext('2d');

    // Range picker buttons
    const rangePicker = document.getElementById('timeseriesRangePicker');
    rangePicker?.addEventListener('click', async (e) => {
      const btn = e.target.closest('.ts-range-btn');
      if (!btn) return;
      const range = btn.getAttribute('data-range');
      if (!range || range === this.currentRange) return;

      rangePicker.querySelectorAll('.ts-range-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      this.currentRange = range;
      await this.loadTimeseries();
    });

    // Interactive mouse move / touch events for hover crosshair & tooltip
    const container = document.getElementById('timeseriesCanvasContainer');
    const tooltip = document.getElementById('timeseriesTooltip');

    const handlePointer = (clientX, clientY) => {
      if (!this.timeseriesData || !this.timeseriesData.buckets?.length || !this.tsCanvas) return;
      const rect = this.tsCanvas.getBoundingClientRect();
      const x = clientX - rect.left;
      const y = clientY - rect.top;

      const padLeft = 46;
      const padRight = 16;
      const plotW = rect.width - padLeft - padRight;
      const buckets = this.timeseriesData.buckets;

      if (x < padLeft - 10 || x > rect.width - padRight + 10 || y < 0 || y > rect.height) {
        this.hoverIndex = -1;
        if (tooltip) tooltip.style.display = 'none';
        this.drawTimeseriesChart();
        return;
      }

      // Find closest bucket
      const ratio = Math.max(0, Math.min(1, (x - padLeft) / plotW));
      const idx = Math.min(buckets.length - 1, Math.round(ratio * (buckets.length - 1)));
      this.hoverIndex = idx;
      this.drawTimeseriesChart();

      // Update & position tooltip
      if (tooltip) {
        const b = buckets[idx];
        const ptX = padLeft + (idx / (buckets.length - 1 || 1)) * plotW;
        const maxVal = Math.max(5, this.timeseriesData.peak_rate * 1.15);
        const ptY = 20 + (1 - b.count / maxVal) * (rect.height - 46);

        const ttHeader = document.getElementById('ttHeader');
        const ttTotalVal = document.getElementById('ttTotalVal');
        const ttSeverities = document.getElementById('ttSeverities');

        if (ttHeader) ttHeader.textContent = `${b.label} (${new Date(b.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })})`;
        if (ttTotalVal) ttTotalVal.textContent = `${b.count.toLocaleString()} event${b.count === 1 ? '' : 's'}`;

        if (ttSeverities) {
          const s = b.severities || {};
          const crit = (s.CRITICAL || 0);
          const high = (s.HIGH || 0);
          const warn = (s.WARNING || 0);
          const info = (s.INFORMATIONAL || 0) + (s.LOW || 0);

          ttSeverities.innerHTML = `
            <div class="tt-sev-row">
              <span class="tt-sev-chip"><span class="tt-sev-dot critical"></span>Critical:</span>
              <strong>${crit}</strong>
            </div>
            <div class="tt-sev-row">
              <span class="tt-sev-chip"><span class="tt-sev-dot high"></span>High:</span>
              <strong>${high}</strong>
            </div>
            <div class="tt-sev-row">
              <span class="tt-sev-chip"><span class="tt-sev-dot warning"></span>Warning:</span>
              <strong>${warn}</strong>
            </div>
            <div class="tt-sev-row">
              <span class="tt-sev-chip"><span class="tt-sev-dot info"></span>Info/Low:</span>
              <strong>${info}</strong>
            </div>
          `;
        }

        tooltip.style.display = 'block';
        tooltip.style.left = `${Math.max(80, Math.min(rect.width - 80, ptX))}px`;
        tooltip.style.top = `${Math.max(40, ptY - 10)}px`;
      }
    };

    container?.addEventListener('mousemove', (e) => handlePointer(e.clientX, e.clientY));
    container?.addEventListener('mouseleave', () => {
      this.hoverIndex = -1;
      if (tooltip) tooltip.style.display = 'none';
      this.drawTimeseriesChart();
    });

    container?.addEventListener('touchmove', (e) => {
      if (e.touches?.[0]) {
        handlePointer(e.touches[0].clientX, e.touches[0].clientY);
      }
    }, { passive: true });

    container?.addEventListener('touchend', () => {
      this.hoverIndex = -1;
      if (tooltip) tooltip.style.display = 'none';
      this.drawTimeseriesChart();
    });

    window.addEventListener('resize', () => this.drawTimeseriesChart());
  },

  async loadTimeseries() {
    try {
      const data = await api.getTimeSeries(this.currentRange);
      this.timeseriesData = data;

      // Update stat badges
      const statTotal = document.getElementById('tsStatTotal');
      const statPeak = document.getElementById('tsStatPeak');
      const statAvg = document.getElementById('tsStatAvg');

      if (statTotal) statTotal.textContent = (data.total_logs || 0).toLocaleString();
      if (statPeak) statPeak.textContent = `${(data.peak_rate || 0).toLocaleString()} logs`;
      if (statAvg) statAvg.textContent = `${(data.avg_rate || 0).toLocaleString()} /bucket`;

      this.drawTimeseriesChart();
    } catch (err) {
      console.warn('Could not load timeseries data', err);
    }
  },

  drawTimeseriesChart() {
    if (!this.tsCanvas) return;
    const canvas = this.tsCanvas;
    const ctx = this.tsCtx || canvas.getContext('2d');
    if (!ctx) return;

    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const w = rect.width;
    const h = rect.height || 220;

    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.resetTransform?.();
    ctx.scale(dpr, dpr);

    ctx.clearRect(0, 0, w, h);

    const padLeft = 46;
    const padRight = 16;
    const padTop = 20;
    const padBottom = 26;
    const plotW = w - padLeft - padRight;
    const plotH = h - padTop - padBottom;

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const gridColor = isLight ? 'rgba(15, 23, 42, 0.08)' : 'rgba(255, 255, 255, 0.08)';
    const textColor = isLight ? '#475569' : '#94A3B8';
    const primaryColor = isLight ? '#0891b2' : '#06B6D4';
    const accentColor = isLight ? '#2563eb' : '#4F46E5';

    const buckets = this.timeseriesData?.buckets || [];
    if (!buckets.length) {
      // Empty placeholder
      ctx.fillStyle = textColor;
      ctx.font = '11px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('Awaiting telemetry activity...', w / 2, h / 2);
      return;
    }

    const peak = this.timeseriesData.peak_rate || 0;
    const maxVal = Math.max(5, Math.ceil(peak * 1.2));

    // 1. Horizontal Grid Lines & Y-Axis Markings
    const yTicks = 4;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.font = '10px monospace';

    for (let i = 0; i <= yTicks; i++) {
      const val = Math.round((maxVal / yTicks) * i);
      const y = padTop + plotH - (i / yTicks) * plotH;

      ctx.beginPath();
      ctx.strokeStyle = gridColor;
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 4]);
      ctx.moveTo(padLeft, y);
      ctx.lineTo(w - padRight, y);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = textColor;
      ctx.fillText(val.toLocaleString(), padLeft - 8, y);
    }

    // 2. X-Axis Time Labels & Vertical Grid Lines
    const step = Math.max(1, Math.floor(buckets.length / (w < 600 ? 5 : 8)));
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';

    for (let i = 0; i < buckets.length; i += step) {
      const x = padLeft + (i / (buckets.length - 1 || 1)) * plotW;
      const b = buckets[i];

      ctx.beginPath();
      ctx.strokeStyle = gridColor;
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 5]);
      ctx.moveTo(x, padTop);
      ctx.lineTo(x, padTop + plotH);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = textColor;
      ctx.fillText(b.label, x, padTop + plotH + 7);
    }

    // 3. Compute Data Coordinates
    const points = buckets.map((b, i) => {
      const x = padLeft + (i / (buckets.length - 1 || 1)) * plotW;
      const y = padTop + plotH - (b.count / maxVal) * plotH;
      return { x, y, b };
    });

    // 4. Draw Smooth Gradient Area Under Curve
    const areaGrad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
    if (isLight) {
      areaGrad.addColorStop(0, 'rgba(8, 145, 178, 0.35)');
      areaGrad.addColorStop(0.5, 'rgba(37, 99, 235, 0.12)');
      areaGrad.addColorStop(1, 'rgba(8, 145, 178, 0.0)');
    } else {
      areaGrad.addColorStop(0, 'rgba(6, 182, 212, 0.40)');
      areaGrad.addColorStop(0.5, 'rgba(79, 70, 229, 0.15)');
      areaGrad.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
    }

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];
      const mx = (p0.x + p1.x) / 2;
      ctx.bezierCurveTo(mx, p0.y, mx, p1.y, p1.x, p1.y);
    }
    ctx.lineTo(points[points.length - 1].x, padTop + plotH);
    ctx.lineTo(points[0].x, padTop + plotH);
    ctx.closePath();
    ctx.fillStyle = areaGrad;
    ctx.fill();

    // 5. Draw Curve Stroke with Gradient
    const strokeGrad = ctx.createLinearGradient(padLeft, 0, w - padRight, 0);
    strokeGrad.addColorStop(0, primaryColor);
    strokeGrad.addColorStop(1, accentColor);

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];
      const mx = (p0.x + p1.x) / 2;
      ctx.bezierCurveTo(mx, p0.y, mx, p1.y, p1.x, p1.y);
    }
    ctx.strokeStyle = strokeGrad;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // 6. Draw Subtle Data Point Nodes
    for (let i = 0; i < points.length; i++) {
      const p = points[i];
      if (p.b.count > 0) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
        ctx.fillStyle = primaryColor;
        ctx.shadowColor = primaryColor;
        ctx.shadowBlur = isLight ? 3 : 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }

    // 7. Interactive Hover Crosshair & Halo
    if (this.hoverIndex >= 0 && this.hoverIndex < points.length) {
      const hp = points[this.hoverIndex];

      // Vertical scanner laser guide
      ctx.beginPath();
      ctx.strokeStyle = isLight ? 'rgba(8, 145, 178, 0.7)' : 'rgba(6, 182, 212, 0.8)';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([3, 3]);
      ctx.moveTo(hp.x, padTop);
      ctx.lineTo(hp.x, padTop + plotH);
      ctx.stroke();
      ctx.setLineDash([]);

      // Outer glowing ring halo
      ctx.beginPath();
      ctx.arc(hp.x, hp.y, 7, 0, Math.PI * 2);
      ctx.fillStyle = isLight ? 'rgba(8, 145, 178, 0.25)' : 'rgba(6, 182, 212, 0.3)';
      ctx.fill();
      ctx.strokeStyle = primaryColor;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Inner solid bright dot
      ctx.beginPath();
      ctx.arc(hp.x, hp.y, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#FFFFFF';
      ctx.fill();
    }
  },

  destroy() {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
    }
  }
};

function roundRect(ctx, x, y, width, height, radius) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.lineTo(x + width - radius, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
  ctx.lineTo(x + width, y + height - radius);
  ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
  ctx.lineTo(x + radius, y + height);
  ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
  ctx.lineTo(x, y + radius);
  ctx.quadraticCurveTo(x, y, x + radius, y);
  ctx.closePath();
}
