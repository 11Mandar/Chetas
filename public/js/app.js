import { api } from './api.js';
import { loginView } from './views/login.js';
import { overviewView } from './views/overview.js';
import { sourcesView } from './views/sources.js';
import { logsView } from './views/logs.js';
import { aiMappingView } from './views/aiMapping.js';
import { auditView } from './views/audit.js';
import { settingsView } from './views/settings.js';
import { drawer } from './components/drawer.js';
import { toast } from './components/toast.js';
import { themeManager } from './theme.js';

/**
 * Main Chetas Application Controller
 */

class ChetasApp {
  constructor() {
    this.currentTab = 'overview';
    this.refreshInterval = null;
  }

  init() {
    // 0. Initialize Theme (Dark/Light mode)
    themeManager.init();

    // 1. Initialize Views
    loginView.init((user) => this.onAuthenticated(user));
    overviewView.init();
    sourcesView.init();
    logsView.init();
    aiMappingView.init();
    auditView.init();
    settingsView.init();

    // 2. Global Navigation & Top Bar Interactions
    this.bindGlobalEvents();

    // 3. Start Periodic Telemetry Sync
    this.startTelemetryLoop();
  }

  onAuthenticated(user) {
    this.navigateToTab('overview');
    this.syncTelemetry();
  }

  bindGlobalEvents() {
    // Nav Tabs Click
    const tabButtons = document.querySelectorAll('.nav-tab');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const tab = btn.getAttribute('data-tab');
        this.navigateToTab(tab);
      });
    });

    // Logo Click -> Navigate to Overview
    document.getElementById('logoHomeLink')?.addEventListener('click', (e) => {
      e.preventDefault();
      this.navigateToTab('overview');
    });

    // Account Avatar Dropdown Toggle
    const accountTrigger = document.getElementById('accountTrigger');
    const accountDropdown = document.getElementById('accountDropdown');

    accountTrigger?.addEventListener('click', (e) => {
      e.stopPropagation();
      accountDropdown?.classList.toggle('show');
    });

    document.addEventListener('click', (e) => {
      if (!accountDropdown?.contains(e.target) && !accountTrigger?.contains(e.target)) {
        accountDropdown?.classList.remove('show');
      }
    });

    // Account Dropdown: Settings Click
    document.getElementById('menuItemSettings')?.addEventListener('click', () => {
      accountDropdown?.classList.remove('show');
      this.navigateToSettings();
    });

    // Global Provenance Search Input
    const globalSearch = document.getElementById('globalProvenanceSearch');
    globalSearch?.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter') {
        const query = globalSearch.value.trim();
        if (!query) return;

        try {
          const event = await api.getEventByProvenance(query);
          drawer.openEvent(event);
        } catch (err) {
          toast.error(`No event found for provenance ID "${query}"`);
        }
      }
    });
  }

  navigateToTab(tabName) {
    this.currentTab = tabName;

    // Show nav tabs container in case we were on Settings
    const navBar = document.getElementById('segmentedNav');
    if (navBar) navBar.style.display = 'flex';

    // Update active tab buttons
    document.querySelectorAll('.nav-tab').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === tabName);
    });

    // Hide all view sections, show target
    document.querySelectorAll('.view-section').forEach(sec => {
      sec.classList.remove('active');
    });

    const targetView = document.getElementById(`view${capitalize(tabName)}`);
    if (targetView) targetView.classList.add('active');

    // Trigger tab-specific refresh
    if (tabName === 'overview') overviewView.render();
    if (tabName === 'sources') sourcesView.loadSources();
    if (tabName === 'logs') logsView.loadLogs();
    if (tabName === 'aiMapping') aiMappingView.loadMappings();
    if (tabName === 'audit') auditView.loadAudit();
  }

  navigateToSettings() {
    // Prompt spec: "Same top bar and layout shell as the rest of the app, no segmented nav tabs since it's not one of the primary sections."
    const navBar = document.getElementById('segmentedNav');
    if (navBar) navBar.style.display = 'none';

    document.querySelectorAll('.view-section').forEach(sec => {
      sec.classList.remove('active');
    });

    const settingsViewEl = document.getElementById('viewSettings');
    if (settingsViewEl) settingsViewEl.classList.add('active');
  }

  startTelemetryLoop() {
    this.syncTelemetry();
    this.refreshInterval = setInterval(() => {
      this.syncTelemetry();
    }, 2500);
  }

  async syncTelemetry() {
    try {
      const status = await api.getStatus();
      overviewView.updateKPICounters(status);

      // Auto-update logs view table if user is currently on logs tab
      if (this.currentTab === 'logs' && logsView.isStreaming) {
        logsView.loadLogs();
      } else if (this.currentTab === 'overview') {
        overviewView.render();
      }
    } catch (e) {
      // ignore
    }
  }
}

function capitalize(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// Instantiate on DOM load
document.addEventListener('DOMContentLoaded', () => {
  const app = new ChetasApp();
  app.init();
  window.__CHETAS_APP__ = app;
});
