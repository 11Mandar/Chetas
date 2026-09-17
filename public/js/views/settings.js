import { toast } from '../components/toast.js';
import { themeManager } from '../theme.js';

/**
 * Settings View Controller
 * Account profile and SOC operator preferences
 */

export const settingsView = {
  preferences: {
    pageSize: 100,
    timezone: 'UTC',
    autoRefreshSec: 3
  },

  init() {
    this.loadPreferences();
    this.bindEvents();
  },

  loadPreferences() {
    const saved = localStorage.getItem('chetas_preferences');
    if (saved) {
      try {
        this.preferences = { ...this.preferences, ...JSON.parse(saved) };
      } catch (e) {}
    }

    const pageSizeEl = document.getElementById('settingPageSize');
    const timezoneEl = document.getElementById('settingTimezone');
    const themeEl = document.getElementById('settingTheme');

    if (pageSizeEl) pageSizeEl.value = this.preferences.pageSize;
    if (timezoneEl) timezoneEl.value = this.preferences.timezone;
    if (themeEl) themeEl.value = themeManager.getTheme();
  },

  bindEvents() {
    // Theme Mode select change
    const themeEl = document.getElementById('settingTheme');
    themeEl?.addEventListener('change', (e) => {
      themeManager.setTheme(e.target.value);
    });

    document.getElementById('settingsForm')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const pageSize = parseInt(document.getElementById('settingPageSize').value, 10);
      const timezone = document.getElementById('settingTimezone').value;
      const themeVal = document.getElementById('settingTheme')?.value || themeManager.getTheme();

      this.preferences.pageSize = pageSize;
      this.preferences.timezone = timezone;
      themeManager.setTheme(themeVal);

      localStorage.setItem('chetas_preferences', JSON.stringify(this.preferences));
      toast.success('Preferences updated successfully');
    });

    document.getElementById('accountUpdateForm')?.addEventListener('submit', (e) => {
      e.preventDefault();
      toast.success('Account credentials updated');
    });
  }
};
