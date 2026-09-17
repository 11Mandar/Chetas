/**
 * Chetas Theme Controller
 * Manages Dark Mode (SOC Operational Default) and Light Mode
 * Persists user preference in localStorage and synchronizes UI across views.
 */

export const themeManager = {
  currentTheme: 'dark',

  init() {
    // 1. Determine saved theme or default to 'dark'
    const saved = localStorage.getItem('chetas_theme');
    const theme = (saved === 'light' || saved === 'dark') ? saved : 'dark';
    this.applyTheme(theme, false);

    // 2. Bind top bar theme toggle switch
    this.bindToggleEvents();
  },

  bindToggleEvents() {
    const toggleBtn = document.getElementById('themeToggleBtn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        this.toggleTheme();
      });
    }

    // Bind settings dropdown if present
    const settingThemeEl = document.getElementById('settingTheme');
    if (settingThemeEl) {
      settingThemeEl.value = this.currentTheme;
      settingThemeEl.addEventListener('change', (e) => {
        this.setTheme(e.target.value);
      });
    }
  },

  toggleTheme() {
    const nextTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
    this.setTheme(nextTheme);
  },

  setTheme(theme) {
    if (theme !== 'dark' && theme !== 'light') return;
    this.applyTheme(theme, true);
  },

  applyTheme(theme, notify = true) {
    this.currentTheme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('chetas_theme', theme);

    // Update Top Bar Toggle Switch UI
    const toggleBtn = document.getElementById('themeToggleBtn');
    if (toggleBtn) {
      toggleBtn.setAttribute('data-theme', theme);
      toggleBtn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
      toggleBtn.setAttribute('title', theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode');
    }

    // Sync Settings dropdown if present
    const settingThemeEl = document.getElementById('settingTheme');
    if (settingThemeEl && settingThemeEl.value !== theme) {
      settingThemeEl.value = theme;
    }

    // Notify listeners
    if (notify) {
      window.dispatchEvent(new CustomEvent('chetas:theme-change', { detail: { theme } }));
    }
  },

  getTheme() {
    return this.currentTheme;
  }
};
