import { api } from '../api.js';
import { toast } from '../components/toast.js';

/**
 * Login Screen Controller
 */

export const loginView = {
  currentUser: null,

  init(onLoginSuccess) {
    this.onLoginSuccess = onLoginSuccess;
    this.checkSession();
    this.bindEvents();
  },

  checkSession() {
    const saved = localStorage.getItem('chetas_user');
    if (saved) {
      try {
        this.currentUser = JSON.parse(saved);
        this.hideLogin();
        if (this.onLoginSuccess) this.onLoginSuccess(this.currentUser);
        return;
      } catch (e) {
        localStorage.removeItem('chetas_user');
      }
    }
    this.showLogin();
  },

  bindEvents() {
    const form = document.getElementById('loginForm');
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('loginUsername').value.trim();
      const password = document.getElementById('loginPassword').value.trim();
      const errorBanner = document.getElementById('authErrorBanner');

      if (!username || !password) {
        errorBanner.textContent = 'Please enter both username and password';
        errorBanner.style.display = 'block';
        return;
      }

      try {
        const res = await api.login(username, password);
        if (res.success) {
          this.currentUser = res.session;
          localStorage.setItem('chetas_user', JSON.stringify(res.session));
          errorBanner.style.display = 'none';
          this.hideLogin();
          toast.success(`Welcome back, ${res.session.name}`);
          if (this.onLoginSuccess) this.onLoginSuccess(this.currentUser);
        } else {
          errorBanner.textContent = res.error || 'Authentication failed';
          errorBanner.style.display = 'block';
        }
      } catch (err) {
        errorBanner.textContent = err.message || 'Error connecting to auth service';
        errorBanner.style.display = 'block';
      }
    });

    document.getElementById('btnSignOut')?.addEventListener('click', () => {
      this.logout();
    });
  },

  logout() {
    if (this.currentUser) {
      api.logout(this.currentUser.username).catch(() => {});
    }
    this.currentUser = null;
    localStorage.removeItem('chetas_user');
    this.showLogin();
    toast.info('Signed out successfully');
  },

  showLogin() {
    const loginModal = document.getElementById('loginModal');
    const topBar = document.getElementById('topCommandBar');
    const navTabs = document.getElementById('segmentedNav');
    const mainViewport = document.getElementById('mainViewport');

    if (loginModal) loginModal.style.display = 'flex';
    if (topBar) topBar.style.display = 'none';
    if (navTabs) navTabs.style.display = 'none';
    if (mainViewport) mainViewport.style.display = 'none';
  },

  hideLogin() {
    const loginModal = document.getElementById('loginModal');
    const topBar = document.getElementById('topCommandBar');
    const navTabs = document.getElementById('segmentedNav');
    const mainViewport = document.getElementById('mainViewport');

    if (loginModal) loginModal.style.display = 'none';
    if (topBar) topBar.style.display = 'flex';
    if (navTabs) navTabs.style.display = 'flex';
    if (mainViewport) mainViewport.style.display = 'block';

    // Update user profile in top bar
    if (this.currentUser) {
      document.getElementById('topBarUserName').textContent = this.currentUser.name || 'Analyst';
      document.getElementById('topBarUserRole').textContent = this.currentUser.role || 'SOC Operator';
      document.getElementById('topBarUserInitial').textContent = (this.currentUser.name || 'A')[0].toUpperCase();
    }
  }
};
