/**
 * Toast Notification Component
 */

let container = null;

function ensureContainer() {
  if (!container) {
    container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
  }
  return container;
}

export const toast = {
  show(message, type = 'info', duration = 3500) {
    const cont = ensureContainer();
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    
    let icon = 'ℹ️';
    if (type === 'success') icon = '✓';
    if (type === 'error') icon = '✕';
    if (type === 'warning') icon = '⚠';

    el.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    cont.appendChild(el);

    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(10px)';
      el.style.transition = 'opacity 200ms ease, transform 200ms ease';
      setTimeout(() => el.remove(), 200);
    }, duration);
  },

  success(message, duration) {
    this.show(message, 'success', duration);
  },

  error(message, duration) {
    this.show(message, 'error', duration);
  },

  info(message, duration) {
    this.show(message, 'info', duration);
  }
};
