/**
 * Shared Formatting and Sanitization Utilities
 */

/**
 * Formats an ISO timestamp or date representation into 24-hour local time: "HH:mm:ss"
 * Example: "20:23:24"
 */
export function formatLocalTime(isoStr) {
  if (!isoStr) return '--:--:--';
  try {
    let d;
    if (typeof isoStr === 'string' && isoStr.startsWith('/Date(')) {
      const match = isoStr.match(/\d+/);
      d = match ? new Date(parseInt(match[0], 10)) : new Date();
    } else {
      d = new Date(isoStr);
    }

    if (isNaN(d.getTime())) {
      return String(isoStr).slice(11, 19) || '--:--:--';
    }

    return d.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    });
  } catch (e) {
    return '--:--:--';
  }
}

/**
 * Formats an ISO timestamp into localized full date and time: "YYYY-MM-DD HH:mm:ss"
 * Example: "2026-09-16 20:23:24"
 */
export function formatLocalDateTime(isoStr) {
  if (!isoStr) return '--';
  try {
    let d;
    if (typeof isoStr === 'string' && isoStr.startsWith('/Date(')) {
      const match = isoStr.match(/\d+/);
      d = match ? new Date(parseInt(match[0], 10)) : new Date();
    } else {
      d = new Date(isoStr);
    }

    if (isNaN(d.getTime())) return String(isoStr);

    const pad = (n) => String(n).padStart(2, '0');
    const yyyy = d.getFullYear();
    const mm = pad(d.getMonth() + 1);
    const dd = pad(d.getDate());
    const hh = pad(d.getHours());
    const min = pad(d.getMinutes());
    const ss = pad(d.getSeconds());

    return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
  } catch (e) {
    return String(isoStr);
  }
}

/**
 * HTML Sanitizer
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
