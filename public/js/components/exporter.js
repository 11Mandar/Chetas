import { toast } from './toast.js';

/**
 * Robust CSV Exporter
 * Formats table rows with escaped quotes, generates date-stamped file,
 * triggers browser download, and shows confirmation toast.
 */

export function exportTableToCSV(tableName, rowsData, customColumns = null) {
  if (!rowsData || rowsData.length === 0) {
    toast.error('No visible rows to export');
    return;
  }

  const today = new Date().toISOString().slice(0, 10);
  const fileName = `chetas_${tableName.toLowerCase().replace(/\s+/g, '_')}_${today}.csv`;

  let headers = [];
  let formatRowFn = null;

  if (tableName === 'logs') {
    headers = [
      'timestamp',
      'provenance_id',
      'event_type',
      'severity',
      'source_ip',
      'destination_ip',
      'user_name',
      'action',
      'outcome',
      'message',
      'extra_data'
    ];

    formatRowFn = (item) => [
      item.timestamp || '',
      item.provenance_id || '',
      item.event_type || '',
      item.severity || '',
      item.source_ip || '',
      item.destination_ip || '',
      item.user_name || '',
      item.action || '',
      item.outcome || '',
      item.message || '',
      JSON.stringify(item.extra_data || {})
    ];
  } else if (tableName === 'sources') {
    headers = ['id', 'name', 'type', 'vendor', 'format', 'status', 'eps', 'total_events', 'last_seen'];
    formatRowFn = (item) => [
      item.id || '',
      item.name || '',
      item.type || '',
      item.vendor || '',
      item.format || '',
      item.status || '',
      item.eps || 0,
      item.total_events || 0,
      item.last_seen || ''
    ];
  } else if (tableName === 'audit') {
    headers = ['id', 'timestamp', 'actor', 'action', 'details', 'ip_address'];
    formatRowFn = (item) => [
      item.id || '',
      item.timestamp || '',
      item.actor || '',
      item.action || '',
      item.details || '',
      item.ip_address || ''
    ];
  } else {
    // Generic fallback
    headers = customColumns || Object.keys(rowsData[0] || {});
    formatRowFn = (item) => headers.map(h => item[h] !== undefined ? item[h] : '');
  }

  // Construct CSV content
  const escapeCsvCell = (val) => {
    if (val === null || val === undefined) return '""';
    const str = String(val).replace(/"/g, '""');
    return `"${str}"`;
  };

  const csvRows = [];
  csvRows.push(headers.map(escapeCsvCell).join(','));

  for (const item of rowsData) {
    const rowValues = formatRowFn(item);
    csvRows.push(rowValues.map(escapeCsvCell).join(','));
  }

  const csvString = csvRows.join('\r\n');
  const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', fileName);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);

  toast.success(`Exported ${rowsData.length} rows to ${fileName}`);
}
