import dgram from 'dgram';
import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import { fileURLToPath } from 'url';
import { processSingleLog } from './pipeline.js';
import { storage } from './storage.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const INCOMING_DIR = path.join(rootDir, 'incoming_logs');
const PROCESSED_DIR = path.join(rootDir, 'incoming_logs', 'processed');
const SYSLOG_UDP_PORT = process.env.SYSLOG_UDP_PORT || 1514;

/**
 * Automated Real Telemetry Collectors
 * 1. Windows Event Log Collector: Collects real live OS System & Application events from the host.
 * 2. UDP Syslog Socket: Listens for direct syslog packets emitted by routers, firewalls, and servers.
 * 3. Directory Watcher: Automatically ingests any .log, .txt, or .json file dropped into incoming_logs/.
 */

import { ENTERPRISE_SIEM_LOGS } from './siemSamples.js';

export class AutomatedCollectors {
  constructor() {
    this.udpSocket = null;
    this.dirWatcher = null;
    this.winEventTimer = null;
    this.lastWinEventTime = new Date(Date.now() - 300000); // Look back 5 mins on initial run
  }

  start() {
    this.registerActiveCollectors();
    this.seedEnterpriseSiemData();
    this.startUDPSyslogListener();
    this.startDirectoryWatcher();
    this.startWindowsEventCollector();
  }

  registerActiveCollectors() {
    // Register the actual collectors as real sources
    storage.registerSource({
      id: 'src-win-system-telemetry',
      name: 'Host-Windows-SystemLog',
      type: 'Operating System Telemetry',
      vendor: 'Microsoft Windows',
      format: 'JSON / EventLog'
    });

    storage.registerSource({
      id: 'src-win-app-telemetry',
      name: 'Host-Windows-ApplicationLog',
      type: 'Application & Service Telemetry',
      vendor: 'Microsoft Windows',
      format: 'JSON / EventLog'
    });

    storage.registerSource({
      id: 'src-udp-syslog-listener',
      name: 'UDP-Syslog-Collector-1514',
      type: 'Network Perimeter Listener',
      vendor: 'Network Devices / Firewalls',
      format: 'Syslog / Auto-Detect'
    });

    storage.registerSource({
      id: 'src-file-directory-watcher',
      name: 'Folder-Watcher-incoming_logs',
      type: 'File System Ingestion',
      vendor: 'Local File System',
      format: 'Auto-Detect'
    });
  }

  /**
   * Injects enterprise-grade multi-vendor security telemetry (Firewall, Auth, Web, EDR)
   * into the live pipeline so analysts can immediately utilize full SIEM capabilities.
   */
  injectEnterpriseSiemPack() {
    let count = 0;
    for (const item of ENTERPRISE_SIEM_LOGS) {
      if (!storage.getSource(item.source_id)) {
        storage.registerSource({
          id: item.source_id,
          name: item.source_name,
          type: item.source_type,
          vendor: item.vendor,
          format: item.format
        });
      }
      const outcome = processSingleLog(item.raw, item.source_id);
      if (outcome.success) count++;
    }
    storage.recordAudit('SYSTEM', 'SIEM_PACK_INJECTED', `Ingested ${count} enterprise security scenario events across multi-vendor appliances`);
    console.log(`[SIEM Engine] Successfully injected ${count} enterprise security logs into pipeline`);
    return count;
  }

  seedEnterpriseSiemData() {
    // Automatically seed enterprise SIEM telemetry if storage is fresh
    if (storage.getEvents().length < 15) {
      this.injectEnterpriseSiemPack();
    }
  }

  // 1. Real Windows Event Log Collector (Polls real System & Application events from host OS)
  startWindowsEventCollector() {
    let processedRecords = new Set();
    let isFirstRun = true;

    const pollEvents = () => {
      const maxCount = isFirstRun ? 50 : 25;
      isFirstRun = false;

      const psCommand = `Get-WinEvent -FilterHashtable @{LogName=@('System', 'Application')} -MaxEvents ${maxCount} -ErrorAction SilentlyContinue | Select-Object RecordId, LogName, TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Compress`;

      exec(`powershell -NoProfile -Command "${psCommand}"`, { maxBuffer: 1024 * 1024 * 10 }, (err, stdout) => {
        if (!err && stdout && stdout.trim()) {
          try {
            const parsed = JSON.parse(stdout);
            const events = Array.isArray(parsed) ? parsed : [parsed];

            for (const ev of events) {
              if (!ev || !ev.RecordId) continue;
              const logKey = `${ev.LogName || 'System'}-${ev.RecordId}`;
              if (processedRecords.has(logKey)) continue;
              processedRecords.add(logKey);

              // Keep deduplication set bounded
              if (processedRecords.size > 5000) {
                const first = processedRecords.values().next().value;
                processedRecords.delete(first);
              }

              // Parse /Date(timestamp)/ or string into ISO string
              let isoTimestamp = new Date().toISOString();
              if (typeof ev.TimeCreated === 'string') {
                const match = ev.TimeCreated.match(/\d+/);
                if (match) {
                  isoTimestamp = new Date(parseInt(match[0], 10)).toISOString();
                } else {
                  const d = new Date(ev.TimeCreated);
                  if (!isNaN(d.getTime())) isoTimestamp = d.toISOString();
                }
              } else if (typeof ev.TimeCreated === 'number') {
                isoTimestamp = new Date(ev.TimeCreated).toISOString();
              }

              const sourceId = ev.LogName === 'Application' ? 'src-win-app-telemetry' : 'src-win-system-telemetry';

              const logEntry = JSON.stringify({
                eventSource: ev.ProviderName || `Microsoft-Windows-${ev.LogName || 'System'}`,
                eventId: ev.Id,
                level: ev.LevelDisplayName || 'Information',
                timestamp: isoTimestamp,
                vendor: 'Microsoft Windows',
                product: `Windows ${ev.LogName || 'System'} Log`,
                message: (ev.Message || `${ev.ProviderName || 'Windows'} Event ${ev.Id}`).replace(/\r?\n/g, ' ')
              });

              processSingleLog(logEntry, sourceId);
            }
          } catch (e) {
            // Json parse ignore
          }
        }
      });
    };

    // Run initial batch immediately
    pollEvents();

    // Poll periodically for new real system & application events
    this.winEventTimer = setInterval(pollEvents, 4000);
    console.log('[Windows Event Collector] Actively polling host Windows System & Application Event Logs');
  }

  // 2. Direct Network Syslog UDP Listener
  startUDPSyslogListener() {
    try {
      this.udpSocket = dgram.createSocket('udp4');

      this.udpSocket.on('message', (msg, rinfo) => {
        const rawLog = msg.toString('utf8');
        const sourceId = `udp-${rinfo.address}:${rinfo.port}`;
        
        if (!storage.getSource(sourceId)) {
          storage.registerSource({
            id: sourceId,
            name: `Network-${rinfo.address}`,
            type: 'Network Device',
            vendor: 'Perimeter Gateway',
            format: 'Syslog / Auto-Detect'
          });
        }

        processSingleLog(rawLog, sourceId);
      });

      this.udpSocket.on('error', (err) => {
        console.warn(`[UDP Collector] Socket error: ${err.message}`);
      });

      this.udpSocket.bind(SYSLOG_UDP_PORT, () => {
        console.log(`[UDP Collector] Automated Syslog listener active on UDP 0.0.0.0:${SYSLOG_UDP_PORT}`);
        storage.recordAudit('SYSTEM', 'COLLECTOR_ACTIVE', `Automated UDP Syslog listener listening on port ${SYSLOG_UDP_PORT}`);
      });
    } catch (e) {
      console.warn(`[UDP Collector] Could not bind UDP port ${SYSLOG_UDP_PORT}:`, e.message);
    }
  }

  // 3. Automated File Drop Directory Watcher
  startDirectoryWatcher() {
    if (!fs.existsSync(INCOMING_DIR)) {
      fs.mkdirSync(INCOMING_DIR, { recursive: true });
    }
    if (!fs.existsSync(PROCESSED_DIR)) {
      fs.mkdirSync(PROCESSED_DIR, { recursive: true });
    }

    this.processPendingFiles();

    try {
      this.dirWatcher = fs.watch(INCOMING_DIR, (eventType, filename) => {
        if (filename && (filename.endsWith('.log') || filename.endsWith('.txt') || filename.endsWith('.json'))) {
          setTimeout(() => this.processSingleFile(filename), 300);
        }
      });
      console.log(`[File Collector] Automated Directory Watcher monitoring: ${INCOMING_DIR}`);
      storage.recordAudit('SYSTEM', 'COLLECTOR_ACTIVE', `Automated Directory Watcher active on incoming_logs/`);
    } catch (e) {
      console.warn('[File Collector] Watcher error:', e.message);
    }
  }

  processPendingFiles() {
    try {
      const files = fs.readdirSync(INCOMING_DIR);
      for (const file of files) {
        if (file === 'processed') continue;
        if (file.endsWith('.log') || file.endsWith('.txt') || file.endsWith('.json')) {
          this.processSingleFile(file);
        }
      }
    } catch (e) {}
  }

  processSingleFile(filename) {
    const filePath = path.join(INCOMING_DIR, filename);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) return;

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
      const sourceId = `file-${filename}`;

      if (!storage.getSource(sourceId)) {
        storage.registerSource({
          id: sourceId,
          name: `File-${filename}`,
          type: 'File Batch Ingestion',
          vendor: 'File Telemetry',
          format: 'Auto-Detect'
        });
      }

      let count = 0;
      for (const line of lines) {
        processSingleLog(line, sourceId);
        count++;
      }

      const destPath = path.join(PROCESSED_DIR, `${Date.now()}_${filename}`);
      fs.renameSync(filePath, destPath);

      storage.recordAudit('SYSTEM', 'AUTO_FILE_INGESTED', `Automatically ingested ${count} logs from file: ${filename}`);
      console.log(`[File Collector] Automatically ingested ${count} logs from ${filename}`);
    } catch (err) {
      console.warn(`[File Collector] Error processing ${filename}:`, err.message);
    }
  }

  stop() {
    if (this.udpSocket) {
      try { this.udpSocket.close(); } catch (e) {}
    }
    if (this.dirWatcher) {
      try { this.dirWatcher.close(); } catch (e) {}
    }
    if (this.winEventTimer) {
      clearInterval(this.winEventTimer);
    }
  }
}

export const collectors = new AutomatedCollectors();
