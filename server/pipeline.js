import { createProvenanceRecord } from './provenance.js';
import { parseLog } from './parsers/index.js';
import { normalizeLog } from './normalizer.js';
import { storage } from './storage.js';

/**
 * Universal Ingestion Pipeline Executor
 * Processes genuine raw telemetry through cryptographic provenance hashing,
 * format auto-detection, specialized parsing, and taxonomy normalization.
 */

export function processSingleLog(rawString, sourceId = 'unknown') {
  if (!rawString || typeof rawString !== 'string' || !rawString.trim()) {
    return { success: false, error: 'Empty log string' };
  }

  try {
    // 1. Provenance Creation: Cryptographic SHA-256 hash & trace ID
    const provenance = createProvenanceRecord(rawString, sourceId);

    // 2. Multi-Format Auto-Detection & Specialized Parsing
    const parsed = parseLog(rawString);

    // 3. Taxonomy Normalization & Dynamic AI Mapping Hook
    const normalized = normalizeLog(parsed, provenance);

    // 4. Storage Persistence & Provenance Indexing
    const saved = storage.addEvent(normalized, rawString);
    return { success: true, event: saved };
  } catch (err) {
    storage.recordError();
    return { success: false, error: err.message };
  }
}
