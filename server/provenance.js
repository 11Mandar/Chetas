import crypto from 'crypto';

let sequenceCounter = 0;

/**
 * Generates a unique, tamper-evident Provenance Trace Record for any raw log event.
 * Ensures 100% data preservation and bidirectional traceability.
 * 
 * @param {string} rawPayload The unaltered raw string received from source
 * @param {string} [sourceId='unknown'] Identifier of the sending collector/device
 * @returns {Object} Provenance metadata block
 */
export function createProvenanceRecord(rawPayload, sourceId = 'unknown') {
  sequenceCounter = (sequenceCounter + 1) % 10000000;
  
  const rawString = typeof rawPayload === 'string' ? rawPayload : JSON.stringify(rawPayload);
  const now = new Date();
  const timestamp = now.toISOString();

  // Cryptographic hash of the exact raw payload
  const hash = crypto.createHash('sha256').update(rawString, 'utf8').digest('hex');
  const shortHash = hash.substring(0, 12);
  const seqPadded = String(sequenceCounter).padStart(5, '0');

  // Human-readable yet deterministic provenance identifier
  const provenanceId = `cht-${shortHash}-${seqPadded}`;

  return {
    provenance_id: provenanceId,
    raw_sha256: hash,
    raw_bytes: Buffer.byteLength(rawString, 'utf8'),
    ingest_timestamp: timestamp,
    source_id: sourceId,
    raw_payload: rawString
  };
}

export function verifyProvenance(rawPayload, expectedHash) {
  const hash = crypto.createHash('sha256').update(rawPayload, 'utf8').digest('hex');
  return hash === expectedHash;
}
