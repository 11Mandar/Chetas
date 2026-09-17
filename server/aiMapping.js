/**
 * AI Semantic Field Mapping Engine
 * Uses NLP/heuristic pattern matching, semantic key similarity, and data type validation
 * to suggest canonical taxonomy mappings for unknown vendor fields.
 */

// Standard Chetas Canonical Taxonomy Target Fields
export const CANONICAL_FIELDS = [
  { field: 'source_ip', type: 'ip', desc: 'Originating IP address' },
  { field: 'source_port', type: 'port', desc: 'Originating TCP/UDP port' },
  { field: 'destination_ip', type: 'ip', desc: 'Destination IP address' },
  { field: 'destination_port', type: 'port', desc: 'Destination TCP/UDP port' },
  { field: 'protocol', type: 'string', desc: 'Network protocol (TCP/UDP/ICMP)' },
  { field: 'user_name', type: 'string', desc: 'Authenticated user or account identifier' },
  { field: 'action', type: 'string', desc: 'Enforcement action (ALLOW, BLOCK, DROP)' },
  { field: 'outcome', type: 'string', desc: 'Result status (SUCCESS, FAILURE)' },
  { field: 'severity', type: 'string', desc: 'Standardized threat severity' },
  { field: 'event_type', type: 'string', desc: 'Normalized categorization tag' },
  { field: 'message', type: 'string', desc: 'Event description / summary' }
];

// Pre-seeded standard security mappings
const defaultApprovedMappings = {
  // IPs
  'src': 'source_ip',
  'srcip': 'source_ip',
  'sourceip': 'source_ip',
  'src_ip': 'source_ip',
  'source_address': 'source_ip',
  'c_ip': 'source_ip',
  'c-ip': 'source_ip',
  'client_ip': 'source_ip',
  'dst': 'destination_ip',
  'dstip': 'destination_ip',
  'destip': 'destination_ip',
  'dst_ip': 'destination_ip',
  'destination_address': 'destination_ip',
  's-ip': 'destination_ip',
  'server_ip': 'destination_ip',
  
  // Ports
  'spt': 'source_port',
  'srcport': 'source_port',
  'src_port': 'source_port',
  'source_port': 'source_port',
  'dpt': 'destination_port',
  'dstport': 'destination_port',
  'dst_port': 'destination_port',
  'dest_port': 'destination_port',
  
  // Protocol
  'proto': 'protocol',
  'transport': 'protocol',
  
  // User
  'usr': 'user_name',
  'user': 'user_name',
  'username': 'user_name',
  'account': 'user_name',
  'logon_user': 'user_name',
  'auth_user': 'user_name',

  // Action
  'act': 'action',
  'rule_action': 'action',
  'disposition': 'action',

  // Message
  'msg': 'message',
  'reason': 'message',
  'description': 'message'
};

class AIMappingRegistry {
  constructor() {
    this.approvedMappings = { ...defaultApprovedMappings };
    this.pendingSuggestions = [];
    this.rejectedMappings = new Set();
  }

  getApproved() {
    return { ...this.approvedMappings };
  }

  getPending() {
    return [...this.pendingSuggestions];
  }

  resolveKey(rawKey) {
    const clean = rawKey.trim().toLowerCase();
    return this.approvedMappings[clean] || null;
  }

  /**
   * Analyzes an unknown key and its sample value, proposing a canonical field mapping if suitable
   */
  evaluateUnknownField(rawKey, sampleValue = '') {
    const key = rawKey.trim().toLowerCase();

    // Skip if already approved or rejected or is already standard canonical
    if (this.approvedMappings[key] || this.rejectedMappings.has(key)) return null;
    if (CANONICAL_FIELDS.some(c => c.field === key)) return null;

    // Check if already in pending
    if (this.pendingSuggestions.some(p => p.raw_key === key)) return null;

    // Heuristic & Semantic Scoring
    let bestMatch = null;
    let highestScore = 0;

    for (const target of CANONICAL_FIELDS) {
      let score = this.calculateSimilarity(key, target.field);

      // Boost with value heuristics
      if (sampleValue) {
        if (target.type === 'ip' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(sampleValue)) {
          if (key.includes('src') || key.includes('client') || key.includes('orig') || key.includes('c_') || key.includes('from')) {
            score = Math.max(score, 0.95);
          } else if (key.includes('dst') || key.includes('dest') || key.includes('server') || key.includes('tgt') || key.includes('to')) {
            score = Math.max(score, 0.95);
          } else {
            score = Math.max(score, 0.78);
          }
        } else if (target.type === 'port' && /^\d+$/.test(sampleValue) && parseInt(sampleValue, 10) <= 65535) {
          if (key.includes('sport') || key.includes('spt') || key.includes('src_p')) {
            score = Math.max(score, 0.96);
          } else if (key.includes('dport') || key.includes('dpt') || key.includes('dst_p')) {
            score = Math.max(score, 0.96);
          } else {
            score = Math.max(score, 0.82);
          }
        }
      }

      if (score > highestScore) {
        highestScore = score;
        bestMatch = target.field;
      }
    }

    if (highestScore >= 0.70 && bestMatch) {
      const suggestion = this.proposeMapping(
        key,
        bestMatch,
        `Auto-detected semantic pattern match (${Math.round(highestScore * 100)}% confidence)`,
        parseFloat(highestScore.toFixed(2)),
        sampleValue
      );
      return suggestion;
    }

    return null;
  }

  proposeMapping(rawKey, canonicalField, rationale, confidence, sampleValue = '') {
    const id = `sug-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const suggestion = {
      id,
      raw_key: rawKey,
      canonical_field: canonicalField,
      confidence: confidence || 0.85,
      rationale: rationale || 'Semantic key match',
      sample_value: sampleValue,
      suggested_at: new Date().toISOString(),
      status: 'pending'
    };
    this.pendingSuggestions.push(suggestion);
    return suggestion;
  }

  approveMapping(idOrKey, customTarget = null) {
    const idx = this.pendingSuggestions.findIndex(s => s.id === idOrKey || s.raw_key === idOrKey);
    let rawKey = idOrKey;
    let targetField = customTarget;

    if (idx !== -1) {
      const sug = this.pendingSuggestions[idx];
      rawKey = sug.raw_key;
      targetField = customTarget || sug.canonical_field;
      this.pendingSuggestions.splice(idx, 1);
    }

    if (!rawKey || !targetField) {
      throw new Error('Missing raw key or target canonical field');
    }

    this.approvedMappings[rawKey.toLowerCase()] = targetField;
    return { rawKey, targetField };
  }

  rejectMapping(idOrKey) {
    const idx = this.pendingSuggestions.findIndex(s => s.id === idOrKey || s.raw_key === idOrKey);
    let key = idOrKey;
    if (idx !== -1) {
      key = this.pendingSuggestions[idx].raw_key;
      this.pendingSuggestions.splice(idx, 1);
    }
    this.rejectedMappings.add(key.toLowerCase());
    return { key };
  }

  calculateSimilarity(s1, s2) {
    if (s1 === s2) return 1.0;
    if (s1.includes(s2) || s2.includes(s1)) return 0.85;

    // Levenshtein distance based ratio
    const len1 = s1.length;
    const len2 = s2.length;
    const maxLen = Math.max(len1, len2);
    if (maxLen === 0) return 1.0;

    const matrix = [];
    for (let i = 0; i <= len1; i++) matrix[i] = [i];
    for (let j = 0; j <= len2; j++) matrix[0][j] = j;

    for (let i = 1; i <= len1; i++) {
      for (let j = 1; j <= len2; j++) {
        const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }

    const dist = matrix[len1][len2];
    return Math.max(0, 1 - dist / maxLen);
  }
}

export const aiMapper = new AIMappingRegistry();
