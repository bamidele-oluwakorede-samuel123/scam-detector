// explanationService.js
// Consolidates all detected flags from different sources into a clean, deduplicated list for display in the frontend.
// WHY A SEPARATE SERVICE?
// Three services generate flags independently (patternDetector,urlAnalysisService, aiService). This service merges them,removes duplicates, and ensures consistent formatting.

/**
 * Merges and deduplicates flags from all analysis sources.
 * Priority order (how they appear in the UI):
 * 1. Pattern-detected flags (structural, clear)
 * 2. URL analysis flags (technical)
 * 3. AI-generated additional flags (contextual)
 *
 * @param {string[]} patternFlags - From patternDetector.js
 * @param {string[]} urlFlags - From urlAnalysisService.js (empty for non-URL)
 * @param {string[]} aiFlags - Additional flags from Claude
 * @returns {string[]} Merged, deduplicated flag list
 */
const consolidateFlags = (patternFlags = [], urlFlags = [], aiFlags = []) => {
  const all = [...patternFlags, ...urlFlags, ...aiFlags];

  // Deduplicate: lowercase comparison to catch near-duplicates
  // e.g., "Uses urgency language" and "uses urgency language" are the same
  const seen = new Set();
  const deduplicated = all.filter((flag) => {
    const key = flag.toLowerCase().trim();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return deduplicated;
};

/**
 * Generates a color-coded severity label for each flag.
 * This helps the frontend style flags differently by importance.
 * @param {string} flag
 * @returns {"high" | "medium" | "low"}
 */
const getFlagSeverity = (flag) => {
  const lower = flag.toLowerCase();

  // High severity: things that are near-certain scam indicators
  const highKeywords = ["impersonat", "raw ip", "phishing", "malware", "steal", "harvest", "credential"];
  if (highKeywords.some((k) => lower.includes(k))) return "high";

  // Medium severity: strong signals but not conclusive alone
  const mediumKeywords = ["urgency", "pressure", "suspicious", "shortener", "reward", "prize", "sensitive"];
  if (mediumKeywords.some((k) => lower.includes(k))) return "medium";

  // Low severity: weak signals, worth noting but not alarming alone
  return "low";
};

export { consolidateFlags, getFlagSeverity };
