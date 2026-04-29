// patternDetector.js
// Rule-based scam detection engine.
// HOW IT WORKS:
// We maintain lists of known scam patterns — regex expressions,keywords, and structural checks. We run the user's input against all of them and return a list of matched red flags plus a preliminary "suspicion score" (0–100).
// This runs BEFORE the AI call because:
//  1. It's instant (no API latency)
//  2. It pre-populates flags so the AI prompt is more focused
//  3. Obvious scams don't need expensive AI processing

// ── Pattern Libraries ---------

// Words/phrases that scammers use to create urgency or fear
const URGENCY_PATTERNS = [
  /urgent/i,
  /act now/i,
  /limited time/i,
  /expires? (today|soon|in \d+ hours?)/i,
  /immediately/i,
  /don't delay/i,
  /last chance/i,
  /time.sensitive/i,
  /respond (now|immediately|asap)/i,
];

// Phrases that promise unrealistic rewards
const REWARD_PATTERNS = [
  /you('ve| have) won/i,
  /congratulations.{0,20}(won|winner|selected)/i,
  /free (gift|prize|reward|iphone|cash)/i,
  /claim your (prize|reward|gift)/i,
  /\$\d{3,}[\s,]*(reward|prize|gift|bonus)/i,
  /lottery/i,
  /sweepstake/i,
];

// Requests for personal/financial data
const DATA_HARVEST_PATTERNS = [
  /verify (your )?(account|identity|details|information)/i,
  /confirm (your )?(password|pin|details|account)/i,
  /enter (your )?(credit card|bank|ssn|social security)/i,
  /update (your )?(billing|payment|account) (info|details|information)/i,
  /suspended.{0,30}account/i,
  /account.{0,30}suspended/i,
  /login (details|credentials|information)/i,
];

// Suspicious URL characteristics
const SUSPICIOUS_URL_PATTERNS = [
  /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly/i, // URL shorteners hide real destination
  /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.(com|net|org)/i, // Hyphenated domains (amazon-secure-login.com)
  /\.(xyz|tk|ml|ga|cf|gq)\b/i, // Free/suspicious TLDs
  /paypal|amazon|netflix|apple|google|microsoft/i, // Brand impersonation in URL
  /secure.*login|login.*secure/i,
  /verify.*account|account.*verify/i,
  /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // Raw IP address as domain
];

// Phone number red flags
const SUSPICIOUS_PHONE_PATTERNS = [
  /\+?1?900/, // Premium rate numbers
  /\+232|\+234|\+233|\+255/, // Common scam origin country codes (Sierra Leone, Nigeria, Ghana, Tanzania)
  /\+44\s*70/, // UK redirect numbers used in scams
];

// Structural text patterns
const STRUCTURAL_PATTERNS = [
  /click (here|this link|below)/i,
  /call (us|now|immediately|back) (at|on)?\s*[\d\-\+\(\)]+/i,
  /text (back|stop|yes|no) to \d+/i,
  /do not (share|show|tell)/i,
  /keep this (confidential|secret|private)/i,
  /nigerian? (prince|government|official)/i,
  /transfer.{0,30}fee/i,
  /advance fee/i,
  /wire transfer/i,
];

// ── Detection Function -------

/**
 * Runs all pattern sets against the input text.
 *
 * @param {string} input - The raw user input
 * @param {string} inputType - "url" | "phone" | "email" | "text"
 * @returns {{ flags: string[], score: number }}
 *   flags: array of human-readable red flag descriptions
 *   score: preliminary suspicion score 0–100
 */
const detectPatterns = (input, inputType) => {
  const flags = [];

  // Helper: runs a list of regex patterns and collects flag messages
  const runPatterns = (patterns, flagMessage) => {
    for (const pattern of patterns) {
      if (pattern.test(input)) {
        flags.push(flagMessage);
        break; // Only add each category once, even if multiple patterns match
      }
    }
  };

  // Run all pattern categories
  runPatterns(URGENCY_PATTERNS, "Uses urgency or pressure tactics");
  runPatterns(REWARD_PATTERNS, "Makes unrealistic prize or reward claims");
  runPatterns(DATA_HARVEST_PATTERNS, "Requests sensitive personal or financial data");
  runPatterns(STRUCTURAL_PATTERNS, "Contains suspicious action requests");

  // Only run URL patterns if this looks like a URL input
  if (inputType === "url") {
    runPatterns(SUSPICIOUS_URL_PATTERNS, "URL has suspicious characteristics");
  }

  // Only run phone patterns for phone inputs
  if (inputType === "phone") {
    runPatterns(SUSPICIOUS_PHONE_PATTERNS, "Phone number matches known scam patterns");
  }

  // ── Preliminary Score Calculation ------
  // Each flag adds weight to the score.
  // More flags = higher score, but we cap at 85 to leave room
  // for the AI to push it higher or pull it lower based on context.
  const scorePerFlag = 20;
  const rawScore = flags.length * scorePerFlag;
  const score = Math.min(rawScore, 85);

  return { flags, score };
};

export default detectPatterns;
