// urlAnalysisService.js
// Performs structural and heuristic analysis on URLs.
// WHY A SEPARATE SERVICE FOR URLs?
// URLs have unique technical properties (protocol, domain, path,TLD) that pattern matching and AI prompts can miss or hallucinate.
// By analyzing the URL's structure directly in code, we get deterministic, reliable results for these checks.

import { extractDomain } from "../utils/helpers.js";

// Major brands that scammers frequently impersonate in URLs
const IMPERSONATED_BRANDS = [
  "paypal", "amazon", "netflix", "apple", "google", "microsoft",
  "facebook", "instagram", "whatsapp", "bank", "chase", "wellsfargo",
  "citibank", "barclays", "hsbc", "dhl", "fedex", "ups",
];

// TLDs (top-level domains) commonly used in scam sites because they're free or cheap
const SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".loan"];

// URL shorteners that hide the real destination
const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
  "short.link", "cutt.ly", "rb.gy",
];

/**
 * Analyzes a URL for scam indicators.
 *
 * @param {string} url - The URL to analyze
 * @returns {{
 *   hasSSL: boolean,
 *   isShortened: boolean,
 *   suspiciousKeywords: string[],
 *   hasBrandImpersonation: boolean,
 *   hasSuspiciousTLD: boolean,
 *   hasRawIP: boolean,
 *   isExcessivelyLong: boolean,
 *   score: number,
 *   flags: string[]
 * }}
 */
const analyzeURL = (url) => {
  const flags = [];
  let score = 0;

  // Normalize: add protocol if missing so URL() constructor works
  const normalizedURL = url.startsWith("http") ? url : `https://${url}`;
  const domain = extractDomain(url) || "";

  let parsedURL;
  try {
    parsedURL = new URL(normalizedURL);
  } catch {
    // If we can't even parse the URL, that's a red flag
    return {
      hasSSL: false,
      isShortened: false,
      suspiciousKeywords: [],
      hasBrandImpersonation: false,
      hasSuspiciousTLD: false,
      hasRawIP: false,
      isExcessivelyLong: true,
      score: 60,
      flags: ["URL could not be parsed — may be malformed or obfuscated"],
    };
  }

  // ── Check 1: SSL (HTTPS) -----
  // Legitimate services almost always use HTTPS.
  // HTTP-only is not proof of scam, but is a weak signal.
  const hasSSL = parsedURL.protocol === "https:";
  if (!hasSSL) {
    flags.push("Does not use HTTPS (insecure connection)");
    score += 15;
  }

  // ── Check 2: URL shortener ------
  // Shorteners hide the real destination — often used to disguise phishing links
  const isShortened = URL_SHORTENERS.some((shortener) => domain.includes(shortener));
  if (isShortened) {
    flags.push("Uses a URL shortener that hides the real destination");
    score += 25;
  }

  // ── Check 3: Brand impersonation in domain ------
  // e.g., "amazon-secure-login.com" or "paypal-verify.net"
  // We look for brand names in the domain but NOT as the primary domain.
  // "amazon.com" is fine; "amazon-login.xyz" is not.
  const suspiciousKeywords = IMPERSONATED_BRANDS.filter((brand) => {
    return domain.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.co.uk`);
  });

  const hasBrandImpersonation = suspiciousKeywords.length > 0;
  if (hasBrandImpersonation) {
    flags.push(`Impersonates a known brand in the domain: ${suspiciousKeywords.join(", ")}`);
    score += 35;
  }

  // ── Check 4: Suspicious TLD --------
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.some((tld) => domain.endsWith(tld));
  if (hasSuspiciousTLD) {
    flags.push("Uses a free or high-risk domain extension (.xyz, .tk, etc.)");
    score += 20;
  }

  // ── Check 5: Raw IP address -----
  // Legitimate websites use domain names, not raw IPs (e.g., http://192.168.1.1/login)
  const hasRawIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain);
  if (hasRawIP) {
    flags.push("Uses a raw IP address instead of a domain name");
    score += 40;
  }

  // ── Check 6: Excessively long URL ------
  // Scam URLs are sometimes padded with gibberish to obscure the real domain
  const isExcessivelyLong = url.length > 200;
  if (isExcessivelyLong) {
    flags.push("Unusually long URL — may be trying to hide its true destination");
    score += 10;
  }

  return {
    hasSSL,
    isShortened,
    suspiciousKeywords,
    hasBrandImpersonation,
    hasSuspiciousTLD,
    hasRawIP,
    isExcessivelyLong,
    score: Math.min(score, 90), // Cap at 90; AI provides final verdict
    flags,
  };
};

export default analyzeURL;
