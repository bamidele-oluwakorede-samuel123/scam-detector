// helpers.js
// Shared utility functions used across the backend.
// These are "pure functions" — they take input, return output,
// and have no side effects (they don't modify databases or call APIs).
// Pure functions are easy to test and reason about.

import aiConfig from "../config/aiConfig.js";

/**
 * Automatically detects what type of input the user submitted.
 * This saves the user from having to select a type manually.
 * Detection order matters — check most specific first:
 *  1. URL (starts with http/https or www, or has a TLD pattern)
 *  2. Phone number (starts with +, or is mostly digits with formatting)
 *  3. Email (has @ with a domain)
 *  4. Text (fallback — anything else)
 *
 * @param {string} input
 * @returns {"url" | "phone" | "email" | "text"}
 */
export const detectInputType = (input) => {
  const trimmed = input.trim();

  // URL check: starts with http(s):// or www. or looks like domain.tld/path
  const urlRegex = /^(https?:\/\/|www\.)|^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/|$)/i;
  if (urlRegex.test(trimmed)) {
    return aiConfig.inputTypes.URL;
  }

  // Phone check: optional + sign, then digits/spaces/dashes/parentheses, at least 7 digits total
  const phoneRegex = /^\+?[\d\s\-\(\)]{7,20}$/;
  if (phoneRegex.test(trimmed)) {
    return aiConfig.inputTypes.PHONE;
  }

  // Email check: standard email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (emailRegex.test(trimmed)) {
    return aiConfig.inputTypes.EMAIL;
  }

  // Default: treat as freeform text (SMS, message, etc.)
  return aiConfig.inputTypes.TEXT;
};

/**
 * Converts a numeric risk score to a human-readable label.
 * Uses the thresholds defined in aiConfig so they stay in sync.
 *
 * @param {number} score - 0 to 100
 * @returns {"safe" | "suspicious" | "dangerous"}
 */
export const scoreToRiskLevel = (score) => {
  const { safe, suspicious } = aiConfig.riskThresholds;

  if (score <= safe) return "safe";
  if (score <= suspicious) return "suspicious";
  return "dangerous";
};

/**
 * Sanitizes input before sending to AI or saving to DB.
 * - Trims whitespace
 * - Caps length at 2000 characters (prevents abuse / prompt injection)
 * - Removes null bytes
 *
 * @param {string} input
 * @returns {string}
 */
export const sanitizeInput = (input) => {
  return input
    .trim()
    .replace(/\0/g, "") // Remove null bytes
    .substring(0, 2000); // Hard cap
};

/**
 * Extracts the domain from a URL string.
 * Used by the URL analysis service.
 *
 * @param {string} url
 * @returns {string | null}
 */
export const extractDomain = (url) => {
  try {
    // Ensure the URL has a protocol so the URL constructor can parse it
    const urlWithProtocol = url.startsWith("http") ? url : `https://${url}`;
    const { hostname } = new URL(urlWithProtocol);
    return hostname.replace(/^www\./, ""); // Strip www.
  } catch {
    return null;
  }
};
