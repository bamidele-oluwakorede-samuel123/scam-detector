// scoringService.js
// Combines multiple analysis signals into a single final risk score.
// WHY COMBINE SIGNALS INSTEAD OF JUST USING AI?
// AI alone can be inconsistent on edge cases. Pattern detection is deterministic. URL analysis catches structural issues AI might miss. Combining them is more robust than any single source.
// WEIGHTING STRATEGY:
// - AI score: 60% weight (most context-aware)
// - Pattern score: 25% weight (fast, rule-based)
// - URL score: 15% weight (structural facts only, URL inputs only)
// For non-URL inputs, the 15% URL weight is redistributed to AI.

import { scoreToRiskLevel } from "../utils/helpers.js";

/**
 * Calculates the final risk score from all analysis sources.
 *
 * @param {{
 *   aiScore: number,          // 0–100 from OPEN_ROUTER AI
 *   patternScore: number,     // 0–100 from patternDetector
 *   urlScore: number | null,  // 0–100 from urlAnalysisService, or null
 *   inputType: string
 * }} scores
 *
 * @returns {{ finalScore: number, riskLevel: string }}
 */
const calculateFinalScore = ({ aiScore, patternScore, urlScore, inputType }) => {
  let finalScore;

  if (inputType === "url" && urlScore !== null) {
    // URL input: use all three signals
    finalScore = aiScore * 0.6 + patternScore * 0.25 + urlScore * 0.15;
  } else {
    // Non-URL: redistribute URL weight to AI
    finalScore = aiScore * 0.75 + patternScore * 0.25;
  }

  // Round to nearest integer and clamp between 0 and 100
  const clamped = Math.round(Math.min(Math.max(finalScore, 0), 100));

  return {
    finalScore: clamped,
    riskLevel: scoreToRiskLevel(clamped),
  };
};

export default calculateFinalScore;
