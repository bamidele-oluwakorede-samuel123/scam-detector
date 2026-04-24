// analysisController.js
// ─────────────────────────────────────────────────────────────
// The main controller that orchestrates the full analysis pipeline.
//
// PIPELINE ORDER:
// 1. Validate & sanitize input
// 2. Detect input type (URL / phone / email / text)
// 3. Run pattern detection (instant, no API)
// 4. Run URL analysis if applicable (instant, no API)
// 5. Run AI analysis (OpenRouter API call — slowest step)
// 6. Combine scores into final risk score
// 7. Consolidate all flags
// 8. Build comparison data
// 9. Save to MongoDB
// 10. Return JSON response to frontend
// Error handling: any step that throws will be caught by the
// Express error handler middleware we set up in app.js.

import { detectInputType, sanitizeInput } from "../utils/helpers.js";
import detectPatterns from "../utils/patternDetector.js";
import analyzeURL from "../services/urlAnalysisService.js";
import analyzeWithAI from "../services/aiService.js";
import calculateFinalScore from "../services/scoringService.js";
import { consolidateFlags } from "../services/explanationService.js";
import buildComparison from "../services/comparisonService.js";
import Scan from "../models/Scan.js";

/**
 * POST /api/analyze
 * Runs the full scam analysis pipeline on user input.
 */
export const analyzeInput = async (req, res, next) => {
  try {
    // ---- Step 1: Validate & sanitize -----------
    const { input } = req.body;

    if (!input || typeof input !== "string") {
      return res.status(400).json({ error: "Input is required and must be a string." });
    }

    const sanitized = sanitizeInput(input);

    if (sanitized.length < 3) {
      return res.status(400).json({ error: "Input is too short to analyze." });
    }

    // ---- Step 2: Detect input type ------
    const inputType = detectInputType(sanitized);

    // ---- Step 3: Pattern detection -------
    const { flags: patternFlags, score: patternScore } = detectPatterns(sanitized, inputType);

    // --- Step 4: URL-specific analysis ------
    let urlAnalysisResult = null;
    let urlFlags = [];
    let urlScore = null;

    if (inputType === "url") {
      urlAnalysisResult = analyzeURL(sanitized);
      urlFlags = urlAnalysisResult.flags;
      urlScore = urlAnalysisResult.score;
    }

    // ---- Step 5: AI analysis ------
    // We pass pre-detected flags to Claude so it can build on them
    const allPreDetectedFlags = [...patternFlags, ...urlFlags];
    const aiResult = await analyzeWithAI(sanitized, inputType, allPreDetectedFlags);

    // --- Step 6: Final score calculation ------
    const { finalScore, riskLevel } = calculateFinalScore({
      aiScore: aiResult.riskScore,
      patternScore,
      urlScore,
      inputType,
    });

    // --- Step 7: Consolidate all flags ------
    const redFlags = consolidateFlags(patternFlags, urlFlags, aiResult.additionalFlags || []);

    // ---- Step 8: Build comparison ------
    const comparison = buildComparison(aiResult.comparison, inputType);

    // ---- Step 9: Save to MongoDB -------
    const scan = await Scan.create({
      input: sanitized,
      inputType,
      riskScore: finalScore,
      riskLevel,
      redFlags,
      explanation: aiResult.explanation,
      verdict: aiResult.verdict,
      comparison,
      urlAnalysis: urlAnalysisResult
        ? {
            hasSSL: urlAnalysisResult.hasSSL,
            suspiciousKeywords: urlAnalysisResult.suspiciousKeywords,
            hasRawIP: urlAnalysisResult.hasRawIP,
          }
        : undefined,
      patternFlags,
    });

    // --- Step 10: Respond -------
    res.status(200).json({
      success: true,
      scanId: scan._id,
      inputType,
      riskScore: finalScore,
      riskLevel,
      verdict: aiResult.verdict,
      explanation: aiResult.explanation,
      redFlags,
      comparison,
      urlAnalysis: urlAnalysisResult,
      createdAt: scan.createdAt,
    });
  } catch (error) {
    // Pass to the global error handler (errorHandler.js)
    next(error);
  }
};

/**
 * GET /api/history
 * Returns the 20 most recent scans from MongoDB.
 */
export const getHistory = async (req, res, next) => {
  try {
    const scans = await Scan.find()
      .sort({ createdAt: -1 }) // Newest first
      .limit(20)
      .select("input inputType riskScore riskLevel verdict createdAt"); // Only send what the frontend needs

    res.status(200).json({ success: true, scans });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/scan/:id
 * Returns a single scan by its MongoDB ID.
 */
export const getScanById = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);

    if (!scan) {
      return res.status(404).json({ error: "Scan not found." });
    }

    res.status(200).json({ success: true, scan });
  } catch (error) {
    next(error);
  }
};
