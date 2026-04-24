// aiConfig.js
// ─────────────────────────────────────────────────────────────
// Central configuration for the scam detector backend.
//
// AI PROVIDER: OpenRouter (https://openrouter.ai)


import dotenv from "dotenv";
dotenv.config();

const aiConfig = {
  // --- OpenRouter API ----
  openRouterApiKey: process.env.OPENROUTER_API_KEY,

  // OpenRouter's API base URL.
  openRouterBaseUrl: "https://openrouter.ai/api/v1/chat/completions",

  // --- AI Model Selection ---
  // This is the model OpenRouter will use for analysis.
  model: process.env.OPENROUTER_MODEL || "meta-llama/llama-3.3-70b-instruct:free",

  // Max tokens the AI can return in one response.
  maxTokens: 1024,

  // --- MongoDB ------
  // Local: mongodb://localhost:27017/scamdetector
  mongoUri: process.env.MONGO_URI || "mongodb://localhost:27017/scamdetector",

  // --- Server -------
  port: process.env.PORT || 5000,

  // ── Risk Score Thresholds -------
  // Score is 0–100. These define the three risk categories.
  riskThresholds: {
    safe: 30,       // 0–30   → Safe (green)
    suspicious: 60, // 31–60  → Suspicious (yellow)
    dangerous: 100,               // 61–100 → Dangerous (red)
  },

  // --- Input Type Constants ------
  // Used by detectInputType() in helpers.js and displayed in the UI.
  inputTypes: {
    URL: "url",
    PHONE: "phone",
    EMAIL: "email",
    TEXT: "text",
  },
};

export default aiConfig;
