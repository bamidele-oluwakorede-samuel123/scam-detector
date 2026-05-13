// api.js
// ─────────────────────────────────────────────────────────────
// Centralized API service for the scam detector frontend.
//
// WHY CENTRALIZE API CALLS?
// If the backend URL changes, or you add auth headers, you
// update ONE file instead of hunting through every component.
//
// We use axios because it:
// - Automatically parses JSON responses
// - Provides cleaner error handling than fetch()
// - Supports request/response interceptors if needed later
// ─────────────────────────────────────────────────────────────

import axios from "axios";

// Base URL: in development, React's proxy (set in package.json)
// forwards /api requests to localhost:5000 automatically.
// In production, set REACT_APP_API_URL in your .env file.
const BASE_URL = process.env.REACT_APP_API_URL || "/api";

const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 30000, // 30 second timeout — AI analysis can take a few seconds
  headers: { "Content-Type": "application/json" },
});

/**
 * Submits input for scam analysis.
 *
 * @param {string} input - The text/URL/phone/email to analyze
 * @returns {Promise<object>} Analysis result from the backend
 */
export const analyzeInput = async (input) => {
  const response = await apiClient.post("/analyze", { input });
  return response.data;
};

/**
 * Submits an image/screenshot for scam analysis.
 *
 * HOW THIS WORKS:
 * We don't send the file directly — we convert it to a Base64 string
 * first in the frontend, then send that string as JSON. This avoids
 * the need for multipart/form-data and works with our existing JSON API.
 *
 * @param {string} base64Image - Base64 encoded image (no data: prefix)
 * @param {string} mimeType - e.g. "image/jpeg", "image/png"
 * @returns {Promise<object>} Analysis result from the backend
 */
export const analyzeImage = async (base64Image, mimeType) => {
  const response = await apiClient.post("/analyze-image", { base64Image, mimeType });
  return response.data;
};

/**
 * Fetches the 20 most recent scan history items.
 *
 * @returns {Promise<{ scans: Array }>}
 */
export const getHistory = async () => {
  const response = await apiClient.get("/history");
  return response.data;
};

/**
 * Fetches a single scan by its MongoDB ID.
 * Used when user navigates directly to a result URL.
 *
 * @param {string} id - MongoDB ObjectId string
 * @returns {Promise<{ scan: object }>}
 */
export const getScanById = async (id) => {
  const response = await apiClient.get(`/scan/${id}`);
  return response.data;
};
