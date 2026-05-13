// analysisRoutes.js
// Defines the API endpoints for the scam detector.
// Route design:
//   POST /api/analyze       → Submit something to analyze
//   GET  /api/history       → Get the last 20 scans
//   GET  /api/scan/:id      → Get a specific scan by ID
// All routes are prefixed with /api in app.js.


import express from "express";
import { analyzeInput, analyzeImage, getHistory, getScanById } from "../controllers/analysisController.js";

const router = express.Router();

// POST /api/analyze — analyze text, URL, phone, or email
router.post("/analyze", analyzeInput);

// POST /api/analyze-image — analyze an uploaded screenshot or image
// Body: { base64Image: string, mimeType: string }
router.post("/analyze-image", analyzeImage);

// GET /api/history — returns the 20 most recent scans
router.get("/history", getHistory);

// GET /api/scan/:id — returns a single scan by MongoDB ID
router.get("/scan/:id", getScanById);

export default router;
