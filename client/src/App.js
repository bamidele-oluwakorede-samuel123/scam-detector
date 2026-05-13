// app.js
// ─────────────────────────────────────────────────────────────
// Express application setup.
//
// WHY SEPARATE app.js FROM server.js?
// app.js builds and exports the Express app.
// server.js imports that app and actually starts listening.
// This separation means tests can import `app` without
// triggering a real server bind, which avoids port conflicts.
// ─────────────────────────────────────────────────────────────

import express from "express";
import cors from "cors";
import analysisRoutes from "./routes/analysisRoutes.js";
import errorHandler from "./middleware/errorHandler.js";

const app = express();

// ── Middleware ───────────────────────────────────────────────

// CORS: allows the React frontend (different port) to call our API.
// In production, replace the origin with your actual frontend domain.
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);

// Parse incoming JSON request bodies.
// Without this, req.body would be undefined in our controllers.
app.use(express.json());

// ── Health Check ─────────────────────────────────────────────
// A simple endpoint to verify the server is running.
// Useful during demos and deployment.
app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "Scam Detector API is running" });
});

// ── API Routes ───────────────────────────────────────────────
// All routes in analysisRoutes.js get the /api prefix here.
// e.g., router.post("/analyze") becomes POST /api/analyze
app.use("/api", analysisRoutes);

// ── 404 Handler ──────────────────────────────────────────────
// If no route matched, send a clear 404 instead of crashing.
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.url} not found.` });
});

// ── Global Error Handler ─────────────────────────────────────
// Must be LAST — Express identifies error middleware by 4 params.
app.use(errorHandler);

export default app;
