// Scan.js
// Mongoose schema/model for a scam scan result.
// A "schema" defines what fields a document can have, what type each field is, and whether it's required.
// A "model" is a class built from the schema that gives us methods like Scan.create(), Scan.find(), Scan.findById(), etc.


import mongoose from "mongoose";

// ── Schema Definition ----
const scanSchema = new mongoose.Schema(
  {
    // The raw input the user submitted
    input: {
      type: String,
      required: true,
      trim: true, // Removes leading/trailing whitespace automatically
    },

    // Auto-detected type: "url" | "phone" | "email" | "text"
    inputType: {
      type: String,
      enum: ["url", "phone", "email", "text"],
      required: true,
    },

    // Final risk score: 0 (completely safe) to 100 (definitely a scam)
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },

    // Human-readable label derived from the score
    riskLevel: {
      type: String,
      enum: ["safe", "suspicious", "dangerous"],
      required: true,
    },

    // Array of red flags detected (e.g., ["urgency language", "suspicious domain"])
    redFlags: {
      type: [String],
      default: [],
    },

    // Plain-English explanation of WHY this is/isn't a scam
    explanation: {
      type: String,
      default: "",
    },

    // AI's verdict — short summary sentence
    verdict: {
      type: String,
      default: "",
    },

    // Comparison data: what the real version looks like vs the scam version
    comparison: {
      legitimate: { type: String, default: "" },
      scam: { type: String, default: "" },
    },

    // Extra data specific to URL scans (null for non-URL inputs)
    urlAnalysis: {
      hasSSL: Boolean,
      domainAge: String,
      suspiciousKeywords: [String],
      redirectCount: Number,
    },

    // Pattern-based flags (from our rule engine, before AI runs)
    patternFlags: {
      type: [String],
      default: [],
    },
  },

  {
    // Mongoose automatically adds "createdAt" and "updatedAt" fields.
    // "createdAt" is what we'll use to sort scan history (newest first).
    timestamps: true,
  }
);

// ── Create the Model -----
// First arg: the model name ("Scan" → MongoDB collection: "scans")
// Second arg: the schema it uses
const Scan = mongoose.model("Scan", scanSchema);

export default Scan;
