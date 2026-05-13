// AnalysisCard.jsx
// ─────────────────────────────────────────────────────────────
// Displays the explanation and red flag breakdown from analysis.
//
// DESIGN DECISIONS:
// - Flags appear with staggered animation (each 80ms after the last)
//   so the user reads them sequentially, not all at once.
// - High severity flags are red, medium amber, low muted.
// - The verdict is shown at the top as the primary takeaway.
// ─────────────────────────────────────────────────────────────

import React from "react";

// Severity color map (matches explanationService.js logic)
const SEVERITY_COLORS = {
  high: { bg: "rgba(245, 90, 90, 0.1)", border: "rgba(245, 90, 90, 0.3)", dot: "#f55a5a" },
  medium: { bg: "rgba(245, 200, 66, 0.1)", border: "rgba(245, 200, 66, 0.3)", dot: "#f5c842" },
  low: { bg: "rgba(255,255,255,0.04)", border: "rgba(255,255,255,0.1)", dot: "rgba(255,255,255,0.3)" },
};

// Lightweight version of getFlagSeverity from the backend
// (duplicated here to avoid an extra API call just for styling)
const getFlagSeverity = (flag) => {
  const lower = flag.toLowerCase();
  if (["impersonat", "raw ip", "phishing", "malware", "steal", "credential"].some((k) => lower.includes(k)))
    return "high";
  if (["urgency", "pressure", "suspicious", "shortener", "reward", "prize"].some((k) => lower.includes(k)))
    return "medium";
  return "low";
};

const AnalysisCard = ({ verdict, explanation, redFlags, inputType }) => {
  return (
    <div style={styles.wrapper}>
      {/* Verdict */}
      <div style={styles.section}>
        <span style={styles.sectionLabel}>AI VERDICT</span>
        <p style={styles.verdict}>{verdict}</p>
      </div>

      {/* Explanation */}
      <div style={styles.section}>
        <span style={styles.sectionLabel}>EXPLANATION</span>
        <p style={styles.explanation}>{explanation}</p>
      </div>

      {/* Red Flags */}
      {redFlags && redFlags.length > 0 && (
        <div style={styles.section}>
          <span style={styles.sectionLabel}>
            RED FLAGS <span style={styles.flagCount}>{redFlags.length}</span>
          </span>
          <div style={styles.flagsList}>
            {redFlags.map((flag, i) => {
              const severity = getFlagSeverity(flag);
              const colors = SEVERITY_COLORS[severity];
              return (
                <div
                  key={i}
                  style={{
                    ...styles.flagItem,
                    background: colors.bg,
                    border: `1px solid ${colors.border}`,
                    // Staggered appearance: each flag delays 80ms more than the last
                    animationDelay: `${i * 80}ms`,
                  }}
                >
                  <span style={{ ...styles.flagDot, background: colors.dot }} />
                  <span style={styles.flagText}>{flag}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Safe message when no flags */}
      {(!redFlags || redFlags.length === 0) && (
        <div style={styles.noFlags}>
          <span style={styles.checkmark}>✓</span>
          <span style={styles.noFlagsText}>No red flags detected by any analysis engine</span>
        </div>
      )}
    </div>
  );
};

const styles = {
  wrapper: {
    display: "flex",
    flexDirection: "column",
    gap: "24px",
    width: "100%",
  },
  section: {
    display: "flex",
    flexDirection: "column",
    gap: "10px",
  },
  sectionLabel: {
    fontFamily: "'Syne', sans-serif",
    fontWeight: 600,
    fontSize: "10px",
    letterSpacing: "0.15em",
    color: "rgba(255,255,255,0.35)",
    textTransform: "uppercase",
  },
  verdict: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    fontSize: "16px",
    color: "#ffffff",
    margin: 0,
    lineHeight: "1.6",
  },
  explanation: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    fontSize: "14px",
    color: "rgba(255,255,255,0.65)",
    margin: 0,
    lineHeight: "1.8",
  },
  flagCount: {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    width: "18px",
    height: "18px",
    background: "rgba(245, 90, 90, 0.25)",
    color: "#f55a5a",
    borderRadius: "50%",
    fontSize: "9px",
    fontWeight: 700,
    marginLeft: "6px",
    verticalAlign: "middle",
  },
  flagsList: {
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  },
  flagItem: {
    display: "flex",
    alignItems: "flex-start",
    gap: "10px",
    padding: "10px 14px",
    borderRadius: "10px",
    animation: "flagSlideIn 0.3s ease both",
  },
  flagDot: {
    width: "7px",
    height: "7px",
    borderRadius: "50%",
    flexShrink: 0,
    marginTop: "5px",
  },
  flagText: {
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 400,
    fontSize: "13.5px",
    color: "rgba(255,255,255,0.8)",
    lineHeight: "1.5",
  },
  noFlags: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    padding: "14px 16px",
    background: "rgba(99, 220, 170, 0.08)",
    border: "1px solid rgba(99, 220, 170, 0.2)",
    borderRadius: "12px",
  },
  checkmark: {
    color: "#63dcaa",
    fontSize: "18px",
    fontWeight: 700,
  },
  noFlagsText: {
    fontFamily: "'DM Sans', sans-serif",
    fontSize: "14px",
    color: "rgba(99, 220, 170, 0.85)",
    fontWeight: 400,
  },
};

export default AnalysisCard;
